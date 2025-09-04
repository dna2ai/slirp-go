package slirp

import (
	"container/list"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"
)

const (
	SOCKS5_VERSION              = 0x05
	SOCKS5_NO_AUTH              = 0x00
	SOCKS5_CMD_CONNECT          = 0x01
	SOCKS5_ATYP_IPV4            = 0x01
	SOCKS5_ATYP_DOMAIN          = 0x03
	SOCKS5_ATYP_IPV6            = 0x04
	SOCKS5_REP_SUCCESS          = 0x00
	SOCKS5_REP_FAILURE          = 0x01
	SOCKS5_REP_CONN_REFUSED     = 0x05
	SOCKS5_REP_HOST_UNREACHABLE = 0x04
)

type Socks5Server struct {
	listener net.Listener
	cm       *ConnMap
}

func NewSocks5Server(port int, cm *ConnMap) (*Socks5Server, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to start SOCKS5 server: %v", err)
	}

	server := &Socks5Server{
		listener: listener,
		cm:       cm,
	}

	go server.serve()
	return server, nil
}

func (s *Socks5Server) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			debugPrintf("[E] SOCKS5 accept error: %v\r\n", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Socks5Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Socks5Server) handleConnection(conn net.Conn) {
	// Authentication negotiation
	if !s.handleAuth(conn) {
		return
	}

	// Handle CONNECT request
	s.handleConnect(conn)
}

func (s *Socks5Server) handleAuth(conn net.Conn) bool {
	// Read version and number of methods
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		debugPrintf("[E] SOCKS5 auth read error: %v\r\n", err)
		return false
	}

	version := buf[0]
	nmethods := buf[1]

	if version != SOCKS5_VERSION {
		debugPrintf("[E] SOCKS5 unsupported version: %d\r\n", version)
		return false
	}

	// Read methods
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		debugPrintf("[E] SOCKS5 methods read error: %v\r\n", err)
		return false
	}

	// Check if NO_AUTH is supported
	noAuthSupported := false
	for _, method := range methods {
		if method == SOCKS5_NO_AUTH {
			noAuthSupported = true
			break
		}
	}

	// Send response
	response := []byte{SOCKS5_VERSION, SOCKS5_NO_AUTH}
	if !noAuthSupported {
		response[1] = 0xFF // No acceptable methods
	}

	if _, err := conn.Write(response); err != nil {
		debugPrintf("[E] SOCKS5 auth response error: %v\r\n", err)
		return false
	}

	return noAuthSupported
}

func (s *Socks5Server) handleConnect(conn net.Conn) {
	// Read CONNECT request
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		debugPrintf("[E] SOCKS5 connect read error: %v\r\n", err)
		return
	}

	version := buf[0]
	cmd := buf[1]
	// rsv := buf[2] // Reserved
	atyp := buf[3]

	if version != SOCKS5_VERSION || cmd != SOCKS5_CMD_CONNECT {
		s.sendConnectResponse(conn, SOCKS5_REP_FAILURE, nil, 0)
		return
	}

	// Read address and port
	var addr string
	var port uint16

	switch atyp {
	case SOCKS5_ATYP_IPV4:
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			s.sendConnectResponse(conn, SOCKS5_REP_FAILURE, nil, 0)
			return
		}
		addr = net.IP(ipBuf).String()

	case SOCKS5_ATYP_IPV6:
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			s.sendConnectResponse(conn, SOCKS5_REP_FAILURE, nil, 0)
			return
		}
		addr = net.IP(ipBuf).String()

	case SOCKS5_ATYP_DOMAIN:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			s.sendConnectResponse(conn, SOCKS5_REP_FAILURE, nil, 0)
			return
		}
		domainLen := lenBuf[0]
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			s.sendConnectResponse(conn, SOCKS5_REP_FAILURE, nil, 0)
			return
		}
		addr = string(domainBuf)

	default:
		s.sendConnectResponse(conn, SOCKS5_REP_FAILURE, nil, 0)
		return
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		s.sendConnectResponse(conn, SOCKS5_REP_FAILURE, nil, 0)
		return
	}
	port = binary.BigEndian.Uint16(portBuf)

	debugPrintf("[I] SOCKS5 CONNECT to %s:%d\r\n", addr, port)

	if s.createVirtualConnection(addr, port, conn) == nil {
		s.sendConnectResponse(conn, SOCKS5_REP_HOST_UNREACHABLE, nil, 0)
		return
	}

	// Send success response
	s.sendConnectResponse(conn, SOCKS5_REP_SUCCESS, []byte{10, 0, 2, 15}, uint16(port)) // Our internal IP
}

func (s *Socks5Server) sendConnectResponse(conn net.Conn, rep byte, bindAddr []byte, bindPort uint16) {
	response := []byte{SOCKS5_VERSION, rep, 0x00} // Version, Reply, Reserved

	if bindAddr != nil {
		if len(bindAddr) == 4 {
			response = append(response, SOCKS5_ATYP_IPV4)
		} else if len(bindAddr) == 16 {
			response = append(response, SOCKS5_ATYP_IPV6)
		}
		response = append(response, bindAddr...)
	} else {
		response = append(response, SOCKS5_ATYP_IPV4)
		response = append(response, []byte{0, 0, 0, 0}...) // 0.0.0.0
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, bindPort)
	response = append(response, portBytes...)

	conn.Write(response)
}

func (s *Socks5Server) createVirtualConnection(addr string, port uint16, clientConn net.Conn) *ConnKey {
	// Parse the target address - but for server mode, we expect connections TO our internal network
	targetIP := net.ParseIP(addr)
	if targetIP == nil {
		// Try to resolve domain name
		ips, err := net.LookupIP(addr)
		if err != nil || len(ips) == 0 {
			return nil
		}
		targetIP = ips[0]
	}

	// Check if target is in our internal network
	if !s.isInternalAddress(targetIP) {
		debugPrintf("[E] SOCKS5 target %s is not in internal network\r\n", addr)
		return nil
	}

	targetIPv4 := targetIP.To4()

	item := &ConnVal{}
	item.Type = ConnTypeTcpServer
	item.TCPcln = clientConn.(*net.TCPConn)
	item.lastActivity = time.Now()
	item.done = make(chan bool)
	item.disposed = false
	item.state = &TcpState{}
	//item.state.value = TcpStateClosed
	item.state.value = TcpStateInit
	// here serverSeq means remote seq, it is client
	// clientSeq means local seq, it is server
	item.state.serverSeq = rand.Uint32()
	item.state.clientSeq = 0 // Will be set when we receive SYN-ACK from server
	item.state.inQ = list.New()
	item.state.inOffset = 0
	item.state.inBusy = false
	item.state.targetIP = binary.BigEndian.Uint32(targetIPv4)
	item.state.targetPort = int(port)

	synPacket, key := s.generateSYNToServer(item, clientConn)
	item.state.clientSeq++
	item.Key = key

	s.cm.mu.Lock()
	s.cm.data[*key] = item
	s.cm.mu.Unlock()

	encoded := encodeSLIP(synPacket)
	seqPrintPacket(encoded)

	go func() {
		time.Sleep(5 * time.Second)
		if item.state.value != TcpStateEstablished {
			debugPrintf("[E] SOCKS5 connect to target %s:%d timeout\r\n", addr, port)
			clientConn.Close()
			item.lock.Lock()
			defer item.lock.Unlock()
			item.Dispose()
			return
		}
	}()
	return key
}

func (s *Socks5Server) isInternalAddress(ip net.IP) bool {
	if ip.To4() != nil {
		// IPv4: check if it's in 10.0.2.0/24
		ipv4 := ip.To4()
		return ipv4[0] == 10 && ipv4[1] == 0 && ipv4[2] == 2
	} else {
		// IPv6: check if it's in fd00::/64
		return ip[0] == 0xfd && ip[1] == 0x00
	}
}

func (s *Socks5Server) generateSYNToServer(item *ConnVal, clientConn net.Conn) ([]byte, *ConnKey) {
	srcIp, sport := getAddrInfo(clientConn.RemoteAddr())
	srcIpv4 := srcIp.To4()
	dstIp := getIpv4FromUint32(item.state.targetIP)
	dstIpv4 := dstIp.To4()
	dport := item.state.targetPort
	var packet []byte
	// Create IPv4 SYN packet
	ipHeader := IPHeader{
		VersionIHL: 0x45,
		Protocol:   PROTO_TCP,
		TTL:        64,
	}
	if srcIpv4.IsLoopback() {
		srcIp = net.ParseIP("10.0.2.1")
		srcIpv4 = srcIp.To4()
	}
	copy(ipHeader.SrcIP[:], dstIpv4)
	copy(ipHeader.DstIP[:], srcIpv4)

	tcpHeader := TCPHeader{
		SrcPort: uint16(dport),
		DstPort: uint16(sport),
		SeqNum:  item.state.serverSeq,
		AckNum:  item.state.clientSeq,
		Flags:   SYN,
		Window:  65535,
	}

	packet = GenerateIpTcpPacket(&ipHeader, &tcpHeader,
		item.state.serverSeq, item.state.clientSeq, SYN, 65535, 0, nil)
	key := s.cm.BuildTcpConnectionKey(&ipHeader, dport, sport)
	debugPrintf("[I] SOCKS5 sending SYN to server %s:%d\r\n", dstIpv4, dport)
	debugPrintf("[I] Created virtual server connection: %s:%d -> %s:%d\r\n",
		srcIpv4, sport, dstIpv4, dport)
	debugDumpPacket(packet)
	return packet, key
}
