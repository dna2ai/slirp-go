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
	SOCKS5_VERSION               = 0x05
	SOCKS5_NO_AUTH               = 0x00
	SOCKS5_CMD_CONNECT           = 0x01
	SOCKS5_CMD_UDP_ASSOCIATE     = 0x03
	SOCKS5_ATYP_IPV4             = 0x01
	SOCKS5_ATYP_DOMAIN           = 0x03
	SOCKS5_ATYP_IPV6             = 0x04
	SOCKS5_REP_SUCCESS           = 0x00
	SOCKS5_REP_FAILURE           = 0x01
	SOCKS5_REP_CONN_REFUSED      = 0x05
	SOCKS5_REP_HOST_UNREACHABLE  = 0x04
	SOCKS5_REP_CMD_NOT_SUPPORTED = 0x07
)

type Socks5Server struct {
	listener    net.Listener
	udpListener *net.UDPConn
	cm          *ConnMap
}

func NewSocks5Server(port int, cm *ConnMap) (*Socks5Server, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to start SOCKS5 server: %v", err)
	}

	// Create UDP listener on the same port for UDP ASSOCIATE
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("failed to start UDP listener: %v", err)
	}

	server := &Socks5Server{
		listener:    listener,
		udpListener: udpListener,
		cm:          cm,
	}

	go server.serve()
	go server.serveUDP()
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
	var err1, err2 error
	if s.listener != nil {
		err1 = s.listener.Close()
	}
	if s.udpListener != nil {
		err2 = s.udpListener.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
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

	if version != SOCKS5_VERSION {
		s.sendConnectResponse(conn, SOCKS5_REP_FAILURE, nil, 0)
		return
	}

	if cmd != SOCKS5_CMD_CONNECT && cmd != SOCKS5_CMD_UDP_ASSOCIATE {
		s.sendConnectResponse(conn, SOCKS5_REP_CMD_NOT_SUPPORTED, nil, 0)
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

	if cmd == SOCKS5_CMD_CONNECT {
		debugPrintf("[I] SOCKS5 CONNECT to %s:%d\r\n", addr, port)

		if s.createVirtualConnection(addr, port, conn) == nil {
			s.sendConnectResponse(conn, SOCKS5_REP_HOST_UNREACHABLE, nil, 0)
			return
		}

		// Send success response
		s.sendConnectResponse(conn, SOCKS5_REP_SUCCESS, []byte{10, 0, 2, 15}, uint16(port)) // Our internal IP
	} else if cmd == SOCKS5_CMD_UDP_ASSOCIATE {
		debugPrintf("[I] SOCKS5 UDP ASSOCIATE\r\n")

		// For UDP ASSOCIATE, we return our UDP listener address
		udpAddr := s.udpListener.LocalAddr().(*net.UDPAddr)
		s.sendConnectResponse(conn, SOCKS5_REP_SUCCESS, udpAddr.IP.To4(), uint16(udpAddr.Port))

		// Keep the TCP connection alive to maintain the UDP association
		go s.maintainUDPAssociation(conn)
	}
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
	item.container = s.cm
	item.lastActivity = time.Now()
	item.done = make(chan bool)
	item.disposed = false
	item.targetIP = binary.BigEndian.Uint32(targetIPv4)
	item.targetPort = int(port)
	item.state = &TcpState{}
	//item.state.value = TcpStateClosed
	item.state.value = TcpStateInit
	item.state.packetQ = make(chan packetAndHeader, 100)
	// here serverSeq means remote seq, it is client
	// clientSeq means local seq, it is server
	item.state.serverSeq = rand.Uint32()
	item.state.clientSeq = 0 // Will be set when we receive SYN-ACK from server
	item.state.inQ = list.New()
	item.state.inOffset = 0
	item.state.inBusy = false
	item.state.closingState = false
	item.state.rto = TCP_INITIAL_RTO

	go item.processTcpPacketQ()
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
		item.lock.Lock()
		if item.state.value != TcpStateEstablished {
			debugPrintf("[E] SOCKS5 connect to target %s:%d timeout\r\n", addr, port)
			// Clean up the connection from ConnMap
			s.cm.Pop(key)
			item.Dispose()
			item.lock.Unlock()
			clientConn.Close()
			return
		}
		item.lock.Unlock()
	}()

	// Monitor client connection for closure
	go s.monitorClientConnection(item, clientConn)
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
	dstIp := getIpv4FromUint32(item.targetIP)
	dstIpv4 := dstIp.To4()
	dport := item.targetPort
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
	key := s.cm.BuildConnectionKey(&ipHeader, dport, sport)
	debugPrintf("[I] SOCKS5 sending SYN to server %s:%d\r\n", dstIpv4, dport)
	debugPrintf("[I] Created virtual server connection: %s:%d -> %s:%d\r\n",
		srcIpv4, sport, dstIpv4, dport)
	debugDumpPacket(packet)
	return packet, key
}

// serveUDP handles UDP packets for SOCKS5 UDP ASSOCIATE
func (s *Socks5Server) serveUDP() {
	buffer := make([]byte, 65536)
	for {
		n, clientAddr, err := s.udpListener.ReadFromUDP(buffer)
		if err != nil {
			debugPrintf("[E] SOCKS5 UDP read error: %v\r\n", err)
			continue
		}

		go s.handleUDPPacket(buffer[:n], clientAddr)
	}
}

// maintainUDPAssociation keeps the TCP connection alive for UDP association
func (s *Socks5Server) maintainUDPAssociation(conn net.Conn) {
	// Keep probing the TCP connection to detect when it closes
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	defer conn.Close() // Ensure connection is closed on exit

	for range ticker.C {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
			_, err := tcpConn.Read(make([]byte, 0))
			tcpConn.SetReadDeadline(time.Time{})

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Expected, connection is alive
				}
				// Any other error means the connection is dead
				debugPrintf("[I] SOCKS5 UDP association closed: %v\r\n", err)
				return
			}
		}
	}
}

// handleUDPPacket processes a SOCKS5 UDP packet
func (s *Socks5Server) handleUDPPacket(data []byte, clientAddr *net.UDPAddr) {
	if len(data) < 10 { // Minimum SOCKS5 UDP header size
		debugPrintf("[E] SOCKS5 UDP packet too short\r\n")
		return
	}

	// Parse SOCKS5 UDP header
	// +----+------+------+----------+----------+----------+
	// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +----+------+------+----------+----------+----------+
	// | 2  |  1   |  1   | Variable |    2     | Variable |
	// +----+------+------+----------+----------+----------+

	if data[0] != 0 || data[1] != 0 { // RSV must be 0
		debugPrintf("[E] SOCKS5 UDP invalid header\r\n")
		return
	}

	frag := data[2]
	if frag != 0 { // We don't support fragmentation
		debugPrintf("[E] SOCKS5 UDP fragmentation not supported\r\n")
		return
	}

	atyp := data[3]
	offset := 4

	var targetIP net.IP
	var targetPort uint16

	switch atyp {
	case SOCKS5_ATYP_IPV4:
		if len(data) < offset+6 {
			return
		}
		targetIP = net.IP(data[offset : offset+4])
		targetPort = binary.BigEndian.Uint16(data[offset+4 : offset+6])
		offset += 6
	case SOCKS5_ATYP_IPV6:
		if len(data) < offset+18 {
			return
		}
		targetIP = net.IP(data[offset : offset+16])
		targetPort = binary.BigEndian.Uint16(data[offset+16 : offset+18])
		offset += 18
	case SOCKS5_ATYP_DOMAIN:
		if len(data) < offset+1 {
			return
		}
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return
		}
		domain := string(data[offset : offset+domainLen])
		offset += domainLen
		targetPort = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		// Resolve domain
		ips, err := net.LookupIP(domain)
		if err != nil || len(ips) == 0 {
			debugPrintf("[E] SOCKS5 UDP domain resolution failed: %s\r\n", domain)
			return
		}
		targetIP = ips[0].To4()
		if targetIP == nil {
			targetIP = ips[0] // IPv6
		}
	default:
		debugPrintf("[E] SOCKS5 UDP unsupported address type: %d\r\n", atyp)
		return
	}

	payload := data[offset:]
	debugPrintf("[I] SOCKS5 UDP relay to %s:%d (%d bytes)\r\n", targetIP, targetPort, len(payload))

	// Check if target is in our internal network
	if !s.isInternalAddress(targetIP) {
		debugPrintf("[E] SOCKS5 UDP target %s is not in internal network\r\n", targetIP)
		return
	}

	// Create virtual UDP packet and send to internal network
	s.createVirtualUDPPacket(targetIP, targetPort, payload, clientAddr)
}

// createVirtualUDPPacket creates a virtual UDP packet for the internal network
func (s *Socks5Server) createVirtualUDPPacket(targetIP net.IP, targetPort uint16, payload []byte, clientAddr *net.UDPAddr) {
	// Create IP header
	ipHeader := IPHeader{
		VersionIHL: 0x45,
		Protocol:   PROTO_UDP,
		TTL:        64,
	}

	srcIp := clientAddr.IP
	srcIpv4 := srcIp.To4()
	if srcIpv4.IsLoopback() {
		srcIp = net.ParseIP("10.0.2.1")
		srcIpv4 = srcIp.To4()
	}
	// Use client's mapped internal IP as source
	copy(ipHeader.SrcIP[:], targetIP.To4())
	copy(ipHeader.DstIP[:], srcIpv4)

	// Create UDP header
	udpHeader := UDPHeader{
		SrcPort: targetPort,
		DstPort: uint16(clientAddr.Port),
	}

	key := s.cm.BuildConnectionKey(&ipHeader, int(targetPort), clientAddr.Port)
	s.cm.mu.Lock()
	item, exists := s.cm.data[*key]
	if !exists {
		item = &ConnVal{}
		item.Type = ConnTypeUdpServer
		item.UDPcln = nil
		item.container = s.cm
		item.done = make(chan bool)
		item.targetIP = binary.BigEndian.Uint32(clientAddr.IP.To4())
		item.targetPort = int(clientAddr.Port)
		item.Key = key
		s.cm.data[*key] = item
	}
	item.disposed = false
	item.lastActivity = time.Now()
	s.cm.mu.Unlock()

	// Generate the complete UDP packet
	udpPacket := GenerateIpUdpPacket(&ipHeader, &udpHeader, payload)
	debugDumpPacket(udpPacket)

	// Send to internal network via SLIP
	encoded := encodeSLIP(udpPacket)
	seqPrintPacket(encoded)
}

// monitorClientConnection monitors the SOCKS5 client connection for closure
// This function monitors the connection state without interfering with data flow
func (s *Socks5Server) monitorClientConnection(item *ConnVal, clientConn net.Conn) {
	// Monitor connection by checking if it's still alive periodically
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if connection is still alive by checking the underlying TCP connection
			if tcpConn, ok := clientConn.(*net.TCPConn); ok {
				// Set a very short deadline to test connectivity without blocking
				tcpConn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
				buffer := make([]byte, 0) // Zero-length buffer for peek
				_, err := tcpConn.Read(buffer)
				tcpConn.SetReadDeadline(time.Time{}) // Reset deadline

				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						// This is an expected timeout, continue monitoring.
						continue
					}
					// Any other error (like EOF) means the connection is closed.
					debugPrintf("[I] SOCKS5 client connection closed, cleaning up server connection\r\n")
					item.lock.Lock()
					if item.state.value == TcpStateEstablished {
						// Mark connection for closure - the handleTcpResponse will handle the FIN
						item.state.closingState = true
						if item.TCPcln != nil {
							item.TCPcln.Close() // This will cause EOF in handleTcpResponse
						}
					}
					item.lock.Unlock()
					return
				}
			}
		case <-item.done:
			// Connection is being disposed
			return
		}
	}
}
