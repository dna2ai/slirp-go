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

func (s *Socks5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

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

	// This is where we simulate the connection to the user mode Linux
	// Instead of actually connecting, we create a virtual connection entry
	// and handle the data exchange through the SLIRP mechanism

	// Create a virtual TCP connection entry
	key := s.createVirtualConnection(addr, port, conn)
	if key == nil {
		s.sendConnectResponse(conn, SOCKS5_REP_HOST_UNREACHABLE, nil, 0)
		return
	}

	// Send success response
	s.sendConnectResponse(conn, SOCKS5_REP_SUCCESS, []byte{10, 0, 2, 15}, 1080) // Our internal IP

	// Handle data relay
	s.handleDataRelay(conn, key)
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

	// Create connection key - this represents the connection FROM external client TO internal server
	// We use a unique source port for each SOCKS5 connection
	srcPort := 32768 + (int(time.Now().UnixNano()) % 32768) // Dynamic port range
	key := ConnKey{
		SrcPort: srcPort,
		DstPort: int(port),
		IsIPv6:  targetIP.To4() == nil,
	}

	if key.IsIPv6 {
		copy(key.SrcIP[:], net.ParseIP("fd00::2")[:]) // Our IPv6 gateway as source
		copy(key.DstIP[:], targetIP[:])               // Target server in UML
	} else {
		// Map IPv4 to first 4 bytes
		copy(key.SrcIP[:4], net.ParseIP("10.0.2.2").To4()) // Our IPv4 gateway as source
		copy(key.DstIP[:4], targetIP.To4())                // Target server in UML
	}

	// Create connection value
	s.cm.mu.Lock()
	defer s.cm.mu.Unlock()

	item := &ConnVal{}
	item.Type = 101 // TCP server
	item.Key = &key
	item.TCPsrvConn = clientConn.(*net.TCPConn)
	item.lastActivity = time.Now()
	item.done = make(chan bool)
	item.disposed = false
	item.isServer = true
	item.serverBuffer = make([]byte, 0)
	item.state = &TcpState{}
	item.state.value = TcpStateClosed
	item.state.inQ = list.New()
	item.state.inOffset = 0
	item.state.inBusy = false
	item.connectionTimeout = 5 * time.Second // 5 second timeout for connection establishment
	s.cm.data[key] = item

	debugPrintf("[I] Created virtual server connection: %s:%d -> %s:%d\r\n",
		net.IP(key.SrcIP[:4]), srcPort, addr, port)

	return &key
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

func (s *Socks5Server) handleDataRelay(clientConn net.Conn, key *ConnKey) {
	s.cm.mu.RLock()
	item, exists := s.cm.data[*key]
	s.cm.mu.RUnlock()

	if !exists {
		return
	}

	// Initialize TCP state and sequence numbers
	item.lock.Lock()
	item.state.clientSeq = rand.Uint32()
	item.state.serverSeq = 0 // Will be set when we receive SYN-ACK from server
	item.lastActivity = time.Now()
	item.lock.Unlock()

	// Send initial SYN packet to User Mode Linux to establish connection
	s.sendSYNToServer(key, item)

	// Handle data from client to server (through SLIRP)
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, err := clientConn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					debugPrintf("[E] SOCKS5 client read error: %v\r\n", err)
				}
				// Send FIN to server if connection is established
				if item.state.value == TcpStateEstablished {
					s.sendFINToServer(key, item)
				}
				item.Dispose()
				return
			}

			// Send data to server through SLIRP
			s.sendDataToServer(key, item, buffer[:n])
			debugPrintf("[I] SOCKS5 sent %d bytes to server\r\n", n)
		}
	}()

	// Connection management loop
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-item.done:
			return
		case <-ticker.C:
			if item.disposed {
				return
			}

			// Check for connection timeout
			if s.checkConnectionTimeout(item, clientConn) {
				return
			}

			// Check if we have data from server to send to client
			s.relayServerDataToClient(item, clientConn)
		}
	}
}

func (s *Socks5Server) checkConnectionTimeout(item *ConnVal, clientConn net.Conn) bool {
	item.lock.Lock()
	defer item.lock.Unlock()

	now := time.Now()

	// Check SYN timeout - waiting for SYN-ACK
	if item.state.value == TcpStateInit && !item.synSentTime.IsZero() {
		if now.Sub(item.synSentTime) > item.connectionTimeout {
			debugPrintf("[E] SOCKS5 connection timeout - no SYN-ACK received from server\r\n")
			// Close client connection - server is not responding
			clientConn.Close()
			item.Dispose()
			return true
		}
	}

	// Check FIN timeout - waiting for FIN-ACK
	if item.state.value == TcpStateFinWait1 && !item.finSentTime.IsZero() {
		if now.Sub(item.finSentTime) > item.connectionTimeout {
			debugPrintf("[E] SOCKS5 FIN timeout - forcing connection close\r\n")
			// Force close client connection
			clientConn.Close()
			item.Dispose()
			return true
		}
	}

	return false
}

func (s *Socks5Server) sendSYNToServer(key *ConnKey, item *ConnVal) {
	debugPrintf("[I] SOCKS5 sending SYN to server %s:%d\r\n",
		net.IP(key.DstIP[:4]), key.DstPort)

	var packet []byte
	if key.IsIPv6 {
		// Create IPv6 SYN packet
		ipv6Header := IPv6Header{
			VersionTCFL:   0x60000000, // Version 6
			PayloadLength: 20,         // TCP header length
			NextHeader:    PROTO_TCP,
			HopLimit:      64,
		}
		copy(ipv6Header.SrcIP[:], key.SrcIP[:])
		copy(ipv6Header.DstIP[:], key.DstIP[:])

		tcpHeader := TCPHeader{
			SrcPort: uint16(key.SrcPort),
			DstPort: uint16(key.DstPort),
			SeqNum:  item.state.clientSeq,
			AckNum:  0,
			Flags:   SYN,
			Window:  65535,
		}

		packet = GenerateIPv6TcpPacket(&ipv6Header, &tcpHeader,
			item.state.clientSeq, 0, SYN, 65535, 0, nil)
	} else {
		// Create IPv4 SYN packet
		ipHeader := IPHeader{
			VersionIHL: 0x45,
			Protocol:   PROTO_TCP,
			TTL:        64,
		}
		copy(ipHeader.SrcIP[:], key.SrcIP[:4])
		copy(ipHeader.DstIP[:], key.DstIP[:4])

		tcpHeader := TCPHeader{
			SrcPort: uint16(key.SrcPort),
			DstPort: uint16(key.DstPort),
			SeqNum:  item.state.clientSeq,
			AckNum:  0,
			Flags:   SYN,
			Window:  65535,
		}

		packet = GenerateIpTcpPacket(&ipHeader, &tcpHeader,
			item.state.clientSeq, 0, SYN, 65535, 0, nil)
	}

	// Send packet through SLIP to User Mode Linux
	encoded := encodeSLIP(packet)
	go seqPrintPacket(encoded)

	// Record when SYN was sent for timeout tracking
	item.lock.Lock()
	item.synSentTime = time.Now()
	item.state.value = TcpStateInit
	item.state.clientSeq++
	item.lock.Unlock()
}

func (s *Socks5Server) sendDataToServer(key *ConnKey, item *ConnVal, data []byte) {
	if item.state.value != TcpStateEstablished {
		// Buffer data until connection is established
		item.lock.Lock()
		item.serverBuffer = append(item.serverBuffer, data...)
		item.lock.Unlock()
		return
	}

	// Fragment data if necessary
	maxPayload := config.MTU - 40 - 20 // IP header + TCP header
	if key.IsIPv6 {
		maxPayload = config.MTU - 40 - 20 // IPv6 header + TCP header
	} else {
		maxPayload = config.MTU - 20 - 20 // IPv4 header + TCP header
	}

	for len(data) > 0 {
		fragmentSize := len(data)
		if fragmentSize > maxPayload {
			fragmentSize = maxPayload
		}

		fragment := data[:fragmentSize]
		data = data[fragmentSize:]

		var packet []byte
		if key.IsIPv6 {
			ipv6Header := IPv6Header{
				VersionTCFL:   0x60000000,
				PayloadLength: uint16(20 + len(fragment)),
				NextHeader:    PROTO_TCP,
				HopLimit:      64,
			}
			copy(ipv6Header.SrcIP[:], key.SrcIP[:])
			copy(ipv6Header.DstIP[:], key.DstIP[:])

			tcpHeader := TCPHeader{
				SrcPort: uint16(key.SrcPort),
				DstPort: uint16(key.DstPort),
				SeqNum:  item.state.clientSeq,
				AckNum:  item.state.serverSeq,
				Flags:   PSH | ACK,
				Window:  65535,
			}

			packet = GenerateIPv6TcpPacket(&ipv6Header, &tcpHeader,
				item.state.clientSeq, item.state.serverSeq, PSH|ACK, 65535, 0, fragment)
		} else {
			ipHeader := IPHeader{
				VersionIHL: 0x45,
				Protocol:   PROTO_TCP,
				TTL:        64,
			}
			copy(ipHeader.SrcIP[:], key.SrcIP[:4])
			copy(ipHeader.DstIP[:], key.DstIP[:4])

			tcpHeader := TCPHeader{
				SrcPort: uint16(key.SrcPort),
				DstPort: uint16(key.DstPort),
				SeqNum:  item.state.clientSeq,
				AckNum:  item.state.serverSeq,
				Flags:   PSH | ACK,
				Window:  65535,
			}

			packet = GenerateIpTcpPacket(&ipHeader, &tcpHeader,
				item.state.clientSeq, item.state.serverSeq, PSH|ACK, 65535, 0, fragment)
		}

		// Send packet through SLIP
		encoded := encodeSLIP(packet)
		go seqPrintPacket(encoded)

		item.state.clientSeq += uint32(len(fragment))
	}
}

func (s *Socks5Server) sendFINToServer(key *ConnKey, item *ConnVal) {
	if item.state.value != TcpStateEstablished {
		return
	}

	debugPrintf("[I] SOCKS5 sending FIN to server\r\n")

	var packet []byte
	if key.IsIPv6 {
		ipv6Header := IPv6Header{
			VersionTCFL:   0x60000000,
			PayloadLength: 20,
			NextHeader:    PROTO_TCP,
			HopLimit:      64,
		}
		copy(ipv6Header.SrcIP[:], key.SrcIP[:])
		copy(ipv6Header.DstIP[:], key.DstIP[:])

		tcpHeader := TCPHeader{
			SrcPort: uint16(key.SrcPort),
			DstPort: uint16(key.DstPort),
			SeqNum:  item.state.clientSeq,
			AckNum:  item.state.serverSeq,
			Flags:   FIN | ACK,
			Window:  65535,
		}

		packet = GenerateIPv6TcpPacket(&ipv6Header, &tcpHeader,
			item.state.clientSeq, item.state.serverSeq, FIN|ACK, 65535, 0, nil)
	} else {
		ipHeader := IPHeader{
			VersionIHL: 0x45,
			Protocol:   PROTO_TCP,
			TTL:        64,
		}
		copy(ipHeader.SrcIP[:], key.SrcIP[:4])
		copy(ipHeader.DstIP[:], key.DstIP[:4])

		tcpHeader := TCPHeader{
			SrcPort: uint16(key.SrcPort),
			DstPort: uint16(key.DstPort),
			SeqNum:  item.state.clientSeq,
			AckNum:  item.state.serverSeq,
			Flags:   FIN | ACK,
			Window:  65535,
		}

		packet = GenerateIpTcpPacket(&ipHeader, &tcpHeader,
			item.state.clientSeq, item.state.serverSeq, FIN|ACK, 65535, 0, nil)
	}

	encoded := encodeSLIP(packet)
	go seqPrintPacket(encoded)

	// Record when FIN was sent for timeout tracking
	item.lock.Lock()
	item.finSentTime = time.Now()
	item.state.value = TcpStateFinWait1
	item.state.clientSeq++
	item.lock.Unlock()
}

func (s *Socks5Server) relayServerDataToClient(item *ConnVal, clientConn net.Conn) {
	item.lock.Lock()
	defer item.lock.Unlock()

	if len(item.serverBuffer) > 0 {
		n, err := clientConn.Write(item.serverBuffer)
		if err != nil {
			debugPrintf("[E] SOCKS5 client write error: %v\r\n", err)
			item.disposed = true
			return
		}

		// Remove sent data from buffer
		if n >= len(item.serverBuffer) {
			item.serverBuffer = item.serverBuffer[:0]
		} else {
			item.serverBuffer = item.serverBuffer[n:]
		}

		debugPrintf("[I] SOCKS5 sent %d bytes to client\r\n", n)
	}
}

func (s *Socks5Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}
