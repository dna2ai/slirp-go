package main

import (
	"bufio"
	"encoding/binary"
	"net"
	"fmt"
	"io"
	"os"
	"syscall"
	"sync"
	"encoding/hex"
	"strings"
	"time"
)

const (
	SLIP_END     = 0xC0
	SLIP_ESC     = 0xDB
	SLIP_ESC_END = 0xDC
	SLIP_ESC_ESC = 0xDD

	// IP protocol numbers
	PROTO_ICMP = 1
	PROTO_TCP  = 6
	PROTO_UDP  = 17

	// ICMP types
	ICMP_ECHO_REQUEST = 8
	ICMP_ECHO_REPLY = 0
	ICMP_DEST_UNREACH = 3
	ICMP_HOST_UNREACH = 1

	UDP_HEADER_LEN = 8
	UDP_TIMEOUT = 30 * time.Second
)

type ConnKey struct {
	SrcIP   uint32
	SrcPort int
	DstIP   uint32
	DstPort int
}

type ConnVal struct {
	// 0 none, 100 tcp client, 101 tcp server, 200 udp client, 201 udp server
	Type int
	Key *ConnKey
	UDPcln *net.UDPConn
	UDPsrv *net.UDPConn
	TCPcln *net.TCPConn
	TCPsrv *net.TCPListener
	lastActivity time.Time
	done chan bool
	container *ConnMap
	lock sync.Mutex
	disposed bool
}

func (cv *ConnVal) IsTimeout(now *time.Time) bool {
	if cv.disposed {
		return true
	}
	if now == nil {
		cur := time.Now()
		now = &cur
	}
	var timeoutT time.Duration
	switch(cv.Type) {
	case 100: timeoutT = 24 * 3600 * time.Second
	case 101: timeoutT = 24 * 3600 * time.Second
	case 200: timeoutT = 30 * time.Second
	case 201: timeoutT = 30 * time.Second
	}
	if (*now).Sub(cv.lastActivity) > timeoutT {
		return true
	}
	return false
}

func (cv *ConnVal) Close() {
	// TODO: send FIN, RST for tcp
	switch(cv.Type) {
	case 100:
		if cv.TCPcln != nil {
			cv.TCPcln.Close()
			cv.TCPcln = nil
		}
	case 101:
		if cv.TCPsrv != nil {
			cv.TCPsrv.Close()
			cv.TCPsrv = nil
		}
	case 200:
		if cv.UDPcln != nil {
			cv.UDPcln.Close()
			cv.UDPcln = nil
		}
	case 201:
		if cv.UDPsrv != nil {
			cv.UDPsrv.Close()
			cv.UDPsrv = nil
		}
	}
}

func (cv *ConnVal) handleUdpResponse(iphdr IPHeader, udphdr UDPHeader) {
	buffer := make([]byte, 65535)
	for {
		select {
		case <-cv.done:
			return
		default:
			// Read response
			cv.UDPcln.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := cv.UDPcln.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				cv.Dispose()
				return
			}
			cv.lastActivity = time.Now()
			response := buffer[:n]
			fmt.Fprintf(os.Stderr, "[D] UDP response\r\n")
			fmt.Fprintf(os.Stderr, strings.ReplaceAll(hex.Dump(response), "\n", "\r\n"))

			// Construct response packet
			ret := GenerateIpUdpPacket(&iphdr, &udphdr, response)
			encoded := encodeSLIP(ret)
			go seqPrintPacket(encoded)
		}
	}
}

func (cv *ConnVal) Dispose() {
	cv.lock.Lock()
	defer cv.lock.Unlock()
	if cv.disposed {
		return
	}
	cv.disposed = true
	close(cv.done)
	cv.Close()
}

type ConnMap struct {
	data map[ConnKey]*ConnVal
	mu   sync.RWMutex
}

func NewConnMap() *ConnMap {
	cm := &ConnMap{
		data: make(map[ConnKey]*ConnVal),
	}
	go cm.cleanup()
	return cm
}

func (cm *ConnMap) cleanup() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cm.mu.Lock()
		now := time.Now()
		for key, item := range cm.data {
			if item.IsTimeout(&now) {
				item.Dispose()
				delete(cm.data, key)
				fmt.Fprintf(os.Stderr, "[D] Timeout connection: %+v\r\n", key)
			}
		}
		cm.mu.Unlock()
	}
}

func (cm *ConnMap) ProcessUDPConnection(iphdr IPHeader, packet []byte) (ConnKey, *ConnVal, UDPHeader, []byte, error) {
	udphdr, payload := parseUdpHeader(packet)
	src := binary.BigEndian.Uint32(iphdr.SrcIP[:])
	sport := int(udphdr.SrcPort)
	dst := binary.BigEndian.Uint32(iphdr.DstIP[:])
	dport := int(udphdr.DstPort)
	addr := net.UDPAddr{
		IP: net.IP(iphdr.DstIP[:]),
		Port: dport,
	}
	if src - 0x0a000200 != src & 0xff {
		addr.IP = net.IP(iphdr.SrcIP[:])
		addr.Port = sport
		tmp := src
		tport := sport
		src = dst
		sport = dport
		dst = tmp
		dport = tport
	}
	key := ConnKey{
		SrcIP: src,
		SrcPort: sport,
		DstIP: dst,
		DstPort: dport,
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	item, exists := cm.data[key]
	if exists {
		fmt.Fprintf(os.Stderr, "using exists key ...\r\n")
		item.lastActivity = time.Now()
	} else {
		fmt.Fprintf(os.Stderr, "using new key ...\r\n")
		udpConn, err := net.DialUDP("udp", nil, &addr)
		if err != nil {
			return key, item, udphdr, payload, fmt.Errorf("failed to dial UDP: %v", err)
		}
		item = &ConnVal{}
		item.Type = 200
		item.Key = &key
		item.UDPcln = udpConn
		item.lastActivity = time.Now()
		item.done = make(chan bool)
		fmt.Fprintf(os.Stderr, "item done: %v\r\n", item.done)
		item.disposed = false
		cm.data[key] = item
		go item.handleUdpResponse(iphdr, udphdr)
	}

	fmt.Fprintf(os.Stderr, "[I] Forwarding UDP packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), udphdr.DstPort)
	_, err := item.UDPcln.Write(payload)
	if err != nil {
		return key, item, udphdr, payload, fmt.Errorf("failed to send UDP: %v", err)
	}
	return key, item, udphdr, payload, nil
}


// IP header structure (20 bytes minimum)
type IPHeader struct {
	VersionIHL     uint8
	TOS            uint8
	TotalLength    uint16
	ID             uint16
	FlagsFragOff   uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SrcIP          [4]byte
	DstIP          [4]byte
}

// ICMP header structure
type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Unused   uint32
}

// UDPHeader represents a UDP header
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

var (
	printMutex sync.Mutex
	debugDumpMutex sync.Mutex
	reader *bufio.Reader
	writer *bufio.Writer
)

func main() {
	reader = bufio.NewReader(os.Stdin)
	writer = bufio.NewWriter(os.Stdout)
	defer writer.Flush()
	cm := NewConnMap()

	for {
		packet, err := readSLIPPacket(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "[E] Error reading SLIP packet: %v\r\n", err)
			continue
		}

		if len(packet) == 0 {
			continue
		}

		fmt.Fprintf(os.Stderr, "[I] Received packet of %d bytes\r\n", len(packet))

		// Parse IP header
		if len(packet) < 20 {
			fmt.Fprintf(os.Stderr, "[E] Packet too small for IP header\r\n")
			continue
		}

		fmt.Fprintf(os.Stderr, "[D] packet\r\n")
		debugDumpPacket(packet)

		ipHeader := parseIPHeader(packet)
		fmt.Fprintf(os.Stderr, "[I] IP packet: src=%v dst=%v proto=%d\r\n",
			ipHeader.SrcIP, ipHeader.DstIP, ipHeader.Protocol)

		var response []byte
		if (ipHeader.Protocol == 17) { // UDP
			fmt.Fprintf(os.Stderr, "[I] Sending UDP response\r\n")
			go cm.ProcessUDPConnection(ipHeader, packet)
			continue
		} else if (ipHeader.Protocol == 1) { // ICMP
			fmt.Fprintf(os.Stderr, "[I] Sending ICMP response\r\n")
			response, err = processICMPPacket(ipHeader, packet)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[E] error: %s\r\n", err)
				continue
			}
			fmt.Fprintf(os.Stderr, "[D] icmp response packet\r\n")
			debugDumpPacket(response)
			encoded := encodeSLIP(response)
			go seqPrintPacket(encoded)
		} else {
			// Generate ICMP Host Unreachable response
			fmt.Fprintf(os.Stderr, "[I] Sending ICMP Host Unreachable response\r\n")
			response = generateICMPHostUnreachable(ipHeader, packet)
			fmt.Fprintf(os.Stderr, "[D] response packet\r\n")
			debugDumpPacket(response)
			// Encode and send response
			encoded := encodeSLIP(response)
			go seqPrintPacket(encoded)
		}
	}
}

func debugDumpPacket(data []byte) {
	fmt.Fprintf(os.Stderr, strings.ReplaceAll(hex.Dump(data), "\n", "\r\n"))
}

func seqPrintPacket(data []byte) {
	if writer == nil {
		// it may meet when program is closing
		return
	}
	printMutex.Lock()
	defer printMutex.Unlock()
	_, err := writer.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[E] Error writing response: %v\r\n", err)
	} else {
		writer.Flush()
	}
}

func readSLIPPacket(reader *bufio.Reader) ([]byte, error) {
	var packet []byte
	escaped := false

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}

		if escaped {
			switch b {
			case SLIP_ESC_END:
				packet = append(packet, SLIP_END)
			case SLIP_ESC_ESC:
				packet = append(packet, SLIP_ESC)
			default:
				// Invalid escape sequence, but continue
				packet = append(packet, b)
			}
			escaped = false
		} else {
			switch b {
			case SLIP_END:
				if len(packet) > 0 {
					return packet, nil
				}
				// Empty packet, continue reading
			case SLIP_ESC:
				escaped = true
			default:
				packet = append(packet, b)
			}
		}
	}
}

func encodeSLIP(data []byte) []byte {
	var encoded []byte

	// Start with END byte
	encoded = append(encoded, SLIP_END)

	for _, b := range data {
		switch b {
		case SLIP_END:
			encoded = append(encoded, SLIP_ESC, SLIP_ESC_END)
		case SLIP_ESC:
			encoded = append(encoded, SLIP_ESC, SLIP_ESC_ESC)
		default:
			encoded = append(encoded, b)
		}
	}

	// End with END byte
	encoded = append(encoded, SLIP_END)
	return encoded
}

func parseIPHeader(packet []byte) IPHeader {
	var header IPHeader
	header.VersionIHL = packet[0]
	header.TOS = packet[1]
	header.TotalLength = binary.BigEndian.Uint16(packet[2:4])
	header.ID = binary.BigEndian.Uint16(packet[4:6])
	header.FlagsFragOff = binary.BigEndian.Uint16(packet[6:8])
	header.TTL = packet[8]
	header.Protocol = packet[9]
	header.HeaderChecksum = binary.BigEndian.Uint16(packet[10:12])
	copy(header.SrcIP[:], packet[12:16])
	copy(header.DstIP[:], packet[16:20])
	return header
}

func parseUdpHeader(packet []byte) (UDPHeader, []byte) {
	var header UDPHeader
	header.SrcPort = 0
	header.DstPort = 0
	if packet[9] != 17 {
		return header, nil
	}
	i := int(packet[0] & 0x0f) * 4
	header.SrcPort = binary.BigEndian.Uint16(packet[i:i+2])
	header.DstPort = binary.BigEndian.Uint16(packet[i+2:i+4])
	header.Length = binary.BigEndian.Uint16(packet[i+4:i+6])
	header.Checksum = binary.BigEndian.Uint16(packet[i+6:i+8])
	return header, packet[i+8:]
}

func generateICMPHostUnreachable(origIP IPHeader, origPacket []byte) []byte {
	// Create new IP header (swap src/dst)
	ipHeaderLen := (origIP.VersionIHL & 0x0f) * 4
	icmpLen := 8 + ipHeaderLen + 8 // ICMP header + IP header + 8 bytes of original data
	totalLen := ipHeaderLen + icmpLen

	response := make([]byte, totalLen)

	// IP Header
	response[0] = 0x45 // Version 4, Header length 5 (20 bytes)
	response[1] = 0    // TOS
	binary.BigEndian.PutUint16(response[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(response[4:6], 0) // ID
	binary.BigEndian.PutUint16(response[6:8], 0) // Flags and Fragment offset
	response[8] = 64                              // TTL
	response[9] = PROTO_ICMP                      // Protocol
	// Checksum calculated later
	copy(response[12:16], origIP.DstIP[:]) // Src IP (our IP is original dst)
	copy(response[16:20], origIP.SrcIP[:]) // Dst IP

	// Calculate IP checksum
	ipChecksum := calculateChecksum(response[:20])
	binary.BigEndian.PutUint16(response[10:12], ipChecksum)

	// ICMP Header
	icmpStart := ipHeaderLen
	response[icmpStart] = ICMP_DEST_UNREACH   // Type
	response[icmpStart+1] = ICMP_HOST_UNREACH // Code
	// Checksum calculated later
	binary.BigEndian.PutUint32(response[icmpStart+4:icmpStart+8], 0) // Unused

	// Copy original IP header + first 8 bytes of data
	copyLen := 28 // IP header (20) + 8 bytes
	if len(origPacket) < copyLen {
		copyLen = len(origPacket)
	}
	copy(response[icmpStart+8:], origPacket[:copyLen])

	// Calculate ICMP checksum
	icmpChecksum := calculateChecksum(response[icmpStart:])
	binary.BigEndian.PutUint16(response[icmpStart+2:icmpStart+4], icmpChecksum)

	return response
}

func processICMPPacket(iphdr IPHeader, packet []byte) ([]byte, error) {
	ipHeaderLen := int(iphdr.VersionIHL & 0x0f) * 4
	if len(packet) < ipHeaderLen + 8 {
		return nil, fmt.Errorf("packet too small for ICMPheader")
	}
	icmpHeader := ICMPHeader{
		Type:     packet[ipHeaderLen],
		Code:     packet[ipHeaderLen + 1],
		Checksum: binary.BigEndian.Uint16(packet[ipHeaderLen+2:ipHeaderLen+4]),
		Unused:   binary.BigEndian.Uint32(packet[ipHeaderLen+4:ipHeaderLen+8]),
	}
	icmpPayload := packet[ipHeaderLen+8:]
	// TODO: verify packet icmp checksum
	switch icmpHeader.Type {
	case ICMP_ECHO_REQUEST:
		dstIPuint32 := binary.BigEndian.Uint32(iphdr.DstIP[:])
		if dstIPuint32 - 0x0a000200 == dstIPuint32 & 0xff {
			fmt.Fprintf(os.Stderr, "[D] ping intranet at 10.0.2.%d\r\n", dstIPuint32 & 0xff)
			responseICMP :=packet[ipHeaderLen:]
			// heal icmp cmd type
			responseICMP[0] = ICMP_ECHO_REPLY
			binary.BigEndian.PutUint16(responseICMP[2:4], 0) // Zero checksum for calculation
			checksum := calculateChecksum(responseICMP)
			binary.BigEndian.PutUint16(responseICMP[2:4], checksum)
			return generateICMPResponse(&iphdr, responseICMP), nil
		}
		response, err := forwardICMPRequest(&iphdr, &icmpHeader, icmpPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to forward ICMP request: %v", err)
		}
		return response, nil
	default:
		// For other ICMP types, we might need different handling
		// For now, return an error
		return nil, fmt.Errorf("unsupported ICMP type: %d", icmpHeader.Type)
	}
}

func forwardICMPRequest(iphdr *IPHeader, icmpHeader *ICMPHeader, payload []byte) ([]byte, error) {
	// Create a raw ICMP socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if fd < 0 {
		return nil, fmt.Errorf("failed to create ICMP socket")
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5})
	if err != nil {
		return nil, fmt.Errorf("failed to set receive timeout: %v", err)
	}

	// Reconstruct the ICMP packet
	icmpPacket := make([]byte, 8+len(payload))
	icmpPacket[0] = icmpHeader.Type
	icmpPacket[1] = icmpHeader.Code
	binary.BigEndian.PutUint16(icmpPacket[2:4], 0) // Zero checksum for calculation
	binary.BigEndian.PutUint32(icmpPacket[4:8], icmpHeader.Unused)
	copy(icmpPacket[8:], payload)

	// Calculate and set checksum
	checksum := calculateChecksum(icmpPacket)
	binary.BigEndian.PutUint16(icmpPacket[2:4], checksum)

	// Send the ICMP packet
	dstAddr := &syscall.SockaddrInet4{
		Port: 0,
		Addr: iphdr.DstIP,
	}
	if err := syscall.Sendto(fd, icmpPacket, 0, dstAddr); err != nil {
		return nil, fmt.Errorf("failed to send ICMP packet: %v", err)
	}

	// Read the response
	responseBuf := make([]byte, 65536) // Max MTU size
	n, peer, err := syscall.Recvfrom(fd, responseBuf, 0)
	fmt.Fprintf(os.Stderr, "Received %d bytes from %s\r\n", n, peer)
	if err != nil {
		if nerr, ok := err.(syscall.Errno); ok && nerr == syscall.EAGAIN {
			return nil, fmt.Errorf("failed to read ICMP timeout: %v", err)
		}
		return nil, fmt.Errorf("failed to read ICMP response: %v", err)
	}

	// The response includes the IP header, so we need to parse it
	if n < 20 {
		return nil, fmt.Errorf("response too small")
	}

	// Skip the IP header (assuming no options)
	ipHeaderLen := int((responseBuf[0] & 0x0F) * 4)
	if n < ipHeaderLen+8 {
		return nil, fmt.Errorf("response too small for ICMP")
	}

	responseICMP := responseBuf[ipHeaderLen:n]
	// heal unused field
	binary.BigEndian.PutUint32(responseICMP[4:8], icmpHeader.Unused)
	binary.BigEndian.PutUint16(responseICMP[2:4], 0) // Zero checksum for calculation
	checksum = calculateChecksum(responseICMP)
	binary.BigEndian.PutUint16(responseICMP[2:4], checksum)

	// Generate the complete IP packet for the response
	return generateICMPResponse(iphdr, responseICMP), nil
}

func generateICMPResponse(originalIPHeader *IPHeader, icmpResponse []byte) []byte {
	// Create a new IP header for the response
	// Swap source and destination
	responseIPHeader := IPHeader{
		VersionIHL:   0x45, // IPv4, 5 words (20 bytes) header
		TOS:          originalIPHeader.TOS,
		TotalLength:  uint16(20 + len(icmpResponse)), // IP header + ICMP
		ID:           originalIPHeader.ID + 1,
		FlagsFragOff: 0x4000, // Don't fragment
		TTL:          64,
		Protocol:     1, // ICMP
		SrcIP:        originalIPHeader.DstIP,
		DstIP:        originalIPHeader.SrcIP,
	}

	// Create the IP packet
	ipPacket := make([]byte, 20+len(icmpResponse))

	// Fill in the IP header
	ipPacket[0] = responseIPHeader.VersionIHL
	ipPacket[1] = responseIPHeader.TOS
	binary.BigEndian.PutUint16(ipPacket[2:4], responseIPHeader.TotalLength)
	binary.BigEndian.PutUint16(ipPacket[4:6], responseIPHeader.ID)
	binary.BigEndian.PutUint16(ipPacket[6:8], responseIPHeader.FlagsFragOff)
	ipPacket[8] = responseIPHeader.TTL
	ipPacket[9] = responseIPHeader.Protocol
	binary.BigEndian.PutUint16(ipPacket[10:12], 0) // Zero checksum for calculation
	copy(ipPacket[12:16], responseIPHeader.SrcIP[:])
	copy(ipPacket[16:20], responseIPHeader.DstIP[:])

	// Calculate and set IP header checksum
	ipChecksum := calculateChecksum(ipPacket[:20])
	binary.BigEndian.PutUint16(ipPacket[10:12], ipChecksum)

	// Copy the ICMP response
	copy(ipPacket[20:], icmpResponse)

	return ipPacket
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32

	// Add each 16-bit word
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}

	// Add left-over byte, if any
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Add carry bits
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// One's complement
	return uint16(^sum)
}

func GenerateIpUdpPacket(origIPHeader *IPHeader, origUDPHeader *UDPHeader, responsePayload []byte) []byte {
	// Calculate lengths
	udpLength := UDP_HEADER_LEN + len(responsePayload)
	ipHeaderLen := int(origIPHeader.VersionIHL & 0x0f) * 4 // Standard IP header without options
	totalLength := ipHeaderLen + udpLength

	// Create packet buffer
	packet := make([]byte, totalLength)

	// Build IP header (swap source and destination)
	packet[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	packet[1] = 0    // TOS
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	binary.BigEndian.PutUint16(packet[4:6], origIPHeader.ID+1) // Increment ID
	binary.BigEndian.PutUint16(packet[6:8], 0)                 // No flags, no fragment
	packet[8] = 64                                              // TTL
	packet[9] = 17                                              // UDP protocol
	// Checksum will be calculated later
	copy(packet[12:16], origIPHeader.DstIP[:]) // Swap: original dst becomes src
	copy(packet[16:20], origIPHeader.SrcIP[:]) // Swap: original src becomes dst

	// Build UDP header (swap ports)
	udpStart := ipHeaderLen
	binary.BigEndian.PutUint16(packet[udpStart:udpStart+2], origUDPHeader.DstPort)   // Swap ports
	binary.BigEndian.PutUint16(packet[udpStart+2:udpStart+4], origUDPHeader.SrcPort) // Swap ports
	binary.BigEndian.PutUint16(packet[udpStart+4:udpStart+6], uint16(udpLength))
	// UDP checksum will be calculated later

	// Copy payload
	copy(packet[udpStart+UDP_HEADER_LEN:], responsePayload)

	// Calculate UDP checksum
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], origIPHeader.DstIP[:])
	copy(pseudoHeader[4:8], origIPHeader.SrcIP[:])
	pseudoHeader[8] = 0
	pseudoHeader[9] = 17
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(udpLength))
	udpChecksum := calculateChecksum(append(pseudoHeader, packet[udpStart:]...))
	binary.BigEndian.PutUint16(packet[udpStart+6:udpStart+8], udpChecksum)
	// Calculate IP checksum
	ipChecksum := calculateChecksum(packet[:ipHeaderLen])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

	return packet
}
