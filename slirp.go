package main

import (
	"bufio"
	"container/list"
	"encoding/binary"
	"encoding/hex"
	"net"
	"fmt"
	"io"
	"os"
	"syscall"
	"sync"
	"strings"
	"time"
)

// TCP flags
const (
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
)

// Connection states
const (
    TcpStateInit = iota
    TcpStateSynReceived
    TcpStateEstablished
    TcpStateFinWait1
    TcpStateFinWait2
    TcpStateClosing
    TcpStateClosed
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
	MTU = 1500

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
	state *TcpState
}

type TcpState struct {
	value     int
	clientSeq uint32
	serverSeq uint32
	inQ       *list.List
	inOffset  int
	inBusy    bool
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

func (cm *ConnMap) ProcessTCPConnection(iphdr IPHeader, packet []byte) (ConnKey, *ConnVal, TCPHeader, []byte, error) {
	tcphdr, payload := parseTCPHeader(packet)
	src := binary.BigEndian.Uint32(iphdr.SrcIP[:])
	sport := int(tcphdr.SrcPort)
	dst := binary.BigEndian.Uint32(iphdr.DstIP[:])
	dport := int(tcphdr.DstPort)
	addr := net.UDPAddr{
		IP: net.IP(iphdr.DstIP[:]),
		Port: dport,
	}
	if (src & 0xffffff00) == 0x0a000200 {
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
		fmt.Fprintf(os.Stderr, "tcp: using exists key ...\r\n")
		item.lastActivity = time.Now()
	} else {
		fmt.Fprintf(os.Stderr, "tcp: using new key ...\r\n")
		item = &ConnVal{}
		item.Type = 100
		item.Key = &key
		item.lastActivity = time.Now()
		item.done = make(chan bool)
		item.state = &TcpState{}
		item.state.value = TcpStateClosed
		item.disposed = false
		cm.data[key] = item
	}
	payloadN := len(payload)
	fmt.Fprintf(os.Stderr, "[I] TCP header: %+v\r\n", tcphdr)
	switch (item.state.value) {
	case TcpStateClosed:
		if tcphdr.Flags & SYN != 0 {
			item.HandleTcpClnSYN(&iphdr, &tcphdr)
		}
	case TcpStateInit:
		if tcphdr.Flags & ACK != 0 {
			item.HandleTcpClnACK(&iphdr, &tcphdr)
		} // -> server: TcpStateSynReceived, client: TcpStateEstablished
	case TcpStateEstablished:
		if payloadN > 0 {
			item.HandleTcpClnData(&iphdr, &tcphdr, payload)
		} else if tcphdr.Flags & FIN != 0 {
			item.HandleTcpClnFIN(&iphdr, &tcphdr)
		} else if tcphdr.Flags & ACK != 0 {
			item.HandleTcpClnACK(&iphdr, &tcphdr)
		}
	case TcpStateFinWait1:
		// FIN, server: TcpStateFinWait2
		item.HandleTcpClnFIN2(&iphdr, &tcphdr)
		// -> TcpStateClosed
	}
	return key, item, tcphdr, payload, nil
}

func (cv *ConnVal) handleTcpResponse(iphdr *IPHeader, tcphdr *TCPHeader) {
	buffer := make([]byte, 65535)
	for {
		if cv.TCPcln == nil {
			return
		}
		// TODO: split into fragments
		n, err := cv.TCPcln.Read(buffer)
		if err != nil {
			if err == io.EOF {
				cv.lock.Lock()
				if cv.state.inQ.Len() == 0 || len(cv.state.inQ.Back().Value.([]byte)) > 0 {
					cv.state.inQ.PushBack([]byte{})
				}
				cv.lock.Unlock()
			} else {
				fmt.Fprintf(os.Stderr, "[I] TCP read RST packet to %s:%d - %v\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort, err)
				cv.Dispose()
				ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
				encoded := encodeSLIP(ret)
				go seqPrintPacket(encoded)
			}
			return
		}
		cv.lock.Lock()
		if n > 0 {
			if cv.state.inQ.Len() == 0 {
				cv.state.inQ.PushBack([]byte{})
			}
			lastElem := cv.state.inQ.Back()
			lastData := append(lastElem.Value.([]byte), buffer[:n]...)
			lastElem.Value = lastData
			go cv.actTcpResponse(iphdr, tcphdr)
		}
		cv.lock.Unlock()
	}
}

func (cv *ConnVal) actTcpResponse(iphdr *IPHeader, tcphdr *TCPHeader) {
	cv.lock.Lock()
	defer cv.lock.Unlock()
	if cv.state.inBusy || cv.state.inQ.Len() == 0 {
		return
	}
	cv.state.inBusy = true
	ipHeaderLen := int(iphdr.VersionIHL & 0x0f) * 4
	tcpHeaderLen := 20
	maxPayloadSize := MTU - ipHeaderLen - tcpHeaderLen
	firstElem := cv.state.inQ.Front()
	data := firstElem.Value.([]byte)
	n := len(data)
	L := maxPayloadSize
	if cv.state.inOffset + maxPayloadSize > n {
		L = n - cv.state.inOffset
		data = data[cv.state.inOffset:]
		cv.state.inQ.Remove(firstElem)
		cv.state.inOffset = 0
	} else {
		data = data[cv.state.inOffset:cv.state.inOffset+L]
		cv.state.inOffset += L
	}
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, PSH|ACK, 65535, 0, data)
	fmt.Fprintf(os.Stderr, "[I] forward slice read %d/%d ...\r\n", L, n)
	debugDumpPacket(ret)
	cv.state.serverSeq += uint32(L)
	cv.lastActivity = time.Now()
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
}

func (cv *ConnVal) HandleTcpClnData(iphdr *IPHeader, tcphdr *TCPHeader, payload []byte) {
	fmt.Fprintf(os.Stderr, "[I] Forwarding TCP packet to %s:%d - %d byte(s)\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort, len(payload))
	if cv.TCPcln == nil {
		fmt.Fprintf(os.Stderr, "[I] TCP predata RST packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
		ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)
		return
	}
	_, err := cv.TCPcln.Write(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[I] TCP data RST packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
		ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)
		return
	}
	cv.lock.Lock()
	defer cv.lock.Unlock()
	cv.state.clientSeq = tcphdr.SeqNum + uint32(len(payload))
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	cv.lastActivity = time.Now()
}

func (cv *ConnVal) HandleTcpClnSYN(iphdr *IPHeader, tcphdr *TCPHeader) {
	fmt.Fprintf(os.Stderr, "[I] TCP SYN packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", net.IP(iphdr.DstIP[:]), tcphdr.DstPort), 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[I] TCP ACK-RST packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
		ret := GenerateIpTcpPacket(iphdr, tcphdr, 0, tcphdr.SeqNum, ACK|RST, 0, 0, nil)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)
		return
	}
	cv.lock.Lock()
	defer cv.lock.Unlock()
	cv.TCPcln, _ = conn.(*net.TCPConn)
	cv.state.value = TcpStateInit
	cv.state.clientSeq = tcphdr.SeqNum + 1
	cv.state.serverSeq = 1000
	cv.state.inQ = list.New()
	cv.state.inOffset = 0
	cv.state.inBusy = false
	cv.lastActivity = time.Now()
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK|SYN, 65535, 0, nil)
        cv.state.serverSeq ++
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	go cv.handleTcpResponse(iphdr, tcphdr)
}

func (cv *ConnVal) HandleTcpClnACK(iphdr *IPHeader, tcphdr *TCPHeader) {
	fmt.Fprintf(os.Stderr, "[I] TCP ACK packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	cv.state.clientSeq = tcphdr.SeqNum
	cv.state.serverSeq = tcphdr.AckNum
	if cv.state.value == TcpStateEstablished {
		cv.state.inBusy = false
		go cv.actTcpResponse(iphdr, tcphdr)
	} else if cv.state.value == TcpStateInit {
		cv.state.value = TcpStateEstablished
	}
}

func (cv *ConnVal) HandleTcpClnFIN(iphdr *IPHeader, tcphdr *TCPHeader) {
	fmt.Fprintf(os.Stderr, "[I] TCP FIN packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	cv.state.value = TcpStateFinWait1
	cv.state.clientSeq = tcphdr.SeqNum + 1
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	if cv.TCPcln != nil {
		cv.TCPcln.Close()
	}
}

func (cv *ConnVal) HandleTcpClnFIN2(iphdr *IPHeader, tcphdr *TCPHeader) {
	fmt.Fprintf(os.Stderr, "[I] TCP FIN-2 packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	//cv.state.value = TcpStateClosing
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK|FIN, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	cv.state.serverSeq ++
	cv.state.value = TcpStateClosed
	// TODO: remove from cm
}

func (cv *ConnVal) HandleTcpClnRST(iphdr *IPHeader, tcphdr *TCPHeader) {
	fmt.Fprintf(os.Stderr, "[I] TCP RST packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	if cv.TCPcln != nil {
		cv.TCPcln.Close()
	}
	cv.state.value = TcpStateClosed
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
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
	if (src & 0xffffff00) == 0x0a000200 {
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
		fmt.Fprintf(os.Stderr, "udp: using exists key ...\r\n")
		item.lastActivity = time.Now()
	} else {
		fmt.Fprintf(os.Stderr, "udp: using new key ...\r\n")
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

// TCPHeader represents a TCP header
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
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
		if (ipHeader.Protocol == 6) { // TCP
			fmt.Fprintf(os.Stderr, "[I] Sending TCP response\r\n")
			go cm.ProcessTCPConnection(ipHeader, packet)
			continue
		} else if (ipHeader.Protocol == 17) { // UDP
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

func parseTCPHeader(packet []byte) (TCPHeader, []byte) {
	// VersionIHL = packet[0]
	i := int(packet[0] & 0x0f) * 4
	var header TCPHeader
	header.SrcPort = binary.BigEndian.Uint16(packet[i : i+2])
	header.DstPort = binary.BigEndian.Uint16(packet[i+2 : i+4])
	header.SeqNum = binary.BigEndian.Uint32(packet[i+4 : i+8])
	header.AckNum = binary.BigEndian.Uint32(packet[i+8 : i+12])
	header.DataOffset = packet[i+12] >> 4
	header.Flags = packet[i+13]
	header.Window = binary.BigEndian.Uint16(packet[i+14 : i+16])
	header.Checksum = binary.BigEndian.Uint16(packet[i+16 : i+18])
	header.Urgent = binary.BigEndian.Uint16(packet[i+18 : i+20])

	return header, packet[i+20:]
}

func parseUdpHeader(packet []byte) (UDPHeader, []byte) {
	var header UDPHeader
	header.SrcPort = 0
	header.DstPort = 0
	// VersionIHL = packet[0]
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

func calculateSubChecksum(srcIP [4]byte, dstIP [4]byte, protocol uint8, data []byte) uint16 {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP[:])
	copy(pseudoHeader[4:8], dstIP[:])
	pseudoHeader[8] = 0
	pseudoHeader[9] = protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(data)))
	return calculateChecksum(append(pseudoHeader, data...))
}

func GenerateIpTcpPacket(origIPHeader *IPHeader, origTCPHeader *TCPHeader, seqNum, ackNum uint32, flags uint8, window, id uint16, responsePayload []byte) []byte {
	// IP header
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // Version 4, IHL 5
	ipHeader[1] = 0    // TOS
	totalLen := 20 + 20 + len(responsePayload) // IP + TCP + payload
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHeader[4:6], id) // ID
	ipHeader[6] = 0x40 // Don't fragment
	ipHeader[8] = 64   // TTL
	ipHeader[9] = 6    // TCP protocol
	binary.BigEndian.PutUint16(ipHeader[10:12], 0) // checksume placeholder
	copy(ipHeader[12:16], origIPHeader.DstIP[:])
	copy(ipHeader[16:20], origIPHeader.SrcIP[:])

	// Calculate IP checksum
	checksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)

	// TCP header
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], origTCPHeader.DstPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], origTCPHeader.SrcPort)
	binary.BigEndian.PutUint32(tcpHeader[4:8], seqNum)
	binary.BigEndian.PutUint32(tcpHeader[8:12], ackNum)
	tcpHeader[12] = 0x50 // Data offset (5 * 4 = 20 bytes)
	tcpHeader[13] = flags
	binary.BigEndian.PutUint16(tcpHeader[14:16], window)

	// Combine TCP header and payload
	tcpData := tcpHeader
	if responsePayload != nil {
		tcpData = append(tcpData, responsePayload...)
	}

	// Calculate TCP checksum
	tcpChecksum := calculateSubChecksum(origIPHeader.DstIP, origIPHeader.SrcIP, 6, tcpData)
	binary.BigEndian.PutUint16(tcpData[16:18], tcpChecksum)

	// Combine IP header and TCP data
	return append(ipHeader, tcpData...)
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
	udpChecksum := calculateSubChecksum(origIPHeader.DstIP, origIPHeader.SrcIP, 17, packet[udpStart:])
	binary.BigEndian.PutUint16(packet[udpStart+6:udpStart+8], udpChecksum)
	// Calculate IP checksum
	ipChecksum := calculateChecksum(packet[:ipHeaderLen])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

	return packet
}

func getTcpStateName(state int) string {
    switch state {
    case TcpStateInit:
        return "INIT"
    case TcpStateSynReceived:
        return "SYN_RECEIVED"
    case TcpStateEstablished:
        return "ESTABLISHED"
    case TcpStateFinWait1:
        return "FIN_WAIT_1"
    case TcpStateFinWait2:
        return "FIN_WAIT_2"
    case TcpStateClosing:
        return "CLOSING"
    case TcpStateClosed:
        return "CLOSED"
    default:
        return "UNKNOWN"
    }
}
