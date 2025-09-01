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

func GenerateIPv6TcpPacket(origIPv6Header *IPv6Header, origTCPHeader *TCPHeader, seqNum, ackNum uint32, flags uint8, window, id uint16, responsePayload []byte) []byte {
	// IPv6 header
	ipv6Header := make([]byte, 40)
	binary.BigEndian.PutUint32(ipv6Header[0:4], 0x60000000) // Version 6, Traffic Class 0, Flow Label 0
	totalLen := 20 + len(responsePayload)                   // TCP + payload
	binary.BigEndian.PutUint16(ipv6Header[4:6], uint16(totalLen))
	ipv6Header[6] = PROTO_TCP // Next Header
	ipv6Header[7] = 64        // Hop Limit
	copy(ipv6Header[8:24], origIPv6Header.DstIP[:])
	copy(ipv6Header[24:40], origIPv6Header.SrcIP[:])

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

	// Calculate TCP checksum using IPv6 pseudo-header
	tcpChecksum := calculateIPv6Checksum(origIPv6Header.DstIP, origIPv6Header.SrcIP, PROTO_TCP, tcpData)
	binary.BigEndian.PutUint16(tcpData[16:18], tcpChecksum)

	// Combine IPv6 header and TCP data
	return append(ipv6Header, tcpData...)
}

func (cm *ConnMap) ProcessTCPv6Connection(ipv6hdr IPv6Header, packet []byte) (ConnKey, *ConnVal, TCPHeader, []byte, error) {
	tcphdr, payload := parseTCPHeader(packet)

	// Create ConnKey for IPv6
	key := ConnKey{
		SrcPort: int(tcphdr.SrcPort),
		DstPort: int(tcphdr.DstPort),
		IsIPv6:  true,
	}
	copy(key.SrcIP[:], ipv6hdr.SrcIP[:])
	copy(key.DstIP[:], ipv6hdr.DstIP[:])

	// Determine if this is from internal network or external
	addr := net.TCPAddr{
		IP:   net.IP(ipv6hdr.DstIP[:]),
		Port: int(tcphdr.DstPort),
	}

	if !isInternalIPv6Address(ipv6hdr.SrcIP) {
		// External to internal - swap addresses
		addr.IP = net.IP(ipv6hdr.SrcIP[:])
		addr.Port = int(tcphdr.SrcPort)
		// Swap key addresses
		copy(key.SrcIP[:], ipv6hdr.DstIP[:])
		copy(key.DstIP[:], ipv6hdr.SrcIP[:])
		key.SrcPort = int(tcphdr.DstPort)
		key.DstPort = int(tcphdr.SrcPort)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()
	item, exists := cm.data[key]
	if exists {
		debugPrintf("tcpv6: using existing key ...\r\n")
		item.lastActivity = time.Now()
	} else {
		debugPrintf("tcpv6: using new key ...\r\n")
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
	debugPrintf("[I] TCPv6 header: %+v\r\n", tcphdr)

	// Handle server connections differently
	if item.isServer {
		switch item.state.value {
		case TcpStateClosed:
			debugPrintf("[E] TCPv6 Server connection received SYN in closed state\r\n")
		case TcpStateInit:
			if tcphdr.Flags&(SYN|ACK) == (SYN | ACK) {
				item.HandleTcpv6SrvSYNACK(&ipv6hdr, &tcphdr)
			} else if tcphdr.Flags&RST != 0 {
				item.HandleTcpv6SrvRST(&ipv6hdr, &tcphdr)
			}
		case TcpStateEstablished:
			if payloadN > 0 {
				item.HandleTcpv6SrvData(&ipv6hdr, &tcphdr, payload)
			} else if tcphdr.Flags&FIN != 0 {
				item.HandleTcpv6SrvFIN(&ipv6hdr, &tcphdr)
			} else if tcphdr.Flags&ACK != 0 {
				item.HandleTcpv6SrvACK(&ipv6hdr, &tcphdr)
			}
		case TcpStateFinWait1:
			item.HandleTcpv6SrvFIN2(&ipv6hdr, &tcphdr)
		}
	} else {
		// Client connections (original logic)
		switch item.state.value {
		case TcpStateClosed:
			if tcphdr.Flags&SYN != 0 {
				item.HandleTcpv6ClnSYN(&ipv6hdr, &tcphdr)
			}
		case TcpStateInit:
			if tcphdr.Flags&ACK != 0 {
				item.HandleTcpv6ClnACK(&ipv6hdr, &tcphdr)
			}
		case TcpStateEstablished:
			if payloadN > 0 {
				item.HandleTcpv6ClnData(&ipv6hdr, &tcphdr, payload)
			} else if tcphdr.Flags&FIN != 0 {
				item.HandleTcpv6ClnFIN(&ipv6hdr, &tcphdr)
			} else if tcphdr.Flags&ACK != 0 {
				item.HandleTcpv6ClnACK(&ipv6hdr, &tcphdr)
			}
		case TcpStateFinWait1:
			item.HandleTcpv6ClnFIN2(&ipv6hdr, &tcphdr)
		}
	}
	return key, item, tcphdr, payload, nil
}

func (cv *ConnVal) handleTcpv6Response(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	buffer := make([]byte, 65535)
	for {
		if cv.TCPcln == nil {
			return
		}
		n, err := cv.TCPcln.Read(buffer)
		if err != nil {
			if err == io.EOF {
				cv.lock.Lock()
				if cv.state.inQ.Len() == 0 || len(cv.state.inQ.Back().Value.([]byte)) > 0 {
					cv.state.inQ.PushBack([]byte{})
				}
				cv.lock.Unlock()
			} else {
				debugPrintf("[I] TCPv6 read RST packet to %s:%d - %v\r\n", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort, err)
				cv.Dispose()
				ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
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
			go cv.actTcpv6Response(ipv6hdr, tcphdr)
		}
		cv.lock.Unlock()
	}
}

func (cv *ConnVal) actTcpv6Response(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	cv.lock.Lock()
	defer cv.lock.Unlock()
	if cv.state.inBusy || cv.state.inQ.Len() == 0 {
		return
	}
	cv.state.inBusy = true
	ipv6HeaderLen := 40
	tcpHeaderLen := 20
	maxPayloadByMTU := config.MTU - ipv6HeaderLen - tcpHeaderLen
	maxPayloadByWindow := int(tcphdr.Window)
	maxPayloadSize := maxPayloadByMTU
	if maxPayloadByWindow < maxPayloadSize {
		maxPayloadSize = maxPayloadByWindow
	}
	if maxPayloadSize <= 0 {
		// wait for window available
		cv.state.inBusy = false
		return
	}
	firstElem := cv.state.inQ.Front()
	data := firstElem.Value.([]byte)
	n := len(data)
	L := maxPayloadSize
	if cv.state.inOffset+maxPayloadSize > n {
		L = n - cv.state.inOffset
		data = data[cv.state.inOffset:]
		cv.state.inQ.Remove(firstElem)
		cv.state.inOffset = 0
	} else {
		data = data[cv.state.inOffset : cv.state.inOffset+L]
		cv.state.inOffset += L
	}
	if L == 0 {
		cv.state.inBusy = false
		return
	}
	ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, PSH|ACK, 65535, 0, data)
	debugPrintf("[I] forward slice read (+%d -> %d)/%d | %d ...\r\n", L, cv.state.inOffset, n, cv.state.inQ.Len())
	debugDumpPacket(ret)
	cv.state.serverSeq += uint32(L)
	cv.lastActivity = time.Now()
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
}

func (cv *ConnVal) HandleTcpv6ClnData(ipv6hdr *IPv6Header, tcphdr *TCPHeader, payload []byte) {
	cv.lock.Lock()
	if cv.state.clientSeq != tcphdr.SeqNum {
		debugPrintf("[E] TCPv6 invalid data packet %d <--> %d\r\n", cv.state.clientSeq, tcphdr.SeqNum)
		return
	}
	cv.lock.Unlock()
	debugPrintf("[I] Forwarding TCPv6 packet to %s:%d - %d byte(s)\r\n", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort, len(payload))
	if cv.TCPcln == nil {
		debugPrintf("[I] TCPv6 predata RST packet to %s:%d\r\n", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort)
		ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)
		return
	}
	_, err := cv.TCPcln.Write(payload)
	if err != nil {
		debugPrintf("[I] TCPv6 data RST packet to %s:%d\r\n", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort)
		ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)
		return
	}
	cv.lock.Lock()
	defer cv.lock.Unlock()
	cv.state.clientSeq = tcphdr.SeqNum + uint32(len(payload))
	ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	cv.lastActivity = time.Now()
}

func (cv *ConnVal) HandleTcpv6ClnSYN(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	debugPrintf("[I] TCPv6 SYN packet to %s:%d\r\n", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort)
	conn, err := net.DialTimeout("tcp6", fmt.Sprintf("[%s]:%d", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort), 5*time.Second)
	if err != nil {
		debugPrintf("[I] TCPv6 ACK-RST packet to %s:%d\r\n", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort)
		ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, 0, tcphdr.SeqNum, ACK|RST, 0, 0, nil)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)
		return
	}
	cv.lock.Lock()
	defer cv.lock.Unlock()
	cv.TCPcln, _ = conn.(*net.TCPConn)
	cv.state.value = TcpStateInit
	cv.state.clientSeq = tcphdr.SeqNum + 1
	cv.state.serverSeq = rand.Uint32()
	cv.state.inQ = list.New()
	cv.state.inOffset = 0
	cv.state.inBusy = false
	cv.lastActivity = time.Now()
	ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK|SYN, 65535, 0, nil)
	cv.state.serverSeq++
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	go cv.handleTcpv6Response(ipv6hdr, tcphdr)
}

func (cv *ConnVal) HandleTcpv6ClnACK(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	debugPrintf("[I] TCPv6 ACK packet to %s:%d\r\n", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	cv.state.clientSeq = tcphdr.SeqNum
	cv.state.serverSeq = tcphdr.AckNum
	if cv.state.value == TcpStateEstablished {
		cv.state.inBusy = false
		go cv.actTcpv6Response(ipv6hdr, tcphdr)
	} else if cv.state.value == TcpStateInit {
		cv.state.value = TcpStateEstablished
	}
}

func (cv *ConnVal) HandleTcpv6ClnFIN(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	debugPrintf("[I] TCPv6 FIN packet to %s:%d\r\n", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	cv.state.value = TcpStateFinWait1
	cv.state.clientSeq = tcphdr.SeqNum + 1
	ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	if cv.TCPcln != nil {
		cv.TCPcln.Close()
	}
}

func (cv *ConnVal) HandleTcpv6ClnFIN2(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	debugPrintf("[I] TCPv6 FIN-2 packet to %s:%d\r\n", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK|FIN, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	cv.state.serverSeq++
	cv.state.value = TcpStateClosed
}

func (cv *ConnVal) HandleTcpv6ClnRST(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	debugPrintf("[I] TCPv6 RST packet to %s:%d\r\n", net.IP(ipv6hdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	if cv.TCPcln != nil {
		cv.TCPcln.Close()
	}
	cv.state.value = TcpStateClosed
	ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
}

// Server-side TCPv6 handlers for SOCKS5 connections

func (cv *ConnVal) HandleTcpv6SrvSYNACK(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	debugPrintf("[I] TCPv6 Server received SYN-ACK from %s:%d\r\n", net.IP(ipv6hdr.SrcIP[:]), tcphdr.SrcPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	// Clear SYN timeout tracking - connection is now established
	cv.synSentTime = time.Time{}

	// Update sequence numbers
	cv.state.serverSeq = tcphdr.SeqNum + 1
	cv.state.clientSeq = tcphdr.AckNum
	cv.state.value = TcpStateEstablished
	cv.lastActivity = time.Now()

	// Send ACK to complete handshake
	ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.clientSeq, cv.state.serverSeq, ACK, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)

	// Send any buffered data from SOCKS5 client
	if len(cv.serverBuffer) > 0 {
		cv.sendBufferedDataToServerv6(ipv6hdr, tcphdr)
	}

	debugPrintf("[I] TCPv6 Server connection established\r\n")
}

func (cv *ConnVal) HandleTcpv6SrvData(ipv6hdr *IPv6Header, tcphdr *TCPHeader, payload []byte) {
	debugPrintf("[I] TCPv6 Server received %d bytes from %s:%d\r\n", len(payload), net.IP(ipv6hdr.SrcIP[:]), tcphdr.SrcPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	// Update sequence numbers
	cv.state.serverSeq = tcphdr.SeqNum + uint32(len(payload))
	cv.state.clientSeq = tcphdr.AckNum
	cv.lastActivity = time.Now()

	// Send ACK
	ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.clientSeq, cv.state.serverSeq, ACK, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)

	// Buffer data to be sent to SOCKS5 client
	cv.serverBuffer = append(cv.serverBuffer, payload...)
}

func (cv *ConnVal) HandleTcpv6SrvACK(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	debugPrintf("[I] TCPv6 Server received ACK from %s:%d\r\n", net.IP(ipv6hdr.SrcIP[:]), tcphdr.SrcPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	cv.state.clientSeq = tcphdr.SeqNum
	cv.state.serverSeq = tcphdr.AckNum
	cv.lastActivity = time.Now()
}

func (cv *ConnVal) HandleTcpv6SrvFIN(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	debugPrintf("[I] TCPv6 Server received FIN from %s:%d\r\n", net.IP(ipv6hdr.SrcIP[:]), tcphdr.SrcPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	// Clear timeout tracking
	cv.finSentTime = time.Time{}

	cv.state.value = TcpStateFinWait1
	cv.state.serverSeq = tcphdr.SeqNum + 1
	cv.lastActivity = time.Now()

	// Send ACK for FIN
	ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.clientSeq, cv.state.serverSeq, ACK, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)

	// Close SOCKS5 client connection
	if cv.TCPsrvConn != nil {
		cv.TCPsrvConn.Close()
		cv.TCPsrvConn = nil
	}
}

func (cv *ConnVal) HandleTcpv6SrvFIN2(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	debugPrintf("[I] TCPv6 Server FIN-2 from %s:%d\r\n", net.IP(ipv6hdr.SrcIP[:]), tcphdr.SrcPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.clientSeq, cv.state.serverSeq, ACK|FIN, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	cv.state.clientSeq++
	cv.state.value = TcpStateClosed
}

func (cv *ConnVal) HandleTcpv6SrvRST(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	debugPrintf("[I] TCPv6 Server received RST from %s:%d - server refused connection\r\n", net.IP(ipv6hdr.SrcIP[:]), tcphdr.SrcPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	// Clear timeout tracking
	cv.synSentTime = time.Time{}
	cv.finSentTime = time.Time{}

	cv.state.value = TcpStateClosed

	// Close SOCKS5 client connection - server refused the connection
	if cv.TCPsrvConn != nil {
		debugPrintf("[I] Closing SOCKS5 client connection due to server RST\r\n")
		cv.TCPsrvConn.Close()
		cv.TCPsrvConn = nil
	}
}

func (cv *ConnVal) sendBufferedDataToServerv6(ipv6hdr *IPv6Header, tcphdr *TCPHeader) {
	if len(cv.serverBuffer) == 0 {
		return
	}

	// Fragment data if necessary
	maxPayload := config.MTU - 40 - 20 // IPv6 header + TCP header
	data := cv.serverBuffer
	cv.serverBuffer = cv.serverBuffer[:0] // Clear buffer

	for len(data) > 0 {
		fragmentSize := len(data)
		if fragmentSize > maxPayload {
			fragmentSize = maxPayload
		}

		fragment := data[:fragmentSize]
		data = data[fragmentSize:]

		ret := GenerateIPv6TcpPacket(ipv6hdr, tcphdr, cv.state.clientSeq, cv.state.serverSeq, PSH|ACK, 65535, 0, fragment)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)

		cv.state.clientSeq += uint32(len(fragment))
	}
}
