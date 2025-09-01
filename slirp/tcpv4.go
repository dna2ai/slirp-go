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

func parseTCPHeader(packet []byte) (TCPHeader, []byte) {
	// VersionIHL = packet[0]
	i := int(packet[0]&0x0f) * 4
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

func GenerateIpTcpPacket(origIPHeader *IPHeader, origTCPHeader *TCPHeader, seqNum, ackNum uint32, flags uint8, window, id uint16, responsePayload []byte) []byte {
	// IP header
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45                         // Version 4, IHL 5
	ipHeader[1] = 0                            // TOS
	totalLen := 20 + 20 + len(responsePayload) // IP + TCP + payload
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHeader[4:6], id)  // ID
	ipHeader[6] = 0x40                             // Don't fragment
	ipHeader[8] = 64                               // TTL
	ipHeader[9] = 6                                // TCP protocol
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

func (cm *ConnMap) ProcessTCPConnection(iphdr IPHeader, packet []byte) (ConnKey, *ConnVal, TCPHeader, []byte, error) {
	tcphdr, payload := parseTCPHeader(packet)
	src := binary.BigEndian.Uint32(iphdr.SrcIP[:])
	sport := int(tcphdr.SrcPort)
	dst := binary.BigEndian.Uint32(iphdr.DstIP[:])
	dport := int(tcphdr.DstPort)
	addr := net.UDPAddr{
		IP:   net.IP(iphdr.DstIP[:]),
		Port: dport,
	}
	if (src & 0xffffff00) != 0x0a000200 {
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
		SrcPort: sport,
		DstPort: dport,
		IsIPv6:  false,
	}
	// Map IPv4 addresses to first 4 bytes of the 16-byte array
	binary.BigEndian.PutUint32(key.SrcIP[:4], src)
	binary.BigEndian.PutUint32(key.DstIP[:4], dst)
	cm.mu.Lock()
	defer cm.mu.Unlock()
	item, exists := cm.data[key]
	if exists {
		debugPrintf("tcp: using exists key ...\r\n")
		item.lastActivity = time.Now()
	} else {
		debugPrintf("tcp: using new key ...\r\n")
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
	debugPrintf("[I] TCP header: %+v\r\n", tcphdr)
	// Handle server connections differently
	if item.isServer {
		switch item.state.value {
		case TcpStateClosed:
			// Server should not receive SYN in closed state - this is an error
			debugPrintf("[E] Server connection received SYN in closed state\r\n")
		case TcpStateInit:
			// Server waiting for SYN-ACK response from UML
			if tcphdr.Flags&(SYN|ACK) == (SYN | ACK) {
				item.HandleTcpSrvSYNACK(&iphdr, &tcphdr)
			} else if tcphdr.Flags&RST != 0 {
				item.HandleTcpSrvRST(&iphdr, &tcphdr)
			}
		case TcpStateEstablished:
			if payloadN > 0 {
				item.HandleTcpSrvData(&iphdr, &tcphdr, payload)
			} else if tcphdr.Flags&FIN != 0 {
				item.HandleTcpSrvFIN(&iphdr, &tcphdr)
			} else if tcphdr.Flags&ACK != 0 {
				item.HandleTcpSrvACK(&iphdr, &tcphdr)
			}
		case TcpStateFinWait1:
			item.HandleTcpSrvFIN2(&iphdr, &tcphdr)
		}
	} else {
		// Client connections (original logic)
		switch item.state.value {
		case TcpStateClosed:
			if tcphdr.Flags&SYN != 0 {
				item.HandleTcpClnSYN(&iphdr, &tcphdr)
			}
		case TcpStateInit:
			if tcphdr.Flags&ACK != 0 {
				item.HandleTcpClnACK(&iphdr, &tcphdr)
			} // -> server: TcpStateSynReceived, client: TcpStateEstablished
		case TcpStateEstablished:
			if payloadN > 0 {
				item.HandleTcpClnData(&iphdr, &tcphdr, payload)
			} else if tcphdr.Flags&FIN != 0 {
				item.HandleTcpClnFIN(&iphdr, &tcphdr)
			} else if tcphdr.Flags&ACK != 0 {
				item.HandleTcpClnACK(&iphdr, &tcphdr)
			}
		case TcpStateFinWait1:
			// FIN, server: TcpStateFinWait2
			item.HandleTcpClnFIN2(&iphdr, &tcphdr)
			// -> TcpStateClosed
		}
	}
	return key, item, tcphdr, payload, nil
}

func (cv *ConnVal) handleTcpResponse(iphdr *IPHeader, tcphdr *TCPHeader) {
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
				debugPrintf("[I] TCP read RST packet to %s:%d - %v\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort, err)
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
	ipHeaderLen := int(iphdr.VersionIHL&0x0f) * 4
	tcpHeaderLen := 20
	maxPayloadByMTU := config.MTU - ipHeaderLen - tcpHeaderLen
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
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, PSH|ACK, 65535, 0, data)
	debugPrintf("[I] forward slice read (+%d -> %d)/%d | %d ...\r\n", L, cv.state.inOffset, n, cv.state.inQ.Len())
	debugDumpPacket(ret)
	cv.state.serverSeq += uint32(L)
	cv.lastActivity = time.Now()
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
}

func (cv *ConnVal) HandleTcpClnData(iphdr *IPHeader, tcphdr *TCPHeader, payload []byte) {
	cv.lock.Lock()
	if cv.state.clientSeq != tcphdr.SeqNum {
		debugPrintf("[E] TCP invalid data packet %d <--> %d\r\n", cv.state.clientSeq, tcphdr.SeqNum)
		return
	}
	cv.lock.Unlock()
	debugPrintf("[I] Forwarding TCP packet to %s:%d - %d byte(s)\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort, len(payload))
	if cv.TCPcln == nil {
		debugPrintf("[I] TCP predata RST packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
		ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)
		return
	}
	_, err := cv.TCPcln.Write(payload)
	if err != nil {
		debugPrintf("[I] TCP data RST packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
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
	debugPrintf("[I] TCP SYN packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", net.IP(iphdr.DstIP[:]), tcphdr.DstPort), 5*time.Second)
	if err != nil {
		debugPrintf("[I] TCP ACK-RST packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
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
	cv.state.serverSeq = rand.Uint32()
	cv.state.inQ = list.New()
	cv.state.inOffset = 0
	cv.state.inBusy = false
	cv.lastActivity = time.Now()
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK|SYN, 65535, 0, nil)
	cv.state.serverSeq++
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	go cv.handleTcpResponse(iphdr, tcphdr)
}

func (cv *ConnVal) HandleTcpClnACK(iphdr *IPHeader, tcphdr *TCPHeader) {
	debugPrintf("[I] TCP ACK packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
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
	debugPrintf("[I] TCP FIN packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
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
	debugPrintf("[I] TCP FIN-2 packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	//cv.state.value = TcpStateClosing
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK|FIN, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	cv.state.serverSeq++
	cv.state.value = TcpStateClosed
	// TODO: remove from cm
}

func (cv *ConnVal) HandleTcpClnRST(iphdr *IPHeader, tcphdr *TCPHeader) {
	debugPrintf("[I] TCP RST packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
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

// Server-side TCP handlers for SOCKS5 connections

func (cv *ConnVal) HandleTcpSrvSYNACK(iphdr *IPHeader, tcphdr *TCPHeader) {
	debugPrintf("[I] TCP Server received SYN-ACK from %s:%d\r\n", net.IP(iphdr.SrcIP[:]), tcphdr.SrcPort)
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
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.clientSeq, cv.state.serverSeq, ACK, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)

	// Send any buffered data from SOCKS5 client
	if len(cv.serverBuffer) > 0 {
		cv.sendBufferedDataToServer(iphdr, tcphdr)
	}

	debugPrintf("[I] TCP Server connection established\r\n")
}

func (cv *ConnVal) HandleTcpSrvData(iphdr *IPHeader, tcphdr *TCPHeader, payload []byte) {
	debugPrintf("[I] TCP Server received %d bytes from %s:%d\r\n", len(payload), net.IP(iphdr.SrcIP[:]), tcphdr.SrcPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	// Update sequence numbers
	cv.state.serverSeq = tcphdr.SeqNum + uint32(len(payload))
	cv.state.clientSeq = tcphdr.AckNum
	cv.lastActivity = time.Now()

	// Send ACK
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.clientSeq, cv.state.serverSeq, ACK, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)

	// Buffer data to be sent to SOCKS5 client
	cv.serverBuffer = append(cv.serverBuffer, payload...)
}

func (cv *ConnVal) HandleTcpSrvACK(iphdr *IPHeader, tcphdr *TCPHeader) {
	debugPrintf("[I] TCP Server received ACK from %s:%d\r\n", net.IP(iphdr.SrcIP[:]), tcphdr.SrcPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	cv.state.clientSeq = tcphdr.SeqNum
	cv.state.serverSeq = tcphdr.AckNum
	cv.lastActivity = time.Now()
}

func (cv *ConnVal) HandleTcpSrvFIN(iphdr *IPHeader, tcphdr *TCPHeader) {
	debugPrintf("[I] TCP Server received FIN from %s:%d\r\n", net.IP(iphdr.SrcIP[:]), tcphdr.SrcPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	// Clear timeout tracking
	cv.finSentTime = time.Time{}

	cv.state.value = TcpStateFinWait1
	cv.state.serverSeq = tcphdr.SeqNum + 1
	cv.lastActivity = time.Now()

	// Send ACK for FIN
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.clientSeq, cv.state.serverSeq, ACK, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)

	// Close SOCKS5 client connection
	if cv.TCPsrvConn != nil {
		cv.TCPsrvConn.Close()
		cv.TCPsrvConn = nil
	}
}

func (cv *ConnVal) HandleTcpSrvFIN2(iphdr *IPHeader, tcphdr *TCPHeader) {
	debugPrintf("[I] TCP Server FIN-2 from %s:%d\r\n", net.IP(iphdr.SrcIP[:]), tcphdr.SrcPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.clientSeq, cv.state.serverSeq, ACK|FIN, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	cv.state.clientSeq++
	cv.state.value = TcpStateClosed
}

func (cv *ConnVal) HandleTcpSrvRST(iphdr *IPHeader, tcphdr *TCPHeader) {
	debugPrintf("[I] TCP Server received RST from %s:%d - server refused connection\r\n", net.IP(iphdr.SrcIP[:]), tcphdr.SrcPort)
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

func (cv *ConnVal) sendBufferedDataToServer(iphdr *IPHeader, tcphdr *TCPHeader) {
	if len(cv.serverBuffer) == 0 {
		return
	}

	// Fragment data if necessary
	maxPayload := config.MTU - 20 - 20 // IP header + TCP header
	data := cv.serverBuffer
	cv.serverBuffer = cv.serverBuffer[:0] // Clear buffer

	for len(data) > 0 {
		fragmentSize := len(data)
		if fragmentSize > maxPayload {
			fragmentSize = maxPayload
		}

		fragment := data[:fragmentSize]
		data = data[fragmentSize:]

		ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.clientSeq, cv.state.serverSeq, PSH|ACK, 65535, 0, fragment)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)

		cv.state.clientSeq += uint32(len(fragment))
	}
}
