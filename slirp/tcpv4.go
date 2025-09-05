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

func (cm *ConnMap) BuildTcpConnectionKey(iphdr *IPHeader, sport, dport int) *ConnKey {
	src := binary.BigEndian.Uint32(iphdr.SrcIP[:])
	dst := binary.BigEndian.Uint32(iphdr.DstIP[:])
	if src > dst || (src == dst && sport > dport) {
		tmp := src
		tport := sport
		src = dst
		sport = dport
		dst = tmp
		dport = tport
	}
	ret := &ConnKey{
		SrcIP:   src,
		SrcPort: sport,
		DstIP:   dst,
		DstPort: dport,
	}
	return ret
}

func (cm *ConnMap) ProcessTCPConnection(iphdr IPHeader, packet []byte) (*ConnKey, *ConnVal, TCPHeader, []byte, error) {
	tcphdr, payload := parseTCPHeader(packet)
	sport := int(tcphdr.SrcPort)
	dport := int(tcphdr.DstPort)
	key := cm.BuildTcpConnectionKey(&iphdr, sport, dport)
	cm.mu.Lock()
	defer cm.mu.Unlock()
	item, exists := cm.data[*key]
	if exists {
		debugPrintf("tcp: using existing key ...\r\n")
		item.lastActivity = time.Now()
	} else {
		debugPrintf("tcp: using new key ...\r\n")
		item = &ConnVal{}
		item.Type = ConnTypeTcpClient
		item.Key = key
		item.container = cm
		item.lastActivity = time.Now()
		item.done = make(chan bool)
		item.state = &TcpState{}
		item.state.value = TcpStateClosed
		item.state.packetQ = make(chan packetAndHeader, 100) // Buffer for 100 packets
		item.disposed = false
		cm.data[*key] = item
		go item.processTcpPacketQ()
	}
	item.state.packetQ <- packetAndHeader{iphdr: iphdr, packet: packet}
	return key, item, tcphdr, payload, nil
}

func (cv *ConnVal) processTcpPacketQ() {
	for ph := range cv.state.packetQ {
		iphdr := ph.iphdr
		packet := ph.packet

		tcphdr, payload := parseTCPHeader(packet)

		// Handle RST packets first, as they can occur in any state.
		if tcphdr.Flags&RST != 0 {
			cv.HandleTcpClnRST(&iphdr, &tcphdr)
			return // Stop processing for this connection.
		}

		payloadN := len(payload)
		debugPrintf("[I] TCP header: %+v\r\n", tcphdr)

		cv.lock.Lock()
		stateValue := cv.state.value
		cv.lock.Unlock()

		switch stateValue {
		case TcpStateClosed:
			if tcphdr.Flags&SYN != 0 {
				cv.HandleTcpClnSYN(&iphdr, &tcphdr)
			}
		case TcpStateInit:
			if tcphdr.Flags&ACK != 0 {
				if tcphdr.Flags&SYN != 0 {
					cv.HandleTcpClnSYNACK(&iphdr, &tcphdr)
				} else {
					cv.HandleTcpClnACK(&iphdr, &tcphdr)
				}
			} // -> server: TcpStateSynReceived, client: TcpStateEstablished
		case TcpStateEstablished:
			if payloadN > 0 {
				cv.HandleTcpClnData(&iphdr, &tcphdr, payload)
			} else if tcphdr.Flags&FIN != 0 {
				cv.HandleTcpClnFIN(&iphdr, &tcphdr)
			} else if tcphdr.Flags&ACK != 0 {
				cv.HandleTcpClnACK(&iphdr, &tcphdr)
			}
		case TcpStateFinWait1:
			if tcphdr.Flags&ACK != 0 {
				cv.lock.Lock()
				cv.state.value = TcpStateFinWait2
				cv.lock.Unlock()
				debugPrintf("[I] TCP state transition to FIN_WAIT_2\r\n")
			}
		case TcpStateFinWait2:
			if tcphdr.Flags&FIN != 0 {
				cv.HandleTcpClnFIN(&iphdr, &tcphdr)
			}
		case TcpStateCloseWait:
			// The client should not be sending any more data.
			// We are waiting for the server to close.
			// We continue to loop to handle potential RSTs.
			break
		case TcpStateLastAck:
			if tcphdr.Flags&ACK != 0 {
				cv.lock.Lock()
				cv.state.value = TcpStateClosed
				cv.Dispose()
				if cv.container != nil {
					cv.container.Pop(cv.Key)
				}
				cv.lock.Unlock()
				debugPrintf("[I] TCP connection closed (LAST_ACK)\r\n")
			}
		}
	}
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
				// Properly handle EOF - remote side closed connection
				debugPrintf("[I] TCP EOF from remote, initiating FIN sequence to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
				cv.lock.Lock()
				if cv.state.value == TcpStateEstablished {
					// Active close from server side
					cv.state.value = TcpStateFinWait1
					ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, FIN|ACK, 65535, 0, nil)
					cv.state.serverSeq++
					encoded := encodeSLIP(ret)
					go seqPrintPacket(encoded)
				} else if cv.state.value == TcpStateCloseWait {
					// Passive close, we have received FIN from client, now server is done
					cv.state.value = TcpStateLastAck
					ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, FIN|ACK, 65535, 0, nil)
					cv.state.serverSeq++
					encoded := encodeSLIP(ret)
					go seqPrintPacket(encoded)
				}
				cv.lock.Unlock()
			} else {
				debugPrintf("[I] TCP read error, sending RST to %s:%d - %v\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort, err)
				cv.Dispose()
				ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, tcphdr.Window, 0, nil)
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
	if maxPayloadSize <= 0 && !cv.state.closingState {
		// wait for window available (but allow FIN to be sent)
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

	// Check if this is a FIN signal (empty data and closing state)
	var flags uint8 = PSH | ACK
	if L == 0 && cv.state.closingState {
		// Send FIN|ACK to initiate close
		flags = FIN | ACK
		debugPrintf("[I] Sending FIN|ACK to client due to EOF from remote\r\n")
		cv.state.value = TcpStateFinWait1
	} else if L == 0 {
		cv.state.inBusy = false
		return
	}

	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, flags, 65535, 0, data)
	debugPrintf("[I] forward slice read (+%d -> %d)/%d | %d ...\r\n", L, cv.state.inOffset, n, cv.state.inQ.Len())
	debugDumpPacket(ret)

	// Store packet for potential retransmission
	cv.state.lastPacket = ret
	cv.state.lastPacketSeq = cv.state.serverSeq
	cv.state.lastSendTime = time.Now()
	cv.state.retryCount = 0
	if cv.state.rto == 0 {
		cv.state.rto = TCP_INITIAL_RTO
	}

	cv.state.serverSeq += uint32(L)
	if flags&FIN != 0 {
		cv.state.serverSeq++ // FIN consumes a sequence number
	}
	cv.lastActivity = time.Now()
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)

	// Start retransmission timer if not already running
	go cv.startRetransmissionTimer(iphdr, tcphdr)
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
		ret := GenerateIpTcpPacket(iphdr, tcphdr, 0, tcphdr.SeqNum+1, ACK|RST, 0, 0, nil)
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
	cv.state.closingState = false
	cv.state.rto = TCP_INITIAL_RTO
	cv.lastActivity = time.Now()
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK|SYN, tcphdr.Window, 0, nil)

	// Store packet for retransmission
	cv.state.lastPacket = ret
	cv.state.lastPacketSeq = cv.state.serverSeq
	cv.state.lastSendTime = time.Now()
	cv.state.retryCount = 0

	cv.state.serverSeq++
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)
	go cv.startRetransmissionTimer(iphdr, tcphdr)
	go cv.handleTcpResponse(iphdr, tcphdr)
}

func (cv *ConnVal) HandleTcpClnSYNACK(iphdr *IPHeader, tcphdr *TCPHeader) {
	debugPrintf("[I] TCP SYN-ACK packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	cv.state.value = TcpStateEstablished
	cv.state.serverSeq = tcphdr.AckNum
	cv.state.clientSeq = tcphdr.SeqNum + 1
	cv.state.inQ = list.New()
	cv.state.inOffset = 0
	cv.state.inBusy = false
	cv.lastActivity = time.Now()
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK, tcphdr.Window, 0, nil)
	debugPrintf("[I] TCP ACK packet to %s:%d\r\n", net.IP(iphdr.SrcIP[:]), tcphdr.SrcPort)
	debugDumpPacket(ret)
	encoded := encodeSLIP(ret)
	seqPrintPacket(encoded)
	go cv.handleTcpResponse(iphdr, tcphdr)
}

func (cv *ConnVal) HandleTcpClnACK(iphdr *IPHeader, tcphdr *TCPHeader) {
	debugPrintf("[I] TCP ACK packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()

	// Check if this ACK acknowledges our sent data
	if cv.state.lastPacket != nil && tcphdr.AckNum >= cv.state.lastPacketSeq {
		// ACK received, reset retransmission timer
		cv.resetRetransmissionTimer()
	}

	if cv.state.clientSeq == tcphdr.SeqNum {
		// This is a pure ACK, no data
		if tcphdr.AckNum > cv.state.serverSeq {
			cv.state.serverSeq = tcphdr.AckNum
		}
	} else {
		// ACK with data, let HandleTcpClnData handle it
		return
	}

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

	if cv.state.value == TcpStateEstablished {
		// Client wants to close, move to CLOSE_WAIT
		cv.state.value = TcpStateCloseWait
		// Acknowledge the FIN
		cv.state.clientSeq = tcphdr.SeqNum + 1
		ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK, 65535, 0, nil)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)
		// Close the write half of the connection to the server
		if cv.TCPcln != nil {
			cv.TCPcln.CloseWrite()
		}
	} else if cv.state.value == TcpStateFinWait2 {
		// This is the final ACK/FIN from the client
		cv.state.clientSeq = tcphdr.SeqNum + 1
		ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, ACK, 65535, 0, nil)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)
		// Close connection
		cv.state.value = TcpStateClosed
		cv.Dispose()
		if cv.container != nil {
			cv.container.Pop(cv.Key)
		}
	}
}

func (cv *ConnVal) HandleTcpClnRST(iphdr *IPHeader, tcphdr *TCPHeader) {
	debugPrintf("[I] TCP RST packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), tcphdr.DstPort)
	cv.lock.Lock()
	defer cv.lock.Unlock()
	cv.Close()
	cv.state.value = TcpStateClosed
	ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
	encoded := encodeSLIP(ret)
	go seqPrintPacket(encoded)

	// Clean up immediately for RST
	cv.Dispose()
	if cv.container != nil {
		cv.container.Pop(cv.Key)
	}
}

// startRetransmissionTimer starts a timer for packet retransmission
func (cv *ConnVal) startRetransmissionTimer(iphdr *IPHeader, tcphdr *TCPHeader) {
	time.Sleep(cv.state.rto)

	cv.lock.Lock()
	defer cv.lock.Unlock()

	// Check if we still need to retransmit
	if cv.disposed || cv.state.lastPacket == nil {
		return
	}

	// Check if ACK was received (sequence number advanced)
	if time.Since(cv.state.lastSendTime) < cv.state.rto {
		return // ACK received, no need to retransmit
	}

	if cv.state.retryCount >= TCP_MAX_RETRIES {
		debugPrintf("[E] TCP max retries reached, closing connection\r\n")
		cv.Dispose()
		ret := GenerateIpTcpPacket(iphdr, tcphdr, cv.state.serverSeq, cv.state.clientSeq, RST, 65535, 0, nil)
		encoded := encodeSLIP(ret)
		go seqPrintPacket(encoded)
		return
	}

	// Retransmit the packet
	cv.state.retryCount++
	cv.state.rto = cv.state.rto * 2
	if cv.state.rto > TCP_MAX_RTO {
		cv.state.rto = TCP_MAX_RTO
	}
	cv.state.lastSendTime = time.Now()

	debugPrintf("[I] TCP retransmitting packet (attempt %d)\r\n", cv.state.retryCount)
	encoded := encodeSLIP(cv.state.lastPacket)
	go seqPrintPacket(encoded)

	// Schedule next retransmission
	go cv.startRetransmissionTimer(iphdr, tcphdr)
}

// resetRetransmissionTimer resets the retransmission state when ACK is received
func (cv *ConnVal) resetRetransmissionTimer() {
	cv.state.lastPacket = nil
	cv.state.retryCount = 0
	cv.state.rto = TCP_INITIAL_RTO
	cv.state.lastSendTime = time.Time{}
}
