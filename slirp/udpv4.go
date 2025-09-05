package slirp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

func parseUdpHeader(packet []byte) (UDPHeader, []byte) {
	var header UDPHeader
	header.SrcPort = 0
	header.DstPort = 0
	// VersionIHL = packet[0]
	i := int(packet[0]&0x0f) * 4
	header.SrcPort = binary.BigEndian.Uint16(packet[i : i+2])
	header.DstPort = binary.BigEndian.Uint16(packet[i+2 : i+4])
	header.Length = binary.BigEndian.Uint16(packet[i+4 : i+6])
	header.Checksum = binary.BigEndian.Uint16(packet[i+6 : i+8])
	return header, packet[i+8:]
}

func GenerateIpUdpPacket(origIPHeader *IPHeader, origUDPHeader *UDPHeader, responsePayload []byte) []byte {
	// Calculate lengths
	udpLength := UDP_HEADER_LEN + len(responsePayload)
	ipHeaderLen := int(origIPHeader.VersionIHL&0x0f) * 4 // Standard IP header without options
	totalLength := ipHeaderLen + udpLength

	// Create packet buffer
	packet := make([]byte, totalLength)

	// Build IP header (swap source and destination)
	packet[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	packet[1] = 0    // TOS
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	binary.BigEndian.PutUint16(packet[4:6], origIPHeader.ID+1) // Increment ID
	binary.BigEndian.PutUint16(packet[6:8], 0)                 // No flags, no fragment
	packet[8] = 64                                             // TTL
	packet[9] = 17                                             // UDP protocol
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

// SendUDPResponseToSocks5 sends a UDP response back to a SOCKS5 client
func SendUDPResponseToSocks5(socks5Server interface{}, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, payload []byte) {
	// This function will be called from connval.go handleUdpResponse
	// when we detect that the response should go to a SOCKS5 client

	if server, ok := socks5Server.(*Socks5Server); ok {
		// Create SOCKS5 UDP response header
		// +----+------+------+----------+----------+----------+
		// |RSV | FRAG | ATYP | SRC.ADDR | SRC.PORT |   DATA   |
		// +----+------+------+----------+----------+----------+
		// | 2  |  1   |  1   | Variable |    2     | Variable |
		// +----+------+------+----------+----------+----------+

		var response []byte
		response = append(response, 0, 0, 0) // RSV (2 bytes) + FRAG (1 byte)

		if srcIP.To4() != nil {
			// IPv4
			response = append(response, SOCKS5_ATYP_IPV4)
			response = append(response, srcIP.To4()...)
		} else {
			// IPv6
			response = append(response, SOCKS5_ATYP_IPV6)
			response = append(response, srcIP.To16()...)
		}

		// Add source port
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, srcPort)
		response = append(response, portBytes...)

		// Add payload
		response = append(response, payload...)

		// Send back to client
		clientAddr := &net.UDPAddr{
			IP:   dstIP, // The original client IP (now destination)
			Port: int(dstPort),
		}

		_, err := server.udpListener.WriteToUDP(response, clientAddr)
		if err != nil {
			debugPrintf("[E] Failed to send UDP response to SOCKS5 client: %v\r\n", err)
		} else {
			debugPrintf("[I] Sent UDP response to SOCKS5 client %s:%d\r\n", dstIP, dstPort)
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
			cv.lock.Lock()
			cv.UDPcln.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := cv.UDPcln.Read(buffer)
			if err != nil {
				cv.lock.Unlock()
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				cv.Dispose()
				return
			}
			cv.lastActivity = time.Now()
			response := buffer[:n]
			debugPrintf("[D] UDP response\r\n")
			debugDumpPacket(response)

			// Check if this should go to a SOCKS5 client
			// If the destination IP is from our internal gateway range, it might be a SOCKS5 client
			dstIP := net.IP(iphdr.SrcIP[:])
			srcIP := net.IP(iphdr.DstIP[:])

			// Check if this is a response that should go to SOCKS5
			if socks5Server != nil && dstIP.Equal(net.ParseIP("10.0.2.1")) {
				// This is likely a response to a SOCKS5 UDP request
				SendUDPResponseToSocks5(socks5Server, srcIP, udphdr.DstPort, dstIP, udphdr.SrcPort, response)
			} else {
				// Normal UDP response - construct response packet
				ret := GenerateIpUdpPacket(&iphdr, &udphdr, response)
				encoded := encodeSLIP(ret)
				go seqPrintPacket(encoded)
			}
			cv.lock.Unlock()
		}
	}
}

func (cm *ConnMap) ProcessUDPConnection(iphdr IPHeader, packet []byte) (ConnKey, *ConnVal, UDPHeader, []byte, error) {
	udphdr, payload := parseUdpHeader(packet)
	src := binary.BigEndian.Uint32(iphdr.SrcIP[:])
	sport := int(udphdr.SrcPort)
	dst := binary.BigEndian.Uint32(iphdr.DstIP[:])
	dport := int(udphdr.DstPort)
	addr := net.UDPAddr{
		IP:   net.IP(iphdr.DstIP[:]),
		Port: dport,
	}

	if (src & 0xffffff00) != GUEST_SUBNET {
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
		SrcIP:   src,
		SrcPort: sport,
		DstIP:   dst,
		DstPort: dport,
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	item, exists := cm.data[key]
	if exists {
		debugPrintf("udp: using exists key ...\r\n")
		item.lastActivity = time.Now()
	} else {
		debugPrintf("udp: using new key ...\r\n")
		udpConn, err := net.DialUDP("udp", nil, &addr)
		if err != nil {
			return key, item, udphdr, payload, fmt.Errorf("failed to dial UDP: %v", err)
		}
		item = &ConnVal{}
		item.Type = ConnTypeUdpClient
		item.Key = &key
		item.container = cm
		item.UDPcln = udpConn
		item.lastActivity = time.Now()
		item.done = make(chan bool)
		item.disposed = false
		cm.data[key] = item
		go item.handleUdpResponse(iphdr, udphdr)
	}

	debugPrintf("[I] Forwarding UDP packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), udphdr.DstPort)
	_, err := item.UDPcln.Write(payload)
	if err != nil {
		return key, item, udphdr, payload, fmt.Errorf("failed to send UDP: %v", err)
	}
	return key, item, udphdr, payload, nil
}
