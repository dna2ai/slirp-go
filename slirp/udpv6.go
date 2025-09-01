package slirp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

func GenerateIPv6UdpPacket(origIPv6Header *IPv6Header, origUDPHeader *UDPHeader, responsePayload []byte) []byte {
	// Calculate lengths
	udpLength := UDP_HEADER_LEN + len(responsePayload)
	totalLength := 40 + udpLength // IPv6 header is always 40 bytes

	// Create packet buffer
	packet := make([]byte, totalLength)

	// Build IPv6 header (swap source and destination)
	binary.BigEndian.PutUint32(packet[0:4], 0x60000000) // Version 6, Traffic Class 0, Flow Label 0
	binary.BigEndian.PutUint16(packet[4:6], uint16(udpLength))
	packet[6] = PROTO_UDP                        // Next Header
	packet[7] = 64                               // Hop Limit
	copy(packet[8:24], origIPv6Header.DstIP[:])  // Swap: original dst becomes src
	copy(packet[24:40], origIPv6Header.SrcIP[:]) // Swap: original src becomes dst

	// Build UDP header (swap ports)
	udpStart := 40
	binary.BigEndian.PutUint16(packet[udpStart:udpStart+2], origUDPHeader.DstPort)   // Swap ports
	binary.BigEndian.PutUint16(packet[udpStart+2:udpStart+4], origUDPHeader.SrcPort) // Swap ports
	binary.BigEndian.PutUint16(packet[udpStart+4:udpStart+6], uint16(udpLength))
	// UDP checksum will be calculated later

	// Copy payload
	copy(packet[udpStart+UDP_HEADER_LEN:], responsePayload)

	// Calculate UDP checksum using IPv6 pseudo-header
	udpChecksum := calculateIPv6Checksum(origIPv6Header.DstIP, origIPv6Header.SrcIP, PROTO_UDP, packet[udpStart:])
	binary.BigEndian.PutUint16(packet[udpStart+6:udpStart+8], udpChecksum)

	return packet
}

func (cm *ConnMap) ProcessUDPv6Connection(ipv6hdr IPv6Header, packet []byte) (ConnKey, *ConnVal, UDPHeader, []byte, error) {
	udphdr, payload := parseUdpHeader(packet)

	// Create ConnKey for IPv6
	key := ConnKey{
		SrcPort: int(udphdr.SrcPort),
		DstPort: int(udphdr.DstPort),
		IsIPv6:  true,
	}
	copy(key.SrcIP[:], ipv6hdr.SrcIP[:])
	copy(key.DstIP[:], ipv6hdr.DstIP[:])

	// Determine if this is from internal network or external
	addr := &net.UDPAddr{
		IP:   net.IP(ipv6hdr.DstIP[:]),
		Port: int(udphdr.DstPort),
	}

	if !isInternalIPv6Address(ipv6hdr.SrcIP) {
		// External to internal - swap addresses
		addr.IP = net.IP(ipv6hdr.SrcIP[:])
		addr.Port = int(udphdr.SrcPort)
		// Swap key addresses
		copy(key.SrcIP[:], ipv6hdr.DstIP[:])
		copy(key.DstIP[:], ipv6hdr.SrcIP[:])
		key.SrcPort = int(udphdr.DstPort)
		key.DstPort = int(udphdr.SrcPort)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()
	item, exists := cm.data[key]
	if exists {
		debugPrintf("udpv6: using existing key ...\r\n")
		item.lastActivity = time.Now()
	} else {
		debugPrintf("udpv6: using new key ...\r\n")
		udpConn, err := net.DialUDP("udp6", nil, addr)
		if err != nil {
			return key, item, udphdr, payload, fmt.Errorf("failed to dial UDPv6: %v", err)
		}
		item = &ConnVal{}
		item.Type = 200
		item.Key = &key
		item.UDPcln = udpConn
		item.lastActivity = time.Now()
		item.done = make(chan bool)
		item.disposed = false
		cm.data[key] = item
		go item.handleUdpv6Response(ipv6hdr, udphdr)
	}

	debugPrintf("[I] Forwarding UDPv6 packet to %s:%d\r\n", net.IP(ipv6hdr.DstIP[:]), udphdr.DstPort)
	_, err := item.UDPcln.Write(payload)
	if err != nil {
		return key, item, udphdr, payload, fmt.Errorf("failed to send UDPv6: %v", err)
	}
	return key, item, udphdr, payload, nil
}

func (cv *ConnVal) handleUdpv6Response(ipv6hdr IPv6Header, udphdr UDPHeader) {
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
			debugPrintf("[D] UDPv6 response\r\n")
			debugDumpPacket(response)

			// Construct response packet
			ret := GenerateIPv6UdpPacket(&ipv6hdr, &udphdr, response)
			encoded := encodeSLIP(ret)
			go seqPrintPacket(encoded)
			cv.lock.Unlock()
		}
	}
}
