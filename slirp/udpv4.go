package slirp

import (
	"encoding/binary"
	"net"
	"time"
	"fmt"
)

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
		SrcIP: src,
		SrcPort: sport,
		DstIP: dst,
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
		item.Type = 200
		item.Key = &key
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

