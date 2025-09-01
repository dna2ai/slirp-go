package slirp

import (
	"encoding/binary"
	"syscall"
	"fmt"
)

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
			debugPrintf("[D] ping intranet at 10.0.2.%d\r\n", dstIPuint32 & 0xff)
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
	responseBuf := make([]byte, 65536)
	n, peer, err := syscall.Recvfrom(fd, responseBuf, 0)
	debugPrintf("Received %d bytes from %s\r\n", n, peer)
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

