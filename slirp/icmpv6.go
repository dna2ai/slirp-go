package slirp

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

func parseICMPv6Header(packet []byte, ipv6HeaderLen int) (ICMPv6Header, []byte) {
	var header ICMPv6Header
	header.Type = packet[ipv6HeaderLen]
	header.Code = packet[ipv6HeaderLen+1]
	header.Checksum = binary.BigEndian.Uint16(packet[ipv6HeaderLen+2 : ipv6HeaderLen+4])
	header.Data = binary.BigEndian.Uint32(packet[ipv6HeaderLen+4 : ipv6HeaderLen+8])
	return header, packet[ipv6HeaderLen+8:]
}

func generateICMPv6Response(originalIPv6Header *IPv6Header, icmpv6Response []byte) []byte {
	// Create a new IPv6 header for the response
	// Swap source and destination
	responseIPv6Header := IPv6Header{
		VersionTCFL:   0x60000000, // IPv6, Traffic Class 0, Flow Label 0
		PayloadLength: uint16(len(icmpv6Response)),
		NextHeader:    PROTO_ICMPV6,
		HopLimit:      64,
		SrcIP:         originalIPv6Header.DstIP,
		DstIP:         originalIPv6Header.SrcIP,
	}

	// Create the IPv6 packet
	ipv6Packet := make([]byte, 40+len(icmpv6Response))

	// Fill in the IPv6 header
	binary.BigEndian.PutUint32(ipv6Packet[0:4], responseIPv6Header.VersionTCFL)
	binary.BigEndian.PutUint16(ipv6Packet[4:6], responseIPv6Header.PayloadLength)
	ipv6Packet[6] = responseIPv6Header.NextHeader
	ipv6Packet[7] = responseIPv6Header.HopLimit
	copy(ipv6Packet[8:24], responseIPv6Header.SrcIP[:])
	copy(ipv6Packet[24:40], responseIPv6Header.DstIP[:])

	// Copy the ICMPv6 response
	copy(ipv6Packet[40:], icmpv6Response)

	return ipv6Packet
}

func generateICMPv6HostUnreachable(origIPv6 IPv6Header, origPacket []byte) []byte {
	// Create new IPv6 header (swap src/dst)
	icmpv6Len := 8 + 40 + 8 // ICMPv6 header + IPv6 header + 8 bytes of original data
	totalLen := 40 + icmpv6Len

	response := make([]byte, totalLen)

	// IPv6 Header
	binary.BigEndian.PutUint32(response[0:4], 0x60000000) // Version 6, Traffic Class 0, Flow Label 0
	binary.BigEndian.PutUint16(response[4:6], uint16(icmpv6Len))
	response[6] = PROTO_ICMPV6               // Next Header
	response[7] = 64                         // Hop Limit
	copy(response[8:24], origIPv6.DstIP[:])  // Src IP (our IP is original dst)
	copy(response[24:40], origIPv6.SrcIP[:]) // Dst IP

	// ICMPv6 Header
	icmpv6Start := 40
	response[icmpv6Start] = ICMPV6_DEST_UNREACH // Type
	response[icmpv6Start+1] = 0                 // Code (No route to destination)
	// Checksum calculated later
	binary.BigEndian.PutUint32(response[icmpv6Start+4:icmpv6Start+8], 0) // Unused

	// Copy original IPv6 header + first 8 bytes of data
	copyLen := 48 // IPv6 header (40) + 8 bytes
	if len(origPacket) < copyLen {
		copyLen = len(origPacket)
	}
	copy(response[icmpv6Start+8:], origPacket[:copyLen])

	// Calculate ICMPv6 checksum (includes pseudo-header)
	icmpv6Checksum := calculateIPv6Checksum(origIPv6.DstIP, origIPv6.SrcIP, PROTO_ICMPV6, response[icmpv6Start:])
	binary.BigEndian.PutUint16(response[icmpv6Start+2:icmpv6Start+4], icmpv6Checksum)

	return response
}

func processICMPv6Packet(ipv6hdr IPv6Header, packet []byte) ([]byte, error) {
	if len(packet) < 40+8 {
		return nil, fmt.Errorf("packet too small for ICMPv6 header")
	}

	icmpv6Header, icmpv6Payload := parseICMPv6Header(packet, 40)

	switch icmpv6Header.Type {
	case ICMPV6_ECHO_REQUEST:
		// Check if it's for our internal IPv6 network
		if isInternalIPv6Address(ipv6hdr.DstIP) {
			debugPrintf("[D] ping internal IPv6 address\r\n")
			responseICMPv6 := packet[40:]
			// Change type to echo reply
			responseICMPv6[0] = ICMPV6_ECHO_REPLY
			binary.BigEndian.PutUint16(responseICMPv6[2:4], 0) // Zero checksum for calculation
			checksum := calculateIPv6Checksum(ipv6hdr.DstIP, ipv6hdr.SrcIP, PROTO_ICMPV6, responseICMPv6)
			binary.BigEndian.PutUint16(responseICMPv6[2:4], checksum)
			return generateICMPv6Response(&ipv6hdr, responseICMPv6), nil
		}
		response, err := forwardICMPv6Request(&ipv6hdr, &icmpv6Header, icmpv6Payload)
		if err != nil {
			return nil, fmt.Errorf("failed to forward ICMPv6 request: %v", err)
		}
		return response, nil
	default:
		// For other ICMPv6 types, we might need different handling
		return nil, fmt.Errorf("unsupported ICMPv6 type: %d", icmpv6Header.Type)
	}
}

func forwardICMPv6Request(ipv6hdr *IPv6Header, icmpv6Header *ICMPv6Header, payload []byte) ([]byte, error) {
	// Create a raw ICMPv6 socket
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMPV6)
	if fd < 0 {
		return nil, fmt.Errorf("failed to create ICMPv6 socket: %v", err)
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5})
	if err != nil {
		return nil, fmt.Errorf("failed to set receive timeout: %v", err)
	}

	// Reconstruct the ICMPv6 packet
	icmpv6Packet := make([]byte, 8+len(payload))
	icmpv6Packet[0] = icmpv6Header.Type
	icmpv6Packet[1] = icmpv6Header.Code
	binary.BigEndian.PutUint16(icmpv6Packet[2:4], 0) // Zero checksum for calculation
	binary.BigEndian.PutUint32(icmpv6Packet[4:8], icmpv6Header.Data)
	copy(icmpv6Packet[8:], payload)

	// Calculate and set checksum
	checksum := calculateIPv6Checksum(ipv6hdr.SrcIP, ipv6hdr.DstIP, PROTO_ICMPV6, icmpv6Packet)
	binary.BigEndian.PutUint16(icmpv6Packet[2:4], checksum)

	// Send the ICMPv6 packet
	dstAddr := &syscall.SockaddrInet6{
		Port: 0,
		Addr: ipv6hdr.DstIP,
	}
	if err := syscall.Sendto(fd, icmpv6Packet, 0, dstAddr); err != nil {
		return nil, fmt.Errorf("failed to send ICMPv6 packet: %v", err)
	}

	// Read the response
	responseBuf := make([]byte, 65536)
	n, peer, err := syscall.Recvfrom(fd, responseBuf, 0)
	debugPrintf("Received %d bytes from %s\r\n", n, peer)
	if err != nil {
		if nerr, ok := err.(syscall.Errno); ok && nerr == syscall.EAGAIN {
			return nil, fmt.Errorf("failed to read ICMPv6 timeout: %v", err)
		}
		return nil, fmt.Errorf("failed to read ICMPv6 response: %v", err)
	}

	// The response includes the IPv6 header, so we need to parse it
	if n < 40 {
		return nil, fmt.Errorf("response too small")
	}

	// Skip the IPv6 header
	if n < 40+8 {
		return nil, fmt.Errorf("response too small for ICMPv6")
	}

	responseICMPv6 := responseBuf[40:n]
	// Restore original data field
	binary.BigEndian.PutUint32(responseICMPv6[4:8], icmpv6Header.Data)
	binary.BigEndian.PutUint16(responseICMPv6[2:4], 0) // Zero checksum for calculation
	checksum = calculateIPv6Checksum(ipv6hdr.DstIP, ipv6hdr.SrcIP, PROTO_ICMPV6, responseICMPv6)
	binary.BigEndian.PutUint16(responseICMPv6[2:4], checksum)

	// Generate the complete IPv6 packet for the response
	return generateICMPv6Response(ipv6hdr, responseICMPv6), nil
}

func isInternalIPv6Address(addr [16]byte) bool {
	// Check if it's in our internal IPv6 network (fd00::/8)
	return addr[0] == 0xfd && addr[1] == 0x00
}

func calculateIPv6Checksum(srcIP [16]byte, dstIP [16]byte, nextHeader uint8, data []byte) uint16 {
	pseudoHeader := make([]byte, 40)
	copy(pseudoHeader[0:16], srcIP[:])
	copy(pseudoHeader[16:32], dstIP[:])
	binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(data)))
	pseudoHeader[36] = 0
	pseudoHeader[37] = 0
	pseudoHeader[38] = 0
	pseudoHeader[39] = nextHeader
	return calculateChecksum(append(pseudoHeader, data...))
}
