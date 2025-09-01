package slirp

import (
	"encoding/binary"
)

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

func parseIPv6Header(packet []byte) IPv6Header {
	var header IPv6Header
	header.VersionTCFL = binary.BigEndian.Uint32(packet[0:4])
	header.PayloadLength = binary.BigEndian.Uint16(packet[4:6])
	header.NextHeader = packet[6]
	header.HopLimit = packet[7]
	copy(header.SrcIP[:], packet[8:24])
	copy(header.DstIP[:], packet[24:40])
	return header
}

func isIPv6Packet(packet []byte) bool {
	if len(packet) < 1 {
		return false
	}
	version := (packet[0] >> 4) & 0x0F
	return version == 6
}
