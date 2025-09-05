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

func (cm *ConnMap) BuildConnectionKey(iphdr *IPHeader, sport, dport int) *ConnKey {
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
