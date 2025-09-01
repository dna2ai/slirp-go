package slirp

import (
	"time"
)

// TCP flags
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
)

// Connection states
const (
	TcpStateInit = iota
	TcpStateSynReceived
	TcpStateEstablished
	TcpStateFinWait1
	TcpStateFinWait2
	TcpStateClosing
	TcpStateClosed
)

const (
	SLIP_END     = 0xC0
	SLIP_ESC     = 0xDB
	SLIP_ESC_END = 0xDC
	SLIP_ESC_ESC = 0xDD

	// IP protocol numbers
	PROTO_ICMP   = 1
	PROTO_TCP    = 6
	PROTO_UDP    = 17
	PROTO_IPV6   = 41
	PROTO_ICMPV6 = 58

	// ICMP types
	ICMP_ECHO_REQUEST = 8
	ICMP_ECHO_REPLY   = 0
	ICMP_DEST_UNREACH = 3
	ICMP_HOST_UNREACH = 1

	// ICMPv6 types
	ICMPV6_ECHO_REQUEST   = 128
	ICMPV6_ECHO_REPLY     = 129
	ICMPV6_DEST_UNREACH   = 1
	ICMPV6_PACKET_TOO_BIG = 2
	ICMPV6_TIME_EXCEEDED  = 3
	ICMPV6_PARAM_PROBLEM  = 4

	UDP_HEADER_LEN = 8
	UDP_TIMEOUT    = 30 * time.Second

	// Default IPv6 addresses for SLIRP
	IPV6_GUEST_PREFIX = "fd00::"
	IPV6_GATEWAY      = "fd00::2"
	IPV6_GUEST        = "fd00::15"
)
