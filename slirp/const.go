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
	PROTO_ICMP = 1
	PROTO_TCP  = 6
	PROTO_UDP  = 17

	// ICMP types
	ICMP_ECHO_REQUEST = 8
	ICMP_ECHO_REPLY   = 0
	ICMP_DEST_UNREACH = 3
	ICMP_HOST_UNREACH = 1

	UDP_HEADER_LEN = 8
	UDP_TIMEOUT    = 30 * time.Second

	// TCP timeout constants
	TCP_INITIAL_RTO    = 1 * time.Second
	TCP_MAX_RTO        = 60 * time.Second
	TCP_MAX_RETRIES    = 3
	TCP_KEEPALIVE_TIME = 2 * time.Hour
)
