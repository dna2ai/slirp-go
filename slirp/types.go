package slirp

import (
	"net"
	"time"
	"sync"
	"container/list"
)

type SlirpConfig struct {
	Debug bool
	MTU   int
}

// IP header structure (20 bytes minimum)
type IPHeader struct {
	VersionIHL     uint8
	TOS            uint8
	TotalLength    uint16
	ID             uint16
	FlagsFragOff   uint16
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	SrcIP          [4]byte
	DstIP          [4]byte
}

// ICMP header structure
type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Unused   uint32
}

// TCPHeader represents a TCP header
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
}

// UDPHeader represents a UDP header
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

type ConnKey struct {
        SrcIP   uint32
        SrcPort int
        DstIP   uint32
        DstPort int
}

type ConnVal struct {
	// 0 none, 100 tcp client, 101 tcp server, 200 udp client, 201 udp server
	Type int
	Key *ConnKey
	UDPcln *net.UDPConn
	UDPsrv *net.UDPConn
	TCPcln *net.TCPConn
	TCPsrv *net.TCPListener
	lastActivity time.Time
	done chan bool
	container *ConnMap
	lock sync.Mutex
	disposed bool
	state *TcpState
}

type TcpState struct {
	value     int
	clientSeq uint32
	serverSeq uint32
	inQ       *list.List
	inOffset  int
	inBusy    bool
}

type ConnMap struct {
	data map[ConnKey]*ConnVal
	mu   sync.RWMutex
}
