package slirp

import (
	"container/list"
	"net"
	"sync"
	"time"
)

type SlirpConfig struct {
	Debug         bool
	MTU           int
	EnableIPv6    bool
	EnableServers bool
	Socks5Port    int
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

// IPv6 header structure (40 bytes)
type IPv6Header struct {
	VersionTCFL   uint32 // Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
	PayloadLength uint16
	NextHeader    uint8
	HopLimit      uint8
	SrcIP         [16]byte
	DstIP         [16]byte
}

// ICMP header structure
type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Unused   uint32
}

// ICMPv6 header structure
type ICMPv6Header struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Data     uint32
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
	SrcIP   [16]byte // Support both IPv4 and IPv6 (IPv4 mapped to first 4 bytes)
	SrcPort int
	DstIP   [16]byte // Support both IPv4 and IPv6 (IPv4 mapped to first 4 bytes)
	DstPort int
	IsIPv6  bool
}

type ConnVal struct {
	// 0 none, 100 tcp client, 101 tcp server, 200 udp client, 201 udp server
	Type         int
	Key          *ConnKey
	UDPcln       *net.UDPConn
	UDPsrv       *net.UDPConn
	TCPcln       *net.TCPConn
	TCPsrv       *net.TCPListener
	TCPsrvConn   *net.TCPConn // For accepted server connections
	lastActivity time.Time
	done         chan bool
	container    *ConnMap
	lock         sync.Mutex
	disposed     bool
	state        *TcpState
	isServer     bool
	serverBuffer []byte // Buffer for server-side data

	// Connection establishment tracking
	synSentTime       time.Time     // When SYN was sent
	finSentTime       time.Time     // When FIN was sent
	connectionTimeout time.Duration // Timeout for connection establishment
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
