package slirp

import (
	"container/list"
	"net"
	"sync"
	"time"
)

type ConnType int

const (
	ConnTypeNone ConnType = iota
	ConnTypeTcpClient
	ConnTypeTcpServer
	ConnTypeUdpClient
	ConnTypeUdpServer
	ConnTypeUnknown
)

type SlirpConfig struct {
	Debug      bool
	MTU        int
	Socks5Port int
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
	MSS        uint16
}

type packetAndHeader struct {
	iphdr  IPHeader
	packet []byte
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
	Type   ConnType
	Key    *ConnKey
	UDPcln *net.UDPConn
	TCPcln *net.TCPConn

	container    *ConnMap
	lastActivity time.Time
	done         chan bool
	lock         sync.Mutex
	disposed     bool
	state        *TcpState
	targetIP     uint32
	targetPort   int
}

type TcpState struct {
	value      int
	clientSeq  uint32
	serverSeq  uint32
	inQ        *list.List
	inOffset   int
	inBusy     bool
	packetQ    chan packetAndHeader // Packet queue for sequential processing
	// Retransmission and timeout fields
	lastPacket    []byte
	lastPacketSeq uint32
	lastSendTime  time.Time
	retryCount    int
	rto           time.Duration // Retransmission timeout
	closingState  bool          // Indicates if we're in closing process

	// Keep track of the latest headers from the client for window updates
	lastClientIpHeader  IPHeader
	lastClientTcpHeader TCPHeader
	serverClosed        bool // Indicates if the server has closed its end
}

type ConnMap struct {
	data map[ConnKey]*ConnVal
	mu   sync.RWMutex
}
