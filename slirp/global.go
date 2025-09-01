package slirp

import (
	"bufio"
	"flag"
	"io"
	"net"
	"os"
	"sync"
)

var (
	printMutex     sync.Mutex
	debugDumpMutex sync.Mutex
	reader         *bufio.Reader
	writer         *bufio.Writer
	config         *SlirpConfig
	socks5Server   *Socks5Server
)

func Run() {
	reader = bufio.NewReader(os.Stdin)
	writer = bufio.NewWriter(os.Stdout)
	cm := NewConnMap()

	config = &SlirpConfig{}
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug info")
	flag.IntVar(&config.MTU, "mtu", 1500, "Set MTU value")
	flag.BoolVar(&config.EnableIPv6, "ipv6", false, "Enable IPv6 support")
	flag.BoolVar(&config.EnableServers, "servers", false, "Enable server support (SOCKS5)")
	flag.IntVar(&config.Socks5Port, "socks5-port", 1080, "SOCKS5 proxy port")
	flag.Parse()

	infoPrintf("- guest network address: 10.0.2.15\r\n")
	infoPrintf("-      gateway address: 10.0.2.2\r\n")
	if config.EnableIPv6 {
		infoPrintf("- guest IPv6 address: fd00::15\r\n")
		infoPrintf("-   gateway IPv6 address: fd00::2\r\n")
	}
	infoPrintf("# run commands to config network:\r\n")
	infoPrintf("$ ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up\r\n")
	infoPrintf("$ route add default gw 10.0.2.2\r\n")
	if config.EnableIPv6 {
		infoPrintf("$ ip -6 addr add fd00::15/64 dev eth0\r\n")
		infoPrintf("$ ip -6 route add default via fd00::2\r\n")
	}

	// Start SOCKS5 server if enabled
	if config.EnableServers {
		var err error
		socks5Server, err = NewSocks5Server(config.Socks5Port, cm)
		if err != nil {
			infoPrintf("[E] Failed to start SOCKS5 server: %v\r\n", err)
		} else {
			infoPrintf("- SOCKS5 proxy started on port %d\r\n", config.Socks5Port)
		}
	}

	for {
		packet, err := readSLIPPacket(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			infoPrintf("[E] Error reading SLIP packet: %v\r\n", err)
			continue
		}

		if len(packet) == 0 {
			continue
		}

		debugPrintf("[I] Received packet of %d bytes\r\n", len(packet))

		debugPrintf("[D] packet\r\n")
		debugDumpPacket(packet)

		// Check if it's IPv6 packet
		if config.EnableIPv6 && isIPv6Packet(packet) {
			// Parse IPv6 header
			if len(packet) < 40 {
				debugPrintf("[E] Packet too small for IPv6 header\r\n")
				continue
			}

			ipv6Header := parseIPv6Header(packet)
			debugPrintf("[I] IPv6 packet: src=%v dst=%v next_header=%d\r\n",
				net.IP(ipv6Header.SrcIP[:]), net.IP(ipv6Header.DstIP[:]), ipv6Header.NextHeader)

			var response []byte
			if ipv6Header.NextHeader == PROTO_TCP { // TCP
				debugPrintf("[I] Sending TCPv6 response\r\n")
				go cm.ProcessTCPv6Connection(ipv6Header, packet)
				continue
			} else if ipv6Header.NextHeader == PROTO_UDP { // UDP
				debugPrintf("[I] Sending UDPv6 response\r\n")
				go cm.ProcessUDPv6Connection(ipv6Header, packet)
				continue
			} else if ipv6Header.NextHeader == PROTO_ICMPV6 { // ICMPv6
				debugPrintf("[I] Sending ICMPv6 response\r\n")
				response, err = processICMPv6Packet(ipv6Header, packet)
				if err != nil {
					infoPrintf("[E] IPv6 error: %s\r\n", err)
					continue
				}
				debugPrintf("[D] icmpv6 response packet\r\n")
				debugDumpPacket(response)
				encoded := encodeSLIP(response)
				go seqPrintPacket(encoded)
			} else {
				// Generate ICMPv6 Host Unreachable response
				debugPrintf("[I] Sending ICMPv6 Host Unreachable response\r\n")
				response = generateICMPv6HostUnreachable(ipv6Header, packet)
				debugPrintf("[D] response packet\r\n")
				debugDumpPacket(response)
				encoded := encodeSLIP(response)
				go seqPrintPacket(encoded)
			}
		} else {
			// Parse IPv4 header
			if len(packet) < 20 {
				debugPrintf("[E] Packet too small for IP header\r\n")
				continue
			}

			ipHeader := parseIPHeader(packet)
			debugPrintf("[I] IP packet: src=%v dst=%v proto=%d\r\n",
				ipHeader.SrcIP, ipHeader.DstIP, ipHeader.Protocol)

			var response []byte
			if ipHeader.Protocol == PROTO_TCP { // TCP
				debugPrintf("[I] Sending TCP response\r\n")
				go cm.ProcessTCPConnection(ipHeader, packet)
				continue
			} else if ipHeader.Protocol == PROTO_UDP { // UDP
				debugPrintf("[I] Sending UDP response\r\n")
				go cm.ProcessUDPConnection(ipHeader, packet)
				continue
			} else if ipHeader.Protocol == PROTO_ICMP { // ICMP
				debugPrintf("[I] Sending ICMP response\r\n")
				response, err = processICMPPacket(ipHeader, packet)
				if err != nil {
					infoPrintf("[E] error: %s\r\n", err)
					continue
				}
				debugPrintf("[D] icmp response packet\r\n")
				debugDumpPacket(response)
				encoded := encodeSLIP(response)
				go seqPrintPacket(encoded)
			} else {
				// Generate ICMP Host Unreachable response
				debugPrintf("[I] Sending ICMP Host Unreachable response\r\n")
				response = generateICMPHostUnreachable(ipHeader, packet)
				debugPrintf("[D] response packet\r\n")
				debugDumpPacket(response)
				// Encode and send response
				encoded := encodeSLIP(response)
				go seqPrintPacket(encoded)
			}
		}
	}
}
