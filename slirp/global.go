package slirp

import (
	"os"
	"sync"
	"bufio"
	"flag"
	"io"
)

var (
	printMutex sync.Mutex
	debugDumpMutex sync.Mutex
	reader *bufio.Reader
	writer *bufio.Writer
	config *SlirpConfig
)

func Run() {
	reader = bufio.NewReader(os.Stdin)
	writer = bufio.NewWriter(os.Stdout)
	cm := NewConnMap()

	config = &SlirpConfig{}
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug info")
	flag.IntVar(&config.MTU, "mtu", 1500, "Set MTU value")
	flag.Parse()

	infoPrintf("- guest network address: 10.0.2.15\r\n")
	infoPrintf("-      gateway address: 10.0.2.2\r\n")
	infoPrintf("# run commands to config network:\r\n")
	infoPrintf("$ ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up\r\n")
	infoPrintf("$ route add default gw 10.0.2.2\r\n")

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

		// Parse IP header
		if len(packet) < 20 {
			debugPrintf("[E] Packet too small for IP header\r\n")
			continue
		}

		debugPrintf("[D] packet\r\n")
		debugDumpPacket(packet)

		ipHeader := parseIPHeader(packet)
		debugPrintf("[I] IP packet: src=%v dst=%v proto=%d\r\n",
			ipHeader.SrcIP, ipHeader.DstIP, ipHeader.Protocol)

		var response []byte
		if (ipHeader.Protocol == 6) { // TCP
			debugPrintf("[I] Sending TCP response\r\n")
			go cm.ProcessTCPConnection(ipHeader, packet)
			continue
		} else if (ipHeader.Protocol == 17) { // UDP
			debugPrintf("[I] Sending UDP response\r\n")
			go cm.ProcessUDPConnection(ipHeader, packet)
			continue
		} else if (ipHeader.Protocol == 1) { // ICMP
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
