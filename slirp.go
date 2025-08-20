package main

import (
	"bufio"
	"encoding/binary"
	"net"
	"fmt"
	"io"
	"os"
	"sync"
	"encoding/hex"
	"strings"
	"time"
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
	ICMP_DEST_UNREACH = 3
	ICMP_HOST_UNREACH = 1

	UDP_HEADER_LEN = 8
	UDP_TIMEOUT = 30 * time.Second
	IP_HEADER_LEN = 20
)

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

// UDPHeader represents a UDP header
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	for {
		packet, err := readSLIPPacket(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Fprintf(os.Stderr, "[E] Error reading SLIP packet: %v\r\n", err)
			continue
		}

		if len(packet) == 0 {
			continue
		}

		fmt.Fprintf(os.Stderr, "[I] Received packet of %d bytes\r\n", len(packet))

		// Parse IP header
		if len(packet) < 20 {
			fmt.Fprintf(os.Stderr, "[E] Packet too small for IP header\r\n")
			continue
		}

		fmt.Fprintf(os.Stderr, "[D] packet\r\n")
		fmt.Fprintf(os.Stderr, strings.ReplaceAll(hex.Dump(packet), "\n", "\r\n"))

		ipHeader := parseIPHeader(packet)
		fmt.Fprintf(os.Stderr, "[I] IP packet: src=%v dst=%v proto=%d\r\n",
			ipHeader.SrcIP, ipHeader.DstIP, ipHeader.Protocol)

		var response []byte
		if (ipHeader.Protocol == 17) { // UDP
			// TODO: using go to handle multiple responses
			fmt.Fprintf(os.Stderr, "[I] Sending UDP response\r\n")
			response, _ = processUdpPacket(&ipHeader, packet)
		} else {
			// Generate ICMP Host Unreachable response
			fmt.Fprintf(os.Stderr, "[I] Sending ICMP Host Unreachable response\r\n")
			response = generateICMPHostUnreachable(ipHeader, packet)
		}

		fmt.Fprintf(os.Stderr, "[D] response packet\r\n")
		fmt.Fprintf(os.Stderr, strings.ReplaceAll(hex.Dump(response), "\n", "\r\n"))
		// Encode and send response
		encoded := encodeSLIP(response)
		_, err = writer.Write(encoded)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[E] Error writing response: %v\r\n", err)
			continue
		}
		writer.Flush()

		fmt.Fprintf(os.Stderr, "^ ==========\r\n")
	}
}

func readSLIPPacket(reader *bufio.Reader) ([]byte, error) {
	var packet []byte
	escaped := false

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}

		if escaped {
			switch b {
			case SLIP_ESC_END:
				packet = append(packet, SLIP_END)
			case SLIP_ESC_ESC:
				packet = append(packet, SLIP_ESC)
			default:
				// Invalid escape sequence, but continue
				packet = append(packet, b)
			}
			escaped = false
		} else {
			switch b {
			case SLIP_END:
				if len(packet) > 0 {
					return packet, nil
				}
				// Empty packet, continue reading
			case SLIP_ESC:
				escaped = true
			default:
				packet = append(packet, b)
			}
		}
	}
}

func encodeSLIP(data []byte) []byte {
	var encoded []byte

	// Start with END byte
	encoded = append(encoded, SLIP_END)

	for _, b := range data {
		switch b {
		case SLIP_END:
			encoded = append(encoded, SLIP_ESC, SLIP_ESC_END)
		case SLIP_ESC:
			encoded = append(encoded, SLIP_ESC, SLIP_ESC_ESC)
		default:
			encoded = append(encoded, b)
		}
	}

	// End with END byte
	encoded = append(encoded, SLIP_END)
	return encoded
}

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

func parseUdpHeader(packet []byte) (UDPHeader, []byte) {
	var header UDPHeader
	header.SrcPort = 0
	header.DstPort = 0
	if packet[9] != 17 {
		return header, nil
	}
	i := int(packet[0] & 0x0f) * 4
	header.SrcPort = binary.BigEndian.Uint16(packet[i:i+2])
	header.DstPort = binary.BigEndian.Uint16(packet[i+2:i+4])
	header.Length = binary.BigEndian.Uint16(packet[i+4:i+6])
	header.Checksum = binary.BigEndian.Uint16(packet[i+6:i+8])
	return header, packet[i+8:]
}

func generateICMPHostUnreachable(origIP IPHeader, origPacket []byte) []byte {
	// Create new IP header (swap src/dst)
	ipHeaderLen := 20
	icmpLen := 8 + 20 + 8 // ICMP header + IP header + 8 bytes of original data
	totalLen := ipHeaderLen + icmpLen

	response := make([]byte, totalLen)

	// IP Header
	response[0] = 0x45 // Version 4, Header length 5 (20 bytes)
	response[1] = 0    // TOS
	binary.BigEndian.PutUint16(response[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(response[4:6], 0) // ID
	binary.BigEndian.PutUint16(response[6:8], 0) // Flags and Fragment offset
	response[8] = 64                              // TTL
	response[9] = PROTO_ICMP                      // Protocol
	// Checksum calculated later
	copy(response[12:16], origIP.DstIP[:]) // Src IP (our IP is original dst)
	copy(response[16:20], origIP.SrcIP[:]) // Dst IP

	// Calculate IP checksum
	ipChecksum := calculateChecksum(response[:20])
	binary.BigEndian.PutUint16(response[10:12], ipChecksum)

	// ICMP Header
	icmpStart := 20
	response[icmpStart] = ICMP_DEST_UNREACH   // Type
	response[icmpStart+1] = ICMP_HOST_UNREACH // Code
	// Checksum calculated later
	binary.BigEndian.PutUint32(response[icmpStart+4:icmpStart+8], 0) // Unused

	// Copy original IP header + first 8 bytes of data
	copyLen := 28 // IP header (20) + 8 bytes
	if len(origPacket) < copyLen {
		copyLen = len(origPacket)
	}
	copy(response[icmpStart+8:], origPacket[:copyLen])

	// Calculate ICMP checksum
	icmpChecksum := calculateChecksum(response[icmpStart:])
	binary.BigEndian.PutUint16(response[icmpStart+2:icmpStart+4], icmpChecksum)

	return response
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32

	// Add each 16-bit word
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}

	// Add left-over byte, if any
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Add carry bits
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// One's complement
	return uint16(^sum)
}

func processUdpPacket(iphdr *IPHeader, packet []byte) ([]byte, error) {
	// Parse the input packet
	udphdr, payload := parseUdpHeader(packet)
	fmt.Fprintf(os.Stderr, "[I] Forwarding UDP packet to %s:%d\r\n", net.IP(iphdr.DstIP[:]), udphdr.DstPort)

	// Forward the UDP packet
	response, err := forwardUDP(iphdr.DstIP, udphdr.DstPort, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to forward UDP: %v", err)
	}
	fmt.Fprintf(os.Stderr, "[D] UDP response\r\n")
	fmt.Fprintf(os.Stderr, strings.ReplaceAll(hex.Dump(response), "\n", "\r\n"))

	// Construct response packet
	ret := GenerateIpUdpPacket(iphdr, &udphdr, response)
	//debugPrintDNSResponseInfo(ret)

	return ret, nil
}

func forwardUDP(dstIP [4]byte, dstPort uint16, payload []byte) ([]byte, error) {
	// Create UDP address
	addr := &net.UDPAddr{
		IP:   net.IP(dstIP[:]),
		Port: int(dstPort),
	}

	// Create UDP connection
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP: %v", err)
	}
	defer conn.Close()

	// Set timeout
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Send payload
	_, err = conn.Write(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to send UDP: %v", err)
	}

	// Read response
	buffer := make([]byte, 65535)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read UDP response: %v", err)
	}

	return buffer[:n], nil
}

func GenerateIpUdpPacket(origIPHeader *IPHeader, origUDPHeader *UDPHeader, responsePayload []byte) []byte {
	// Calculate lengths
	udpLength := UDP_HEADER_LEN + len(responsePayload)
	ipHeaderLen := IP_HEADER_LEN // Standard IP header without options
	totalLength := ipHeaderLen + udpLength

	// Create packet buffer
	packet := make([]byte, totalLength)

	// Build IP header (swap source and destination)
	packet[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	packet[1] = 0    // TOS
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLength))
	binary.BigEndian.PutUint16(packet[4:6], origIPHeader.ID+1) // Increment ID
	binary.BigEndian.PutUint16(packet[6:8], 0)                 // No flags, no fragment
	packet[8] = 64                                              // TTL
	packet[9] = 17                                              // UDP protocol
	// Checksum will be calculated later
	copy(packet[12:16], origIPHeader.DstIP[:]) // Swap: original dst becomes src
	copy(packet[16:20], origIPHeader.SrcIP[:]) // Swap: original src becomes dst

	// Build UDP header (swap ports)
	udpStart := ipHeaderLen
	binary.BigEndian.PutUint16(packet[udpStart:udpStart+2], origUDPHeader.DstPort)   // Swap ports
	binary.BigEndian.PutUint16(packet[udpStart+2:udpStart+4], origUDPHeader.SrcPort) // Swap ports
	binary.BigEndian.PutUint16(packet[udpStart+4:udpStart+6], uint16(udpLength))
	// UDP checksum will be calculated later

	// Copy payload
	copy(packet[udpStart+UDP_HEADER_LEN:], responsePayload)

	// Calculate UDP checksum
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], origIPHeader.DstIP[:])
	copy(pseudoHeader[4:8], origIPHeader.SrcIP[:])
	pseudoHeader[8] = 0
	pseudoHeader[9] = 17
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(udpLength))
	udpChecksum := calculateChecksum(append(pseudoHeader, packet[udpStart:]...))
	binary.BigEndian.PutUint16(packet[udpStart+6:udpStart+8], udpChecksum)
	// Calculate IP checksum
	ipChecksum := calculateChecksum(packet[:ipHeaderLen])
	binary.BigEndian.PutUint16(packet[10:12], ipChecksum)

	return packet
}

// UDP manager


// ############################ dns debug
func debugPrintDNSResponseInfo(packet []byte) error {
    // Minimum IP header size
    if len(packet) < 20 {
        return fmt.Errorf("packet too small for IP header")
    }

    // Parse IP header
    version := packet[0] >> 4
    if version != 4 {
        return fmt.Errorf("only IPv4 supported, got version %d", version)
    }

    ihl := int(packet[0]&0x0F) * 4
    if len(packet) < ihl {
        return fmt.Errorf("packet too small for IP header length %d", ihl)
    }

    protocol := packet[9]
    if protocol != 17 { // UDP
        return fmt.Errorf("expected UDP protocol (17), got %d", protocol)
    }

    srcIP := net.IPv4(packet[12], packet[13], packet[14], packet[15])
    dstIP := net.IPv4(packet[16], packet[17], packet[18], packet[19])

    // Parse UDP header
    udpStart := ihl
    if len(packet) < udpStart+8 {
        return fmt.Errorf("packet too small for UDP header")
    }

    srcPort := binary.BigEndian.Uint16(packet[udpStart : udpStart+2])
    dstPort := binary.BigEndian.Uint16(packet[udpStart+2 : udpStart+4])
    udpLength := binary.BigEndian.Uint16(packet[udpStart+4 : udpStart+6])

    // Parse DNS header
    dnsStart := udpStart + 8
    if len(packet) < dnsStart+12 {
        return fmt.Errorf("packet too small for DNS header")
    }

    transactionID := binary.BigEndian.Uint16(packet[dnsStart : dnsStart+2])
    flags := binary.BigEndian.Uint16(packet[dnsStart+2 : dnsStart+4])

    // Extract flag bits
    qr := (flags >> 15) & 1
    opcode := (flags >> 11) & 0xF
    aa := (flags >> 10) & 1
    tc := (flags >> 9) & 1
    rd := (flags >> 8) & 1
    ra := (flags >> 7) & 1
    rcode := flags & 0xF

    qdCount := binary.BigEndian.Uint16(packet[dnsStart+4 : dnsStart+6])
    anCount := binary.BigEndian.Uint16(packet[dnsStart+6 : dnsStart+8])
    nsCount := binary.BigEndian.Uint16(packet[dnsStart+8 : dnsStart+10])
    arCount := binary.BigEndian.Uint16(packet[dnsStart+10 : dnsStart+12])

    // Print to stderr
    fmt.Fprintf(os.Stderr, "=== DNS Response Info ===\r\n")
    fmt.Fprintf(os.Stderr, "IP: %s:%d -> %s:%d\r\n", srcIP, srcPort, dstIP, dstPort)
    fmt.Fprintf(os.Stderr, "UDP Length: %d bytes\r\n", udpLength)
    fmt.Fprintf(os.Stderr, "\r\nDNS Header:\r\n")
    fmt.Fprintf(os.Stderr, "  Transaction ID: 0x%04X\r\n", transactionID)
    fmt.Fprintf(os.Stderr, "  Flags: 0x%04X\r\n", flags)
    fmt.Fprintf(os.Stderr, "    QR: %d (Response)\r\n", qr)
    fmt.Fprintf(os.Stderr, "    Opcode: %d\r\n", opcode)
    fmt.Fprintf(os.Stderr, "    AA: %d\r\n", aa)
    fmt.Fprintf(os.Stderr, "    TC: %d\r\n", tc)
    fmt.Fprintf(os.Stderr, "    RD: %d\r\n", rd)
    fmt.Fprintf(os.Stderr, "    RA: %d\r\n", ra)
    fmt.Fprintf(os.Stderr, "    RCODE: %d (%s)\r\n", rcode, getRcodeName(rcode))
    fmt.Fprintf(os.Stderr, "  Questions: %d\r\n", qdCount)
    fmt.Fprintf(os.Stderr, "  Answers: %d\r\n", anCount)
    fmt.Fprintf(os.Stderr, "  Authority: %d\r\n", nsCount)
    fmt.Fprintf(os.Stderr, "  Additional: %d\r\n", arCount)

    // Parse questions and answers if space permits
    offset := dnsStart + 12

    // Parse questions
    if qdCount > 0 {
        fmt.Fprintf(os.Stderr, "\r\nQuestions:\r\n")
        for i := 0; i < int(qdCount) && offset < len(packet); i++ {
            name, newOffset := parseDomainName(packet, offset)
            if newOffset <= offset || newOffset+4 > len(packet) {
                break
            }
            qtype := binary.BigEndian.Uint16(packet[newOffset : newOffset+2])
            qclass := binary.BigEndian.Uint16(packet[newOffset+2 : newOffset+4])
            fmt.Fprintf(os.Stderr, "  %s (Type: %s, Class: %d)\r\n", name, getTypeName(qtype), qclass)
            offset = newOffset + 4
        }
    }

    // Parse answers
    if anCount > 0 {
        fmt.Fprintf(os.Stderr, "\r\nAnswers:\r\n")
        for i := 0; i < int(anCount) && offset < len(packet); i++ {
            name, newOffset := parseDomainName(packet, offset)
            if newOffset <= offset || newOffset+10 > len(packet) {
                break
            }

            rtype := binary.BigEndian.Uint16(packet[newOffset : newOffset+2])
            rclass := binary.BigEndian.Uint16(packet[newOffset+2 : newOffset+4])
            ttl := binary.BigEndian.Uint32(packet[newOffset+4 : newOffset+8])
            rdLength := binary.BigEndian.Uint16(packet[newOffset+8 : newOffset+10])

            fmt.Fprintf(os.Stderr, "  %s: Type=%s, Class=%d, TTL=%d", name, getTypeName(rtype), rclass, ttl)

            rdataStart := newOffset + 10
            if rdataStart+int(rdLength) <= len(packet) {
                if rtype == 1 && rdLength == 4 { // A record
                    ip := net.IPv4(packet[rdataStart], packet[rdataStart+1], packet[rdataStart+2], packet[rdataStart+3])
                    fmt.Fprintf(os.Stderr, ", Data=%s", ip)
                } else if rtype == 5 { // CNAME
                    cname, _ := parseDomainName(packet, rdataStart)
                    fmt.Fprintf(os.Stderr, ", Data=%s", cname)
                }
            }
            fmt.Fprintf(os.Stderr, "\r\n")

            offset = rdataStart + int(rdLength)
        }
    }

    fmt.Fprintf(os.Stderr, "========================\r\n")
    return nil
}

// parseDomainName parses a DNS domain name starting at offset
func parseDomainName(packet []byte, offset int) (string, int) {
    var name string
    origOffset := offset
    jumped := false

    for offset < len(packet) {
        length := int(packet[offset])

        if length == 0 {
            offset++
            break
        }

        // Check for compression pointer
        if length&0xC0 == 0xC0 {
            if offset+1 >= len(packet) {
                break
            }
            pointer := int(binary.BigEndian.Uint16(packet[offset:offset+2]) & 0x3FFF)
            if !jumped {
                origOffset = offset + 2
            }
            offset = pointer
            jumped = true
            continue
        }

        if offset+1+length > len(packet) {
            break
        }

        if name != "" {
            name += "."
        }
        name += string(packet[offset+1 : offset+1+length])
        offset += 1 + length
    }

    if jumped {
        return name, origOffset
    }
    return name, offset
}

// getTypeName returns the name of a DNS record type
func getTypeName(t uint16) string {
    switch t {
    case 1:
        return "A"
    case 2:
        return "NS"
    case 5:
        return "CNAME"
    case 6:
        return "SOA"
    case 12:
        return "PTR"
    case 15:
        return "MX"
    case 16:
        return "TXT"
    case 28:
        return "AAAA"
    default:
        return fmt.Sprintf("%d", t)
    }
}

// getRcodeName returns the name of a DNS response code
func getRcodeName(code uint16) string {
    switch code {
    case 0:
        return "No Error"
    case 1:
        return "Format Error"
    case 2:
        return "Server Failure"
    case 3:
        return "Name Error"
    case 4:
        return "Not Implemented"
    case 5:
        return "Refused"
    default:
        return "Unknown"
    }
}
