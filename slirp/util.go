package slirp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

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

func calculateSubChecksum(srcIP [4]byte, dstIP [4]byte, protocol uint8, data []byte) uint16 {
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP[:])
	copy(pseudoHeader[4:8], dstIP[:])
	pseudoHeader[8] = 0
	pseudoHeader[9] = protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(data)))
	return calculateChecksum(append(pseudoHeader, data...))
}

func getTcpStateName(state int) string {
	switch state {
	case TcpStateInit:
		return "INIT"
	case TcpStateSynReceived:
		return "SYN_RECEIVED"
	case TcpStateEstablished:
		return "ESTABLISHED"
	case TcpStateFinWait1:
		return "FIN_WAIT_1"
	case TcpStateFinWait2:
		return "FIN_WAIT_2"
	case TcpStateClosing:
		return "CLOSING"
	case TcpStateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

func debugDumpPacket(data []byte) {
	if config.Debug {
		dumpStr := strings.ReplaceAll(hex.Dump(data), "\n", "\r\n")
		fmt.Fprint(os.Stderr, dumpStr)
	}
}

func debugPrintf(format string, args ...interface{}) {
	if config.Debug {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

func infoPrintf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}

func seqPrintPacket(data []byte) {
	if writer == nil {
		// it may meet when program is closing
		return
	}
	printMutex.Lock()
	defer printMutex.Unlock()
	_, err := writer.Write(data)
	if err != nil {
		infoPrintf("[E] Error writing response: %v\r\n", err)
	} else {
		writer.Flush()
	}
}
