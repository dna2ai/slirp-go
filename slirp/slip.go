package slirp

import (
	"bufio"
)

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
