package slirp

import (
	"time"
	"net"
)

func (cv *ConnVal) IsTimeout(now *time.Time) bool {
	if cv.disposed {
		return true
	}
	if now == nil {
		cur := time.Now()
		now = &cur
	}
	var timeoutT time.Duration
	switch(cv.Type) {
	case ConnTypeTcpClient: timeoutT = 24 * 3600 * time.Second
	case ConnTypeTcpServer: timeoutT = 24 * 3600 * time.Second
	case ConnTypeUdpClient: timeoutT = 30 * time.Second
	case ConnTypeUdpServer: timeoutT = 30 * time.Second
	}
	if (*now).Sub(cv.lastActivity) > timeoutT {
		return true
	}
	return false
}

func (cv *ConnVal) Close() {
	// TODO: send FIN, RST for tcp
	switch(cv.Type) {
	case ConnTypeTcpClient, ConnTypeTcpServer:
		if cv.TCPcln != nil {
			cv.TCPcln.Close()
			cv.TCPcln = nil
		}
	case ConnTypeUdpClient, ConnTypeUdpServer:
		if cv.UDPcln != nil {
			cv.UDPcln.Close()
			cv.UDPcln = nil
		}
	}
}

func (cv *ConnVal) handleUdpResponse(iphdr IPHeader, udphdr UDPHeader) {
	buffer := make([]byte, 65535)
	for {
		select {
		case <-cv.done:
			return
		default:
			// Read response
			cv.lock.Lock()
			cv.UDPcln.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := cv.UDPcln.Read(buffer)
			if err != nil {
				cv.lock.Unlock()
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				cv.Dispose()
				return
			}
			cv.lastActivity = time.Now()
			response := buffer[:n]
			debugPrintf("[D] UDP response\r\n")
			debugDumpPacket(response)

			// Construct response packet
			ret := GenerateIpUdpPacket(&iphdr, &udphdr, response)
			encoded := encodeSLIP(ret)
			go seqPrintPacket(encoded)
			cv.lock.Unlock()
		}
	}
}

func (cv *ConnVal) Dispose() {
	cv.lock.Lock()
	defer cv.lock.Unlock()
	if cv.disposed {
		return
	}
	cv.disposed = true
	close(cv.done)
	cv.Close()
}

