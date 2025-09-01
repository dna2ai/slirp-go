package slirp

import (
	"net"
	"time"
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
	switch cv.Type {
	case 100:
		timeoutT = 24 * 3600 * time.Second
	case 101:
		timeoutT = 24 * 3600 * time.Second
	case 200:
		timeoutT = 30 * time.Second
	case 201:
		timeoutT = 30 * time.Second
	}
	if (*now).Sub(cv.lastActivity) > timeoutT {
		return true
	}
	return false
}

func (cv *ConnVal) Close() {
	// TODO: send FIN, RST for tcp
	switch cv.Type {
	case 100:
		if cv.TCPcln != nil {
			cv.TCPcln.Close()
			cv.TCPcln = nil
		}
	case 101:
		if cv.TCPsrv != nil {
			cv.TCPsrv.Close()
			cv.TCPsrv = nil
		}
		if cv.TCPsrvConn != nil {
			cv.TCPsrvConn.Close()
			cv.TCPsrvConn = nil
		}
	case 200:
		if cv.UDPcln != nil {
			cv.UDPcln.Close()
			cv.UDPcln = nil
		}
	case 201:
		if cv.UDPsrv != nil {
			cv.UDPsrv.Close()
			cv.UDPsrv = nil
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
