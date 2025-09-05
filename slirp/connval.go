package slirp

import (
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
	case ConnTypeTcpClient:
		// Use different timeouts based on connection state
		if cv.state != nil {
			switch cv.state.value {
			case TcpStateClosed, TcpStateFinWait1, TcpStateFinWait2, TcpStateClosing:
				timeoutT = 30 * time.Second // Shorter timeout for closing connections
			default:
				timeoutT = TCP_KEEPALIVE_TIME // Use keepalive time for established connections
			}
		} else {
			timeoutT = TCP_KEEPALIVE_TIME
		}
	case ConnTypeTcpServer:
		// Same logic for server connections
		if cv.state != nil {
			switch cv.state.value {
			case TcpStateClosed, TcpStateFinWait1, TcpStateFinWait2, TcpStateClosing:
				timeoutT = 30 * time.Second
			default:
				timeoutT = TCP_KEEPALIVE_TIME
			}
		} else {
			timeoutT = TCP_KEEPALIVE_TIME
		}
	case ConnTypeUdpClient:
		timeoutT = 30 * time.Second
	case ConnTypeUdpServer:
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
