package slirp

import (
	"time"
)

func NewConnMap() *ConnMap {
	cm := &ConnMap{
		data: make(map[ConnKey]*ConnVal),
	}
	go cm.cleanup()
	return cm
}

func (cm *ConnMap) cleanup() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cm.mu.Lock()
		now := time.Now()
		for key, item := range cm.data {
			if item.IsTimeout(&now) {
				item.Dispose()
				delete(cm.data, key)
				debugPrintf("[D] Timeout connection: %+v\r\n", key)
			}
		}
		cm.mu.Unlock()
	}
}

