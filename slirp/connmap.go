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

func (cm *ConnMap) Pop(key *ConnKey) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	item, exists := cm.data[*key]
	if !exists {
		return false
	}
	item.Close()
	delete(cm.data, *key)
	return true
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
