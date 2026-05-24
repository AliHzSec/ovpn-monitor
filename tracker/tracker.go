package tracker

import "sync"

type OnlineTracker struct {
	mu      sync.RWMutex
	clients map[string]bool
}

func (o *OnlineTracker) Set(clients map[string]bool) {
	o.mu.Lock()
	o.clients = clients
	o.mu.Unlock()
}

func (o *OnlineTracker) Get() map[string]bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	result := make(map[string]bool, len(o.clients))
	for k, v := range o.clients {
		result[k] = v
	}
	return result
}
