package sysinfo

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

type broadcastHub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func newBroadcastHub() *broadcastHub {
	return &broadcastHub{clients: make(map[chan []byte]struct{})}
}

func (h *broadcastHub) subscribe() chan []byte {
	ch := make(chan []byte, 1)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *broadcastHub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

func (h *broadcastHub) broadcast(data []byte) {
	h.mu.Lock()
	for ch := range h.clients {
		select {
		case ch <- data:
		default:
		}
	}
	h.mu.Unlock()
}

// StatsCache collects system stats on a background loop and distributes them to subscribers.
type StatsCache struct {
	mu    sync.RWMutex
	stats *SystemStats
	data  []byte // pre-serialized JSON
	hub   *broadcastHub
}

func NewStatsCache() *StatsCache {
	return &StatsCache{hub: newBroadcastHub()}
}

// Get returns the latest cached stats and their pre-serialized JSON (both nil until first collection).
func (c *StatsCache) Get() (*SystemStats, []byte) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats, c.data
}

// Subscribe returns a channel that receives pre-serialized JSON on each stats update.
func (c *StatsCache) Subscribe() chan []byte {
	return c.hub.subscribe()
}

// Unsubscribe removes the channel returned by Subscribe.
func (c *StatsCache) Unsubscribe(ch chan []byte) {
	c.hub.unsubscribe(ch)
}

// Run collects stats in a loop until ctx is cancelled.
// Each iteration takes ~2s (Collect blocks ~1s + 1s sleep).
func (c *StatsCache) Run(ctx context.Context) {
	for {
		stats, err := Collect() // blocks ~1s
		if err == nil {
			if data, jsonErr := json.Marshal(stats); jsonErr == nil {
				c.mu.Lock()
				c.stats = stats
				c.data = data
				c.mu.Unlock()
				c.hub.broadcast(data)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
