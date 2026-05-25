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

// TrafficQuerier fetches the all-time sum of VPN client traffic from persistent storage.
// Returning (0, 0, nil) is valid when no sessions exist yet.
type TrafficQuerier func(ctx context.Context) (sent, recv uint64, err error)

// ClientCountQuerier fetches current online and total registered VPN client counts.
type ClientCountQuerier func(ctx context.Context) (online, total int, err error)

// StatsCache collects system stats on a background loop and distributes them to subscribers.
type StatsCache struct {
	mu               sync.RWMutex
	stats            *SystemStats
	data             []byte // pre-serialized JSON
	hub              *broadcastHub
	queryTraffic     TrafficQuerier
	queryClientCount ClientCountQuerier
}

// NewStatsCache creates an empty cache. queryTraffic and queryClientCount are called on every
// collection cycle to merge external data into the snapshot; either may be nil to omit.
func NewStatsCache(queryTraffic TrafficQuerier, queryClientCount ClientCountQuerier) *StatsCache {
	return &StatsCache{hub: newBroadcastHub(), queryTraffic: queryTraffic, queryClientCount: queryClientCount}
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
			if c.queryTraffic != nil {
				dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				if sent, recv, qErr := c.queryTraffic(dbCtx); qErr == nil {
					stats.VPNTotalSent = sent
					stats.VPNTotalRecv = recv
				}
				cancel()
			}
			if c.queryClientCount != nil {
				dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				if online, total, qErr := c.queryClientCount(dbCtx); qErr == nil {
					stats.ClientOnline = online
					stats.ClientTotal = total
				}
				cancel()
			}
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
