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

// HistoryPoint is one averaged sample of overall network speed.
type HistoryPoint struct {
	Timestamp   int64  `json:"timestamp"`    // unix seconds, start of the sampled minute
	DownloadBps uint64 `json:"download_bps"` // average bytes/sec received during that minute
	UploadBps   uint64 `json:"upload_bps"`   // average bytes/sec sent during that minute
}

// historyRetention bounds the in-memory speed history to the last 24 hours
// (one averaged point per minute → at most 1440 points).
const historyRetention = 24 * time.Hour

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

	// 24h network speed history (per-minute averages) and today's peak speed.
	history     []HistoryPoint
	historyJSON []byte // pre-serialized history
	peakSpeed   uint64 // highest up/down speed seen on peakDay
	peakDay     string // local date (YYYY-MM-DD) the peak belongs to
	bucketStart int64  // unix seconds of the minute currently being accumulated
	bucketDown  uint64 // sum of down-speed samples in the current minute
	bucketUp    uint64 // sum of up-speed samples in the current minute
	bucketCount uint64 // number of samples in the current minute
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

// HistoryJSON returns the pre-serialized network speed history for the last
// 24 hours ("[]" until the first full minute has been sampled).
func (c *StatsCache) HistoryJSON() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.historyJSON == nil {
		return []byte("[]")
	}
	return c.historyJSON
}

// trackSpeed stamps today's peak speed onto stats and folds the sample into
// the per-minute history buffer.
func (c *StatsCache) trackSpeed(stats *SystemStats, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	day := now.Format("2006-01-02")
	if day != c.peakDay {
		c.peakDay = day
		c.peakSpeed = 0
	}
	if stats.NetDownSpeed > c.peakSpeed {
		c.peakSpeed = stats.NetDownSpeed
	}
	if stats.NetUpSpeed > c.peakSpeed {
		c.peakSpeed = stats.NetUpSpeed
	}
	stats.PeakSpeedToday = c.peakSpeed

	minute := now.Unix() / 60 * 60
	if c.bucketStart == 0 {
		c.bucketStart = minute
	}
	if minute != c.bucketStart {
		c.flushBucketLocked()
		c.bucketStart = minute
	}
	c.bucketDown += stats.NetDownSpeed
	c.bucketUp += stats.NetUpSpeed
	c.bucketCount++
}

// flushBucketLocked averages the accumulated minute into a HistoryPoint,
// drops points older than the retention window and re-serializes the history.
// Caller must hold c.mu.
func (c *StatsCache) flushBucketLocked() {
	if c.bucketCount == 0 {
		return
	}
	point := HistoryPoint{
		Timestamp:   c.bucketStart,
		DownloadBps: c.bucketDown / c.bucketCount,
		UploadBps:   c.bucketUp / c.bucketCount,
	}
	c.bucketDown, c.bucketUp, c.bucketCount = 0, 0, 0

	cutoff := point.Timestamp - int64(historyRetention/time.Second)
	trim := 0
	for trim < len(c.history) && c.history[trim].Timestamp < cutoff {
		trim++
	}
	if trim > 0 {
		c.history = append(c.history[:0], c.history[trim:]...)
	}
	c.history = append(c.history, point)

	if data, err := json.Marshal(c.history); err == nil {
		c.historyJSON = data
	}
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
			c.trackSpeed(stats, time.Now())
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
