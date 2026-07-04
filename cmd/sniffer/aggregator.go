package main

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"
)

const tsLayout = "2006-01-02 15:04:05"

// aggKey identifies one (client, root-domain) bucket.
type aggKey struct {
	client string
	domain string
}

// aggEntry accumulates the pending delta for a bucket SINCE the last flush.
// first/last are the earliest/latest observation times in this window; count is
// the number of increments (already de-duplicated by the dedup window).
type aggEntry struct {
	first time.Time
	last  time.Time
	count int64
}

// Aggregator keeps a small in-memory map of pending (client, domain) deltas and
// batch-flushes them to SQLite, so there is at most one DB write per flush
// interval rather than one per packet. Storage in the DB is bounded to one row
// per (client, domain); the in-memory map is bounded the same way and is reset
// every flush.
type Aggregator struct {
	db          *sql.DB
	logger      *slog.Logger
	dedupWindow time.Duration

	mu      sync.Mutex
	pending map[aggKey]*aggEntry
	// lastCount holds, per bucket, the time of the most recent counted visit.
	// It survives flushes so the dedup window spans them, and is pruned of stale
	// entries on every flush to stay bounded.
	lastCount map[aggKey]time.Time
}

func NewAggregator(db *sql.DB, dedup time.Duration, logger *slog.Logger) *Aggregator {
	return &Aggregator{
		db:          db,
		logger:      logger,
		dedupWindow: dedup,
		pending:     map[aggKey]*aggEntry{},
		lastCount:   map[aggKey]time.Time{},
	}
}

// Observe records that client visited domain at time now. The visit count is
// only incremented when the previous counted visit for this bucket is older than
// the dedup window, so a burst of connections to the same domain doesn't inflate
// the counter; last_seen is always advanced.
func (a *Aggregator) Observe(client, domain string, now time.Time) {
	k := aggKey{client: client, domain: domain}
	a.mu.Lock()
	defer a.mu.Unlock()

	e := a.pending[k]
	if e == nil {
		e = &aggEntry{first: now, last: now}
		a.pending[k] = e
	}
	if now.Before(e.first) {
		e.first = now
	}
	if now.After(e.last) {
		e.last = now
	}

	prev, seen := a.lastCount[k]
	if !seen || now.Sub(prev) >= a.dedupWindow {
		e.count++
		a.lastCount[k] = now
	}
}

// FlushLoop flushes on a ticker until ctx is cancelled, then flushes once more so
// buffered observations aren't lost on shutdown.
func (a *Aggregator) FlushLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.Flush(ctx)
		case <-ctx.Done():
			// Final drain with a fresh short-lived context.
			fctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			a.Flush(fctx)
			cancel()
			return
		}
	}
}

// Flush upserts all pending deltas into visited_domains in a single transaction,
// then clears the pending map and prunes stale dedup entries.
func (a *Aggregator) Flush(ctx context.Context) {
	a.mu.Lock()
	snapshot := a.pending
	a.pending = map[aggKey]*aggEntry{}
	// Prune dedup markers older than the window — they can no longer suppress a
	// count, so keeping them only wastes memory.
	cutoff := time.Now().Add(-a.dedupWindow)
	for k, t := range a.lastCount {
		if t.Before(cutoff) {
			delete(a.lastCount, k)
		}
	}
	a.mu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		a.logger.Error("flush: begin tx", "err", err)
		a.requeue(snapshot)
		return
	}
	// visit_count adds the delta; last_seen/first_seen are widened via MAX/MIN
	// (lexicographic ordering is correct for the fixed "YYYY-MM-DD HH:MM:SS"
	// format). A brand-new bucket inserts its window's values directly.
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO visited_domains (client_name, domain, first_seen, last_seen, visit_count)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(client_name, domain) DO UPDATE SET
			visit_count = visit_count + excluded.visit_count,
			last_seen   = MAX(last_seen, excluded.last_seen),
			first_seen  = MIN(first_seen, excluded.first_seen)`)
	if err != nil {
		a.logger.Error("flush: prepare", "err", err)
		tx.Rollback()
		a.requeue(snapshot)
		return
	}

	n := 0
	for k, e := range snapshot {
		if _, err := stmt.ExecContext(ctx, k.client, k.domain,
			e.first.Format(tsLayout), e.last.Format(tsLayout), e.count); err != nil {
			a.logger.Error("flush: exec", "client", k.client, "domain", k.domain, "err", err)
			continue
		}
		n++
	}
	stmt.Close()
	if err := tx.Commit(); err != nil {
		a.logger.Error("flush: commit", "err", err)
		a.requeue(snapshot)
		return
	}
	a.logger.Info("flushed visited domains", "buckets", n)
}

// requeue merges a failed snapshot back into pending so its counts aren't lost
// and are retried on the next flush.
func (a *Aggregator) requeue(snapshot map[aggKey]*aggEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, e := range snapshot {
		cur := a.pending[k]
		if cur == nil {
			a.pending[k] = e
			continue
		}
		cur.count += e.count
		if e.first.Before(cur.first) {
			cur.first = e.first
		}
		if e.last.After(cur.last) {
			cur.last = e.last
		}
	}
}
