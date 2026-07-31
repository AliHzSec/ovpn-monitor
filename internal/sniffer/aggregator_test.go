package sniffer

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// Mirrors the visited_domains schema created by the panel's db.Migrate,
	// which owns the table in production.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS visited_domains (
			id          INTEGER PRIMARY KEY,
			client_name TEXT NOT NULL,
			domain      TEXT NOT NULL,
			first_seen  TEXT NOT NULL,
			last_seen   TEXT NOT NULL,
			visit_count INTEGER NOT NULL DEFAULT 1 CHECK (visit_count >= 0),
			UNIQUE (client_name, domain)
		)`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func rowFor(t *testing.T, db *sql.DB, client, domain string) (first, last string, count int64) {
	t.Helper()
	err := db.QueryRow(`SELECT first_seen, last_seen, visit_count FROM visited_domains WHERE client_name=? AND domain=?`,
		client, domain).Scan(&first, &last, &count)
	if err != nil {
		t.Fatalf("row(%s,%s): %v", client, domain, err)
	}
	return
}

func TestAggregatorDedupAndFlush(t *testing.T) {
	db := testDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agg := NewAggregator(db, time.Minute, logger)

	base := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	agg.Observe("alice", "youtube.com", base)                     // count 1
	agg.Observe("alice", "youtube.com", base.Add(10*time.Second)) // within window -> no count, advances last
	agg.Observe("alice", "youtube.com", base.Add(2*time.Minute))  // outside window -> count 2

	agg.Flush(context.Background())

	first, last, count := rowFor(t, db, "alice", "youtube.com")
	if count != 2 {
		t.Errorf("visit_count = %d, want 2", count)
	}
	if first != "2026-01-02 15:04:05" {
		t.Errorf("first_seen = %q", first)
	}
	if last != "2026-01-02 15:06:05" {
		t.Errorf("last_seen = %q", last)
	}
}

func TestAggregatorAccumulatesAcrossFlushes(t *testing.T) {
	db := testDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	agg := NewAggregator(db, time.Nanosecond, logger) // effectively count every observation

	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	agg.Observe("bob", "github.com", base.Add(time.Hour))
	agg.Observe("bob", "github.com", base.Add(2*time.Hour))
	agg.Flush(context.Background())

	// A later flush must add to the existing row, keep the earliest first_seen,
	// and advance last_seen.
	agg.Observe("bob", "github.com", base) // earlier than stored first_seen
	agg.Observe("bob", "github.com", base.Add(5*time.Hour))
	agg.Flush(context.Background())

	first, last, count := rowFor(t, db, "bob", "github.com")
	if count != 4 {
		t.Errorf("visit_count = %d, want 4", count)
	}
	if first != "2026-03-01 00:00:00" {
		t.Errorf("first_seen = %q, want earliest", first)
	}
	if last != "2026-03-01 05:00:00" {
		t.Errorf("last_seen = %q, want latest", last)
	}
}

func TestAggregatorEmptyFlushNoop(t *testing.T) {
	db := testDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	NewAggregator(db, time.Minute, logger).Flush(context.Background()) // must not error/panic
}
