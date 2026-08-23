package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// legacyDB builds a database whose visited_domains table predates the
// root_domain column, so Migrate has to add and backfill it.
func legacyDB(t *testing.T) *DB {
	t.Helper()
	sqldb, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqldb.Close() })
	if _, err := sqldb.Exec(`
		CREATE TABLE visited_domains (
			id          INTEGER PRIMARY KEY,
			client_name TEXT NOT NULL,
			domain      TEXT NOT NULL,
			first_seen  TEXT NOT NULL,
			last_seen   TEXT NOT NULL,
			visit_count INTEGER NOT NULL DEFAULT 1 CHECK (visit_count >= 0),
			UNIQUE (client_name, domain)
		)`); err != nil {
		t.Fatal(err)
	}
	return New(sqldb)
}

func migrated(t *testing.T, d *DB) {
	t.Helper()
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
}

func insertVisit(t *testing.T, d *DB, client, host, first, last string, count int64) {
	t.Helper()
	_, err := d.db.Exec(
		`INSERT INTO visited_domains (client_name, domain, first_seen, last_seen, visit_count)
		 VALUES (?, ?, ?, ?, ?)`, client, host, first, last, count)
	if err != nil {
		t.Fatalf("insert %s: %v", host, err)
	}
}

// The migration must add root_domain and fill it in for existing rows, and it
// must repair the rows the old private-suffix-aware detection left standing
// alone: firebaseremoteconfig.googleapis.com now groups under googleapis.com.
func TestMigrateBackfillsRootDomain(t *testing.T) {
	d := legacyDB(t)
	insertVisit(t, d, "alice", "firebaseremoteconfig.googleapis.com", "2026-01-01 00:00:00", "2026-01-01 00:00:00", 1)
	insertVisit(t, d, "alice", "youtube.com", "2026-01-01 00:00:00", "2026-01-01 00:00:00", 1)
	insertVisit(t, d, "alice", "bbc.co.uk", "2026-01-01 00:00:00", "2026-01-01 00:00:00", 1)
	// A value Root cannot resolve must still group under itself, not vanish.
	insertVisit(t, d, "alice", "10.0.0.9", "2026-01-01 00:00:00", "2026-01-01 00:00:00", 1)

	migrated(t, d)

	want := map[string]string{
		"firebaseremoteconfig.googleapis.com": "googleapis.com",
		"youtube.com":                         "youtube.com",
		"bbc.co.uk":                           "bbc.co.uk",
		"10.0.0.9":                            "10.0.0.9",
	}
	for host, wantRoot := range want {
		var got string
		if err := d.db.QueryRow(
			`SELECT root_domain FROM visited_domains WHERE domain = ?`, host).Scan(&got); err != nil {
			t.Fatalf("read %s: %v", host, err)
		}
		if got != wantRoot {
			t.Errorf("root_domain of %q = %q, want %q", host, got, wantRoot)
		}
	}
}

// Running Migrate twice must not fail on the already-present column, and must
// not re-write rows that already carry a root.
func TestMigrateIsIdempotent(t *testing.T) {
	d := legacyDB(t)
	insertVisit(t, d, "alice", "www.example.com", "2026-01-01 00:00:00", "2026-01-01 00:00:00", 1)
	migrated(t, d)
	migrated(t, d)

	var root string
	if err := d.db.QueryRow(`SELECT root_domain FROM visited_domains`).Scan(&root); err != nil {
		t.Fatal(err)
	}
	if root != "example.com" {
		t.Errorf("root_domain = %q, want example.com", root)
	}
}

func TestQueryVisitedRootDomainsAggregates(t *testing.T) {
	d := legacyDB(t)
	// Three hostnames under googleapis.com, spanning a wide time range.
	insertVisit(t, d, "alice", "firebaseremoteconfig.googleapis.com", "2026-01-02 09:00:00", "2026-01-05 18:00:00", 210)
	insertVisit(t, d, "alice", "www.googleapis.com", "2026-01-01 08:00:00", "2026-01-04 12:00:00", 141)
	insertVisit(t, d, "alice", "googleapis.com", "2026-01-03 10:00:00", "2026-01-06 20:00:00", 61)
	// A second site, and one belonging to a different client.
	insertVisit(t, d, "alice", "www.youtube.com", "2026-01-02 00:00:00", "2026-01-02 01:00:00", 5)
	insertVisit(t, d, "bob", "www.googleapis.com", "2026-01-01 00:00:00", "2026-01-01 00:00:00", 999)
	migrated(t, d)

	rows, err := d.QueryVisitedRootDomains(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d root domains, want 2: %+v", len(rows), rows)
	}
	// Ordered by most recent activity first.
	if rows[0].Domain != "googleapis.com" || rows[1].Domain != "youtube.com" {
		t.Fatalf("order = %q, %q; want googleapis.com, youtube.com", rows[0].Domain, rows[1].Domain)
	}

	g := rows[0]
	if g.VisitCount != 412 { // 210 + 141 + 61, alice's rows only
		t.Errorf("visit_count = %d, want 412", g.VisitCount)
	}
	if g.FirstSeen != "2026-01-01 08:00:00" {
		t.Errorf("first_seen = %q, want the earliest across subdomains", g.FirstSeen)
	}
	if g.LastSeen != "2026-01-06 20:00:00" {
		t.Errorf("last_seen = %q, want the latest across subdomains", g.LastSeen)
	}
	if g.SubdomainCount != 3 {
		t.Errorf("subdomain_count = %d, want 3", g.SubdomainCount)
	}
	if g.FirstSeenEpoch == 0 || g.LastSeenEpoch == 0 {
		t.Errorf("epochs not populated: %d, %d", g.FirstSeenEpoch, g.LastSeenEpoch)
	}
	// The search blob must carry every hostname folded into the row, so the
	// client page can match a subdomain the collapsed row never displays.
	for _, host := range []string{"firebaseremoteconfig.googleapis.com", "www.googleapis.com", "googleapis.com"} {
		if !strings.Contains(g.Hostnames, host) {
			t.Errorf("hostnames %q missing %q", g.Hostnames, host)
		}
	}
}

func TestQueryVisitedSubdomains(t *testing.T) {
	d := legacyDB(t)
	insertVisit(t, d, "alice", "firebaseremoteconfig.googleapis.com", "2026-01-02 09:00:00", "2026-01-05 18:00:00", 210)
	insertVisit(t, d, "alice", "googleapis.com", "2026-01-03 10:00:00", "2026-01-06 20:00:00", 61)
	insertVisit(t, d, "alice", "www.youtube.com", "2026-01-02 00:00:00", "2026-01-02 01:00:00", 5)
	insertVisit(t, d, "bob", "www.googleapis.com", "2026-01-01 00:00:00", "2026-01-01 00:00:00", 999)
	migrated(t, d)

	rows, err := d.QueryVisitedSubdomains(context.Background(), "alice", "googleapis.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(rows), rows)
	}
	// Newest activity first; the root itself is included as a row of its own.
	if rows[0].Domain != "googleapis.com" || rows[0].VisitCount != 61 {
		t.Errorf("rows[0] = %q/%d, want googleapis.com/61", rows[0].Domain, rows[0].VisitCount)
	}
	if rows[1].Domain != "firebaseremoteconfig.googleapis.com" || rows[1].VisitCount != 210 {
		t.Errorf("rows[1] = %q/%d, want firebaseremoteconfig.googleapis.com/210", rows[1].Domain, rows[1].VisitCount)
	}

	// A root the client never visited yields an empty list, not an error.
	none, err := d.QueryVisitedSubdomains(context.Background(), "alice", "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Errorf("got %d rows for an unvisited root, want 0", len(none))
	}
}
