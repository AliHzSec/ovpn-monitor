package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ovpnmonitor/internal/db"
	"ovpnmonitor/internal/model"
)

// visit is one seeded row of browsing history.
type visit struct {
	client, host, first, last string
	count                     int64
}

// seedVisits writes rows the way an older build did — hostname only, with no
// root_domain — then re-runs the migration so the backfill fills the column in.
// That puts the routes under test on the same data an upgraded panel would see.
func seedVisits(t *testing.T, database *db.DB, sqldb *sql.DB, rows []visit) {
	t.Helper()
	for _, r := range rows {
		if _, err := sqldb.Exec(
			`INSERT INTO visited_domains (client_name, domain, first_seen, last_seen, visit_count)
			 VALUES (?, ?, ?, ?, ?)`, r.client, r.host, r.first, r.last, r.count); err != nil {
			t.Fatalf("seed %s: %v", r.host, err)
		}
	}
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
}

func getJSON(t *testing.T, mux *http.ServeMux, cookie *http.Cookie, path string) []model.VisitedDomain {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (body %q)", path, rec.Code, rec.Body.String())
	}
	var out []model.VisitedDomain
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET %s: decode: %v (body %q)", path, err, rec.Body.String())
	}
	return out
}

// The two levels of the Visited Domains view must agree: the root list's
// rolled-up numbers have to match what the detail route returns for that root.
func TestVisitedDomainsRoutes(t *testing.T) {
	mux, database, sqldb, cookie, _ := newTestPanel(t)
	seedVisits(t, database, sqldb, []visit{
		{"alice", "firebaseremoteconfig.googleapis.com", "2026-01-02 09:00:00", "2026-01-05 18:00:00", 210},
		{"alice", "www.googleapis.com", "2026-01-01 08:00:00", "2026-01-04 12:00:00", 141},
		{"alice", "googleapis.com", "2026-01-03 10:00:00", "2026-01-06 20:00:00", 61},
		{"alice", "www.youtube.com", "2026-01-02 00:00:00", "2026-01-02 01:00:00", 5},
	})

	roots := getJSON(t, mux, cookie, "/api/clients/alice/domains")
	if len(roots) != 2 {
		t.Fatalf("root list has %d rows, want 2: %+v", len(roots), roots)
	}
	// The bug being fixed: this used to be a standalone row.
	for _, r := range roots {
		if strings.HasPrefix(r.Domain, "firebaseremoteconfig.") {
			t.Fatalf("subdomain %q leaked into the root list", r.Domain)
		}
	}
	if roots[0].Domain != "googleapis.com" || roots[0].VisitCount != 412 {
		t.Fatalf("roots[0] = %q/%d, want googleapis.com/412", roots[0].Domain, roots[0].VisitCount)
	}

	subs := getJSON(t, mux, cookie, "/api/clients/alice/domains/googleapis.com")
	if len(subs) != 3 {
		t.Fatalf("subdomain list has %d rows, want 3: %+v", len(subs), subs)
	}
	var sum int64
	for _, s := range subs {
		sum += s.VisitCount
	}
	if sum != roots[0].VisitCount {
		t.Errorf("subdomain visits sum to %d but the root row says %d", sum, roots[0].VisitCount)
	}
	if int64(len(subs)) != roots[0].SubdomainCount {
		t.Errorf("subdomain_count = %d but the detail route returned %d rows",
			roots[0].SubdomainCount, len(subs))
	}
}

// The domain detail route must serve the SPA (the React router reads the
// client name and root domain out of the URL) and stay behind the session
// cookie.
func TestDomainDetailPage(t *testing.T) {
	mux, database, sqldb, cookie, _ := newTestPanel(t)
	seedVisits(t, database, sqldb, []visit{
		{"alice", "firebaseremoteconfig.googleapis.com", "2026-01-02 09:00:00", "2026-01-05 18:00:00", 210},
	})

	req := httptest.NewRequest(http.MethodGet, "/panel/clients/alice/domains/googleapis.com", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("page = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `<div id="app">`) {
		t.Errorf("page did not serve the SPA (index.html)")
	}

	// Unauthenticated requests must not reach it.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/clients/alice/domains/googleapis.com", nil))
	if rec.Code == http.StatusOK {
		t.Errorf("page served without a session cookie")
	}
}

// A root the client never visited is an empty list, not an error, and the
// client detail route still works alongside the nested one.
func TestVisitedDomainsRoutesDoNotShadow(t *testing.T) {
	mux, database, sqldb, cookie, _ := newTestPanel(t)
	seedVisits(t, database, sqldb, []visit{
		{"alice", "www.youtube.com", "2026-01-02 00:00:00", "2026-01-02 01:00:00", 5},
	})

	if got := getJSON(t, mux, cookie, "/api/clients/alice/domains/example.org"); len(got) != 0 {
		t.Errorf("unvisited root returned %d rows, want 0", len(got))
	}

	req := httptest.NewRequest(http.MethodGet, "/panel/clients/alice", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<div id="app">`) {
		t.Errorf("client detail page broke: %d", rec.Code)
	}
}
