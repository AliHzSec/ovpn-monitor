package handler

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"ovpnmonitor/internal/auth"
	"ovpnmonitor/internal/db"
	"ovpnmonitor/internal/openvpn"
	"ovpnmonitor/internal/tracker"
	"ovpnmonitor/internal/wireguard"
)

func newTestPanel(t *testing.T) (*http.ServeMux, *db.DB, *http.Cookie) {
	t.Helper()
	sqldb, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "t.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqldb.Close() })
	database := db.New(sqldb)
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	tmpl, err := LoadTemplates("../../templates")
	if err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewSessionStore(time.Hour)
	token := auth.GenerateToken()
	sessions.Set(token)

	mux := http.NewServeMux()
	Register(mux, Deps{
		DB: database, Sessions: sessions,
		OVPNOnline: &tracker.OnlineTracker{}, WGOnline: &tracker.OnlineTracker{},
		Certs: &openvpn.CertWhitelist{}, WGRegistry: &wireguard.Registry{},
		IPP: &openvpn.IPPStore{}, Templates: tmpl,
		SessionTTL: time.Hour, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		TemplatesDir: "../../templates",
	})
	return mux, database, &http.Cookie{Name: "session", Value: token}
}

// Saving one settings section must leave every other section's values intact.
// The form for a section only carries its own fields, so a handler that blindly
// wrote every known key would blank the rest — disabling whole subsystems.
func TestSavingOneSectionLeavesOthersIntact(t *testing.T) {
	mux, database, cookie := newTestPanel(t)

	before, _ := database.GetAllSettings(context.Background())

	form := url.Values{
		"wireguard_conf":              {"/etc/wireguard/wg1.conf"},
		"wireguard_interface":         {"wg1"},
		"wireguard_handshake_timeout": {"240s"},
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/wireguard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/settings/wireguard?saved=1" {
		t.Errorf("redirect = %q, want /settings/wireguard?saved=1", loc)
	}

	after, _ := database.GetAllSettings(context.Background())

	if after["wireguard_interface"] != "wg1" {
		t.Errorf("wireguard_interface = %q, want wg1", after["wireguard_interface"])
	}
	// Everything the WireGuard form did not carry must be byte-identical.
	for key, want := range before {
		if strings.HasPrefix(key, "wireguard_") {
			continue
		}
		if after[key] != want {
			t.Errorf("key %q was clobbered: %q -> %q", key, want, after[key])
		}
	}
}

// A section POST must not be able to write keys outside its own allow-list,
// even when the request body smuggles them in.
func TestSectionCannotWriteForeignKeys(t *testing.T) {
	mux, database, cookie := newTestPanel(t)

	form := url.Values{
		"wireguard_interface": {"wg1"},
		"openvpn_status_log":  {"/tmp/evil.log"}, // not owned by this section
		"addr":                {"0.0.0.0:9999"},  // would also trigger a restart
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/wireguard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	after, _ := database.GetAllSettings(context.Background())
	if after["openvpn_status_log"] != "/var/log/openvpn/status.log" {
		t.Errorf("foreign key written: openvpn_status_log = %q", after["openvpn_status_log"])
	}
	if after["addr"] != "0.0.0.0:80" {
		t.Errorf("foreign key written: addr = %q", after["addr"])
	}
	// addr is untouched, so no restart should have been signalled either.
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "restarting=1") {
		t.Errorf("unexpected restart signalled: %q", loc)
	}
}

// An empty password field means "keep the current password", never "clear it".
func TestEmptyPasswordKeepsExistingHash(t *testing.T) {
	mux, database, cookie := newTestPanel(t)
	before, _ := database.GetAllSettings(context.Background())

	form := url.Values{"addr": {"0.0.0.0:80"}, "admin_user": {"admin"}, "poll_interval": {"10s"}, "admin_pass": {""}}
	req := httptest.NewRequest(http.MethodPost, "/settings/general", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	mux.ServeHTTP(httptest.NewRecorder(), req)

	after, _ := database.GetAllSettings(context.Background())
	if after["admin_pass"] != before["admin_pass"] {
		t.Errorf("admin_pass changed on empty submit")
	}
}

// /settings redirects to the first section; unknown sections 404.
func TestSettingsRouting(t *testing.T) {
	mux, _, cookie := newTestPanel(t)

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/settings", http.StatusSeeOther},
		{"/settings/general", http.StatusOK},
		{"/settings/openvpn", http.StatusOK},
		{"/settings/wireguard", http.StatusOK},
		{"/settings/domains", http.StatusOK},
		{"/settings/nope", http.StatusNotFound},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("GET %s = %d, want %d", tc.path, rec.Code, tc.want)
		}
	}
}

// Settings pages stay behind auth after the route split.
func TestSettingsRequiresAuth(t *testing.T) {
	mux, _, _ := newTestPanel(t)
	for _, p := range []string{"/settings", "/settings/general", "/settings/wireguard"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if loc := rec.Header().Get("Location"); loc != "/panel/login" {
			t.Errorf("GET %s without session redirected to %q, want /panel/login", p, loc)
		}
	}
}

// A section that does not own admin_user must not be able to change the
// password — a password manager autofilling an unrelated page would otherwise
// silently rotate the admin credential.
func TestForeignSectionCannotChangePassword(t *testing.T) {
	mux, database, cookie := newTestPanel(t)
	before, _ := database.GetAllSettings(context.Background())

	form := url.Values{"wireguard_interface": {"wg1"}, "admin_pass": {"hunter2"}}
	req := httptest.NewRequest(http.MethodPost, "/settings/wireguard", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	mux.ServeHTTP(httptest.NewRecorder(), req)

	after, _ := database.GetAllSettings(context.Background())
	if after["admin_pass"] != before["admin_pass"] {
		t.Error("admin_pass changed from a section that does not own it")
	}
}

// The General section still applies a real password change, stored hashed.
func TestGeneralSectionChangesPassword(t *testing.T) {
	mux, database, cookie := newTestPanel(t)
	before, _ := database.GetAllSettings(context.Background())

	form := url.Values{"admin_user": {"admin"}, "admin_pass": {"a-new-password"}}
	req := httptest.NewRequest(http.MethodPost, "/settings/general", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	mux.ServeHTTP(httptest.NewRecorder(), req)

	after, _ := database.GetAllSettings(context.Background())
	if after["admin_pass"] == before["admin_pass"] {
		t.Fatal("admin_pass was not updated")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(after["admin_pass"]), []byte("a-new-password")); err != nil {
		t.Errorf("stored password is not a bcrypt hash of the new value: %v", err)
	}
}

// Changing the listening address from the section that owns it still signals a
// restart, so the existing behaviour is preserved.
func TestAddrChangeStillSignalsRestart(t *testing.T) {
	mux, _, cookie := newTestPanel(t)

	form := url.Values{"addr": {"127.0.0.1:8080"}, "admin_user": {"admin"}, "poll_interval": {"10s"}}
	req := httptest.NewRequest(http.MethodPost, "/settings/general", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); loc != "/settings/general?saved=1&restarting=1" {
		t.Errorf("redirect = %q, want the restarting flash", loc)
	}
	// NOTE: the handler schedules os.Exit(0) 500ms out. The test process must
	// finish this test well before then; nothing else here sleeps.
}
