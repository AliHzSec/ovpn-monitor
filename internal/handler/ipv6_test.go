package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"ovpnmonitor/internal/auth"
	"ovpnmonitor/internal/db"
	"ovpnmonitor/internal/ipv6"
	"ovpnmonitor/internal/openvpn"
	"ovpnmonitor/internal/tracker"
	"ovpnmonitor/internal/wireguard"
)

const ipv6TestWGConf = `[Interface]
Address = 10.66.66.1/24
PostUp = ip6tables -I FORWARD -i wg0 -j ACCEPT
#PostUp = ip6tables -I FORWARD -i wg0 -j REJECT --reject-with icmp6-adm-prohibited
PostDown = ip6tables -D FORWARD -i wg0 -j ACCEPT
#PostDown = ip6tables -D FORWARD -i wg0 -j REJECT --reject-with icmp6-adm-prohibited
`

func newIPv6TestPanel(t *testing.T, confPath string) (*http.ServeMux, *http.Cookie) {
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
	sessions := auth.NewSessionStore(time.Hour)
	token := sessions.Create()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := ipv6.NewWireGuard(confPath, "wg-quick@wg0", "wg0", logger)
	svc.Restart = func(context.Context, string) error { return nil }

	mux := http.NewServeMux()
	Register(mux, Deps{
		DB: database, Sessions: sessions,
		OVPNOnline: &tracker.OnlineTracker{}, WGOnline: &tracker.OnlineTracker{},
		Certs: &openvpn.CertWhitelist{}, WGRegistry: &wireguard.Registry{},
		IPP:        &openvpn.IPPStore{},
		SessionTTL: time.Hour, Logger: logger,
		IPv6WG: svc,
	})
	return mux, &http.Cookie{Name: "session", Value: token}
}

func TestIPv6GetAndPut(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(confPath, []byte(ipv6TestWGConf), 0o600); err != nil {
		t.Fatal(err)
	}
	mux, cookie := newIPv6TestPanel(t, confPath)

	// GET reads the live file.
	req := httptest.NewRequest(http.MethodGet, "/api/settings/wireguard/ipv6", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rec.Code)
	}
	var got map[string]string
	json.NewDecoder(rec.Body).Decode(&got)
	if got["state"] != "enabled" {
		t.Errorf("GET state = %q, want enabled", got["state"])
	}

	// PUT flips the file and reports the new state.
	req = httptest.NewRequest(http.MethodPut, "/api/settings/wireguard/ipv6",
		strings.NewReader(`{"enabled": false}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var putGot map[string]interface{}
	json.NewDecoder(rec.Body).Decode(&putGot)
	if putGot["state"] != "disabled" {
		t.Errorf("PUT state = %q, want disabled", putGot["state"])
	}
	content, _ := os.ReadFile(confPath)
	if strings.Contains(string(content), "\nPostUp = ip6tables -I FORWARD -i wg0 -j ACCEPT") {
		t.Errorf("config still has an active ACCEPT line after disable:\n%s", content)
	}

	// Auth is required.
	req = httptest.NewRequest(http.MethodGet, "/api/settings/wireguard/ipv6", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("GET without a session must not succeed")
	}
}

func TestIPv6UnconfiguredServiceIs404(t *testing.T) {
	confPath := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(confPath, []byte(ipv6TestWGConf), 0o600); err != nil {
		t.Fatal(err)
	}
	mux, cookie := newIPv6TestPanel(t, confPath)

	// OpenVPN has no configured service in this panel.
	req := httptest.NewRequest(http.MethodGet, "/api/settings/openvpn/ipv6", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET for unconfigured service status = %d, want 404", rec.Code)
	}
}
