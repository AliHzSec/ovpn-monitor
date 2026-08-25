package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"ovpnmonitor/internal/auth"
	"ovpnmonitor/internal/openvpn"
	"ovpnmonitor/internal/tracker"
	"ovpnmonitor/internal/wireguard"
)

// sessionCookieOf extracts the session cookie from a response.
func sessionCookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" {
			return c
		}
	}
	t.Fatal("no session cookie in response")
	return nil
}

// GET /panel/login serves the embedded login SPA. It sets NO cookies — a
// session is only minted on a successful login POST.
func TestLoginPageServed(t *testing.T) {
	mux, _, _, _ := newTestPanel(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/login", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /panel/login = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("login page set cookies: %v", cookies)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("HTML page served with Cache-Control %q, want no-cache", cc)
	}
}

// A failed login answers 401 JSON (the SPA shows the error box).
func TestLoginPostContract(t *testing.T) {
	mux, _, _, _ := newTestPanel(t)

	form := url.Values{"username": {"admin"}, "password": {"definitely-wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/panel/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-creds login = %d, want 401 (body %q)", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("401 body is not JSON: %v (%q)", err, rec.Body.String())
	}
	if body["error"] != "Invalid username or password" {
		t.Errorf("error = %q, want %q", body["error"], "Invalid username or password")
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("failed login set cookies: %v", cookies)
	}
}

// A successful login rotates the session: any old session is deleted
// (fixation protection) and the response carries a brand-new authenticated
// session cookie.
func TestLoginSuccessRotatesSession(t *testing.T) {
	mux, database, _, old := newTestPanel(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveSetting(context.Background(), "admin_pass", string(hash)); err != nil {
		t.Fatal(err)
	}

	form := url.Values{"username": {"admin"}, "password": {"s3cret-pass"}}
	req := httptest.NewRequest(http.MethodPost, "/panel/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(old)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/panel" {
		t.Fatalf("good login = %d → %q, want 303 → /panel", rec.Code, rec.Header().Get("Location"))
	}
	authed := sessionCookieOf(t, rec)
	if authed.Value == old.Value {
		t.Error("session token was not rotated on login")
	}
	if !authed.HttpOnly {
		t.Error("authenticated session cookie must be HttpOnly")
	}

	// The old session is dead: it no longer authenticates anything.
	req = httptest.NewRequest(http.MethodGet, "/panel", nil)
	req.AddCookie(old)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/panel/login" {
		t.Errorf("old session after login = %d → %q, want 303 → /panel/login",
			rec.Code, rec.Header().Get("Location"))
	}

	// The new session serves the SPA.
	req = httptest.NewRequest(http.MethodGet, "/panel", nil)
	req.AddCookie(authed)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /panel with rotated session = %d, want 200", rec.Code)
	}
}

// API and WS routes answer 401 JSON when unauthenticated (the SPA's http
// layer redirects to the login page client-side); HTML page routes keep the
// classic 303.
func TestUnauthenticatedContracts(t *testing.T) {
	mux, _, _, _ := newTestPanel(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/server-stats", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/server-stats unauthenticated = %d, want 401", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "unauthorized" {
		t.Errorf("401 body = %q, want {\"error\":\"unauthorized\"}", rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("API 401 must not redirect, got Location %q", loc)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/panel/login" {
		t.Errorf("GET /panel unauthenticated = %d → %q, want 303 → /panel/login",
			rec.Code, rec.Header().Get("Location"))
	}
}

// Authenticated SPA routes — including client-side-only paths — all serve the
// embedded index.html, so refreshes and deep links work.
func TestSPAPagesServeIndex(t *testing.T) {
	mux, _, _, cookie := newTestPanel(t)

	for _, path := range []string{
		"/panel",
		"/panel/clients",
		"/panel/clients/anything",              // client detail, name resolved by the SPA
		"/panel/totally/unknown/deep/link",     // SPA fallback
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
			continue
		}
		if !strings.Contains(rec.Body.String(), `<div id="app">`) {
			t.Errorf("GET %s did not serve index.html", path)
		}
	}
}

// The client portal is IP-gated and sessionless: it is served with the
// window.OVPN_PORTAL bootstrap injected and sets no cookies at all.
func TestPortalServesBootstrap(t *testing.T) {
	_, database, _, _ := newTestPanel(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Rebuild the mux with a VPN subnet and a seeded ipp.txt so the portal
	// route actually resolves the visitor.
	ippPath := filepath.Join(t.TempDir(), "ipp.txt")
	if err := os.WriteFile(ippPath, []byte("alice,10.8.0.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ipp := &openvpn.IPPStore{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ipp.RefreshLoop(ctx, ippPath, database, logger)
	for deadline := time.Now().Add(2 * time.Second); ; {
		if m, _ := ipp.Get(); len(m) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ipp store did not load")
		}
		time.Sleep(5 * time.Millisecond)
	}

	_, vpnNet, err := net.ParseCIDR("10.8.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	Register(mux, Deps{
		DB: database, Sessions: auth.NewSessionStore(time.Hour),
		OVPNOnline: &tracker.OnlineTracker{}, WGOnline: &tracker.OnlineTracker{},
		Certs: &openvpn.CertWhitelist{}, WGRegistry: &wireguard.Registry{},
		IPP: ipp, VPNNet: vpnNet,
		SessionTTL: time.Hour, Logger: logger,
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.8.0.2:5555"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET / from VPN IP = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "window.OVPN_PORTAL") {
		t.Error("portal bootstrap was not injected")
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("portal set cookies: %v", cookies)
	}
}
