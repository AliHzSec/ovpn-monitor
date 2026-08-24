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
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"ovpnmonitor/internal/auth"
	"ovpnmonitor/internal/openvpn"
	"ovpnmonitor/internal/tracker"
	"ovpnmonitor/internal/wireguard"
)

// csrfMetaRe extracts the injected token from a served HTML page.
var csrfMetaRe = regexp.MustCompile(`<meta name="csrf-token" content="([0-9a-f]{64})" />`)

// assertNoCSRFCookie fails when a response sets a csrf cookie: the session
// cookie is the only cookie this panel sets — the synchronizer token lives
// server-side with the session record, never in a cookie.
func assertNoCSRFCookie(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if strings.EqualFold(c.Name, "csrf") {
			t.Errorf("response set a csrf cookie: %v", c)
		}
	}
}

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

// GET /panel/login serves the embedded login SPA with a CSRF token injected
// into the meta. The token is NOT double-submitted via a cookie: the server
// mints a pre-auth session, stores the token with it server-side, and sets
// only the (HttpOnly) session cookie. Presenting that session again reuses
// the same stored token instead of minting a new one.
func TestLoginPageServesCSRFToken(t *testing.T) {
	mux, _, _, _, _ := newTestPanel(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/login", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /panel/login = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	m := csrfMetaRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no injected csrf meta in login page:\n%s", rec.Body.String())
	}
	sess := sessionCookieOf(t, rec)
	if !sess.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	assertNoCSRFCookie(t, rec)
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("HTML page served with Cache-Control %q, want no-cache", cc)
	}

	// Re-presenting the pre-auth session reuses its stored token and sets no
	// new cookie.
	req := httptest.NewRequest(http.MethodGet, "/panel/login", nil)
	req.AddCookie(sess)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	m2 := csrfMetaRe.FindStringSubmatch(rec.Body.String())
	if m2 == nil || m2[1] != m[1] {
		t.Errorf("revisit did not reuse the session's stored token: %q vs %q", m2, m)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("revisit with a valid session set cookies: %v", rec.Result().Cookies())
	}
}

// A failed login answers 401 JSON (the SPA shows the error box). The
// synchronizer-token check runs first: a missing/mismatched X-CSRF-Token —
// or a session the server does not know — is refused with 403 before
// credentials are checked.
func TestLoginPostContract(t *testing.T) {
	mux, _, _, _, _ := newTestPanel(t)

	// Establish the pre-auth session the login page would have set.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/login", nil))
	sess := sessionCookieOf(t, rec)
	token := csrfMetaRe.FindStringSubmatch(rec.Body.String())[1]

	post := func(sess *http.Cookie, header string) *httptest.ResponseRecorder {
		form := url.Values{"username": {"admin"}, "password": {"definitely-wrong"}}
		req := httptest.NewRequest(http.MethodPost, "/panel/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if sess != nil {
			req.AddCookie(sess)
		}
		if header != "" {
			req.Header.Set("X-CSRF-Token", header)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assertNoCSRFCookie(t, rec)
		return rec
	}

	rec = post(sess, token)
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

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"missing header":    post(sess, ""),
		"mismatched header": post(sess, "not-the-stored-token"),
		"unknown session":   post(nil, token),
	} {
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: login = %d, want 403", name, rec.Code)
			continue
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "invalid csrf token" {
			t.Errorf("%s: 403 body = %q, want {\"error\":\"invalid csrf token\"}", name, rec.Body.String())
		}
	}
}

// A successful login rotates the session: the pre-auth session is deleted
// (fixation protection) and the response carries a brand-new authenticated
// session cookie whose pages inject its own stored CSRF token.
func TestLoginSuccessRotatesSession(t *testing.T) {
	mux, database, _, _, _ := newTestPanel(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveSetting(context.Background(), "admin_pass", string(hash)); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panel/login", nil))
	preAuth := sessionCookieOf(t, rec)
	preAuthCSRF := csrfMetaRe.FindStringSubmatch(rec.Body.String())[1]

	form := url.Values{"username": {"admin"}, "password": {"s3cret-pass"}}
	req := httptest.NewRequest(http.MethodPost, "/panel/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(preAuth)
	req.Header.Set("X-CSRF-Token", preAuthCSRF)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/panel" {
		t.Fatalf("good login = %d → %q, want 303 → /panel", rec.Code, rec.Header().Get("Location"))
	}
	assertNoCSRFCookie(t, rec)
	authed := sessionCookieOf(t, rec)
	if authed.Value == preAuth.Value {
		t.Error("session token was not rotated on login")
	}
	if !authed.HttpOnly {
		t.Error("authenticated session cookie must be HttpOnly")
	}

	// The pre-auth session is dead: it no longer authenticates anything.
	req = httptest.NewRequest(http.MethodGet, "/panel", nil)
	req.AddCookie(preAuth)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/panel/login" {
		t.Errorf("old session after login = %d → %q, want 303 → /panel/login",
			rec.Code, rec.Header().Get("Location"))
	}

	// The new session serves the SPA with its own stored CSRF token.
	req = httptest.NewRequest(http.MethodGet, "/panel", nil)
	req.AddCookie(authed)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /panel with rotated session = %d, want 200", rec.Code)
	}
	m := csrfMetaRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no injected csrf meta in authed page:\n%s", rec.Body.String())
	}
	if m[1] == preAuthCSRF {
		t.Error("authed page still carries the pre-auth CSRF token")
	}
	assertNoCSRFCookie(t, rec)
}

// API and WS routes answer 401 JSON when unauthenticated (the SPA's http
// layer redirects to the login page client-side); HTML page routes keep the
// classic 303.
func TestUnauthenticatedContracts(t *testing.T) {
	mux, _, _, _, _ := newTestPanel(t)

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
// embedded index.html with the session's stored CSRF token in the meta, so
// refreshes and deep links work.
func TestSPAPagesServeIndex(t *testing.T) {
	mux, _, _, cookie, csrf := newTestPanel(t)

	for _, path := range []string{
		"/panel",
		"/panel/clients",
		"/panel/clients/anything",              // client detail, name resolved by the SPA
		"/panel/clients/anything/domains/x.co", // domain detail
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
		if !strings.Contains(rec.Body.String(), `content="`+csrf+`"`) {
			t.Errorf("GET %s did not inject the session's CSRF token", path)
		}
		assertNoCSRFCookie(t, rec)
	}
}

// A mutating settings POST without the session's CSRF token is refused even
// with a valid authenticated session — the token is compared against the
// server-side session record, not a cookie.
func TestSettingsPostRequiresCSRF(t *testing.T) {
	mux, _, _, cookie, csrf := newTestPanel(t)

	post := func(header string) *httptest.ResponseRecorder {
		form := url.Values{"wireguard_interface": {"wg1"}}
		req := httptest.NewRequest(http.MethodPost, "/settings/wireguard", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		if header != "" {
			req.Header.Set("X-CSRF-Token", header)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		assertNoCSRFCookie(t, rec)
		return rec
	}

	if rec := post(""); rec.Code != http.StatusForbidden {
		t.Errorf("POST /settings/wireguard without CSRF = %d, want 403", rec.Code)
	}
	if rec := post("wrong-token"); rec.Code != http.StatusForbidden {
		t.Errorf("POST /settings/wireguard with wrong CSRF = %d, want 403", rec.Code)
	}
	if rec := post(csrf); rec.Code != http.StatusSeeOther {
		t.Errorf("POST /settings/wireguard with the session's CSRF = %d, want 303", rec.Code)
	}
}

// The client portal is IP-gated and sessionless: it is served with the CSRF
// meta left EMPTY (it makes no mutating requests) and sets no cookies at all.
func TestPortalServesEmptyCSRFMeta(t *testing.T) {
	_, database, _, _, _ := newTestPanel(t)
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
	if !strings.Contains(body, `<meta name="csrf-token" content="" />`) {
		t.Errorf("portal csrf meta is not empty:\n%s", body)
	}
	if !strings.Contains(body, "window.OVPN_PORTAL") {
		t.Error("portal bootstrap was not injected")
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("portal set cookies: %v", cookies)
	}
}
