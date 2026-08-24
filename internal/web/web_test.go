package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"ovpnmonitor/internal/model"
)

// A dist holding only the .gitkeep placeholder (frontend never built) must
// produce a clear 500, not a confusing 404 or an empty page.
func TestUnbuiltDistReturnsClear500(t *testing.T) {
	fsys := fstest.MapFS{"dist/.gitkeep": {}}

	rec := httptest.NewRecorder()
	servePage(fsys, rec, "index.html", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "frontend not built — run ./build.sh") {
		t.Errorf("body = %q, want the build hint", rec.Body.String())
	}
}

// A plain page is served verbatim, no-cache and without setting cookies.
func TestServePagePassthrough(t *testing.T) {
	const page = `<html><head><title>t</title></head><body></body></html>`
	fsys := fstest.MapFS{"dist/index.html": {Data: []byte(page)}}

	rec := httptest.NewRecorder()
	servePage(fsys, rec, "index.html", nil)
	if rec.Body.String() != page {
		t.Errorf("page was modified in serving:\n%s", rec.Body.String())
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("page serving set cookies: %v", cookies)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-cache") {
		t.Errorf("HTML page served with Cache-Control %q, want no-cache", cc)
	}
}

// portal.html gets the window.OVPN_PORTAL bootstrap injected before </head>,
// with the ClientPortalData json tags the React portal reads. The portal is
// sessionless: no cookies are set.
func TestServePortalInjectsBootstrap(t *testing.T) {
	fsys := fstest.MapFS{
		"dist/portal.html": {Data: []byte(
			`<html><head><title>VPN Portal</title></head><body></body></html>`)},
	}
	data := model.ClientPortalData{
		CommonName:     "alice",
		VPNAddress:     "10.8.0.2",
		Online:         true,
		ConnectedSince: "2026-01-01 10:00:00",
		LastSeen:       "2026-01-01 11:00:00",
	}

	rec := httptest.NewRecorder()
	servePage(fsys, rec, "portal.html", data)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 500-free 200", rec.Code)
	}
	body := rec.Body.String()

	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("portal set cookies: %v", cookies)
	}

	const marker = "<script>window.OVPN_PORTAL = "
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no OVPN_PORTAL bootstrap in page:\n%s", body)
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, "</script>")
	if j < 0 {
		t.Fatalf("bootstrap script not closed:\n%s", body)
	}
	if k := strings.Index(body[i:], "</head>"); k < 0 || strings.Index(body, "</head>") < i {
		t.Error("bootstrap must be injected before </head>")
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(rest[:j]), &payload); err != nil {
		t.Fatalf("bootstrap payload is not JSON: %v", err)
	}
	want := map[string]any{
		"common_name":     "alice",
		"vpn_address":     "10.8.0.2",
		"online":          true,
		"connected_since": "2026-01-01 10:00:00",
		"last_seen":       "2026-01-01 11:00:00",
	}
	for k, v := range want {
		if payload[k] != v {
			t.Errorf("payload[%q] = %v, want %v", k, payload[k], v)
		}
	}
}
