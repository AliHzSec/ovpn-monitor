package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Changing the listening address from the section that owns it still signals a
// restart, so the existing behaviour is preserved.
//
// This test lives in a zz_-prefixed file so it runs LAST in the package (the
// testing framework runs tests in file order, files alphabetical): the handler
// schedules os.Exit(0) 500ms out to effect the restart, and any test still
// running when it fires would be killed mid-flight.
func TestAddrChangeStillSignalsRestart(t *testing.T) {
	mux, _, _, cookie := newTestPanel(t)

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
	// finish well before then; this being the last test keeps that cheap.
}
