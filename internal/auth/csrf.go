package auth

import (
	"crypto/subtle"
	"io"
	"net/http"
)

// CSRFHeader is the header mutating requests must send, carrying the
// synchronizer token stored server-side with the caller's session. The SPA
// reads the token from the csrf-token <meta> the server injects into the
// HTML pages and echoes it back in this header.
const CSRFHeader = "X-CSRF-Token"

// CSRFMiddleware enforces the synchronizer-token pattern on mutating routes:
// the X-CSRF-Token header is compared in constant time against the token
// stored with the request's session record. There is deliberately NO csrf
// cookie — the session cookie is the only cookie, and the token lives only
// in server-side storage and the served HTML. A missing header, an unknown
// or expired session, or a mismatch are all refused with 403 JSON.
//
// For POST /panel/login the session is the pre-auth one minted when the
// login page was served; for the other wrapped routes AuthMiddleware has
// already run, so the session is authenticated. GET routes, /ws and
// /api/client-stats are never wrapped, so they stay exempt.
func CSRFMiddleware(sessions *SessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get(CSRFHeader)
		stored := ""
		if c, err := r.Cookie("session"); err == nil {
			stored, _ = sessions.CSRFToken(c.Value)
		}
		if header == "" || stored == "" ||
			subtle.ConstantTimeCompare([]byte(stored), []byte(header)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"error":"invalid csrf token"}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}
