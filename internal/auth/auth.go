package auth

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"time"
)

// session is one server-side session record. Beyond expiry it carries:
//
//   - authenticated: false for the PRE-AUTH sessions minted when the login
//     page is served (they exist only to hold the CSRF token for the login
//     POST and never pass AuthMiddleware), true after a successful login;
//   - csrf: the synchronizer token bound to this session, injected into the
//     served HTML pages and compared against the X-CSRF-Token header of
//     mutating requests (see csrf.go).
type session struct {
	expires       time.Time
	authenticated bool
	csrf          string
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*session
	ttl      time.Duration
}

func NewSessionStore(ttl time.Duration) *SessionStore {
	s := &SessionStore{
		sessions: make(map[string]*session),
		ttl:      ttl,
	}
	go s.sweepLoop()
	return s
}

// sweepLoop periodically evicts expired tokens so the session map does not grow
// unbounded with tokens that are never presented again.
func (s *SessionStore) sweepLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for token, sess := range s.sessions {
			if now.After(sess.expires) {
				delete(s.sessions, token)
			}
		}
		s.mu.Unlock()
	}
}

// Create mints a fresh session token and a fresh CSRF token and stores the
// record. authenticated is false for the pre-auth sessions that back the
// login form's CSRF check, true for the session minted on login success.
func (s *SessionStore) Create(authenticated bool) (sessionToken, csrfToken string) {
	sessionToken = GenerateToken()
	csrfToken = GenerateToken()
	s.mu.Lock()
	s.sessions[sessionToken] = &session{
		expires:       time.Now().Add(s.ttl),
		authenticated: authenticated,
		csrf:          csrfToken,
	}
	s.mu.Unlock()
	return sessionToken, csrfToken
}

// lookup returns the live session record for token, evicting it if expired.
func (s *SessionStore) lookup(token string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.expires) {
		delete(s.sessions, token)
		return nil, false
	}
	return sess, true
}

// Valid reports whether token is a live AUTHENTICATED session. Pre-auth
// sessions (minted for the login page's CSRF check) never qualify.
func (s *SessionStore) Valid(token string) bool {
	sess, ok := s.lookup(token)
	return ok && sess.authenticated
}

// CSRFToken returns the synchronizer token stored with any live session,
// pre-auth or authenticated. Records minted before tokens were stored
// server-side get one lazily.
func (s *SessionStore) CSRFToken(token string) (string, bool) {
	sess, ok := s.lookup(token)
	if !ok {
		return "", false
	}
	if sess.csrf == "" {
		s.mu.Lock()
		sess.csrf = GenerateToken()
		s.mu.Unlock()
	}
	return sess.csrf, true
}

func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func GenerateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func AuthMiddleware(sessions *SessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err != nil || !sessions.Valid(c.Value) {
			http.Redirect(w, r, "/panel/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// APIAuthMiddleware is AuthMiddleware for the JSON/WebSocket routes: instead
// of a 303 to the login page (meaningless to fetch/XHR callers) it answers
// 401 JSON, which the SPA's http layer turns into a client-side redirect.
func APIAuthMiddleware(sessions *SessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err != nil || !sessions.Valid(c.Value) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"unauthorized"}`)
			return
		}
		next.ServeHTTP(w, r)
	})
}
