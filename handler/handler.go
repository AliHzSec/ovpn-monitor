package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"ovpnmonitor/auth"
	"ovpnmonitor/db"
	"ovpnmonitor/ipp"
	"ovpnmonitor/model"
	"ovpnmonitor/sysinfo"
	"ovpnmonitor/tracker"
)

func LoadTemplates(dir string) (*template.Template, error) {
	return template.ParseGlob(filepath.Join(dir, "*.html"))
}

func renderTemplate(w http.ResponseWriter, tmpl *template.Template, name string, data interface{}) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func VPNClientIP(r *http.Request, vpnNet *net.IPNet) (net.IP, bool) {
	if vpnNet == nil {
		return nil, false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	return ip, vpnNet.Contains(ip)
}

func Register(
	mux *http.ServeMux,
	database *db.DB,
	sessions *auth.SessionStore,
	online *tracker.OnlineTracker,
	ippSt *ipp.Store,
	tmpl *template.Template,
	vpnNet *net.IPNet,
	adminUser, adminPass string,
	sessionTTL time.Duration,
	logger *slog.Logger,
	templatesDir string,
) {
	// ── Static files ─────────────────────────────────────────────────────────
	mux.Handle("/static/", http.StripPrefix("/static/",
		http.FileServer(http.Dir(filepath.Join(templatesDir, "static")))))

	// ── Admin API ────────────────────────────────────────────────────────────
	mux.Handle("/api/server-stats", auth.AuthMiddleware(sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		type result struct {
			stats *sysinfo.SystemStats
			err   error
		}
		ch := make(chan result, 1)
		go func() {
			stats, err := sysinfo.Collect()
			ch <- result{stats, err}
		}()

		select {
		case res := <-ch:
			if res.err != nil {
				logger.Error("server-stats: " + res.err.Error())
				http.Error(w, "Internal Error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(res.stats)
		case <-ctx.Done():
			http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
		}
	})))

	mux.Handle("/api/clients", auth.AuthMiddleware(sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("filter")
		clients, err := database.QueryClients(r.Context(), filter)
		if err != nil {
			logger.Error("querying clients: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		onlineSet := online.Get()
		for i := range clients {
			clients[i].Online = onlineSet[clients[i].CommonName]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(clients)
	})))

	// ── Client stats API (VPN IP only, no auth) ──────────────────────────────
	mux.HandleFunc("/api/client-stats", func(w http.ResponseWriter, r *http.Request) {
		clientIP, ok := VPNClientIP(r, vpnNet)
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		vpnToName, _ := ippSt.Get()
		commonName, found := vpnToName[clientIP.String()]
		if !found {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		filter := r.URL.Query().Get("filter")
		c, err := database.ClientStatsByName(r.Context(), commonName, db.CutoffFor(filter))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			logger.Error("client stats: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		onlineSet := online.Get()
		c.Online = onlineSet[c.CommonName]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	})

	// ── /login → redirect to /panel/login ────────────────────────────────────
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/panel/login", http.StatusMovedPermanently)
	})

	// ── /logout → redirect to /panel/logout ──────────────────────────────────
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/panel/logout", http.StatusMovedPermanently)
	})

	// ── Admin login (GET + POST) ──────────────────────────────────────────────
	mux.HandleFunc("/panel/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			user := r.FormValue("username")
			pass := r.FormValue("password")
			if user == adminUser && pass == adminPass {
				token := auth.GenerateToken()
				sessions.Set(token)
				http.SetCookie(w, &http.Cookie{
					Name:     "session",
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					MaxAge:   int(sessionTTL.Seconds()),
				})
				http.Redirect(w, r, "/panel", http.StatusSeeOther)
				return
			}
			renderTemplate(w, tmpl, "login.html", map[string]interface{}{
				"Error": "Invalid username or password",
			})
			return
		}
		renderTemplate(w, tmpl, "login.html", nil)
	})

	// ── Admin logout ──────────────────────────────────────────────────────────
	mux.HandleFunc("/panel/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil {
			sessions.Delete(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/panel/login", http.StatusSeeOther)
	})

	// ── Admin dashboard ───────────────────────────────────────────────────────
	mux.Handle("/panel", auth.AuthMiddleware(sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, tmpl, "dashboard.html", nil)
	})))

	// ── Clients page ──────────────────────────────────────────────────────────
	mux.Handle("/panel/clients", auth.AuthMiddleware(sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, tmpl, "dashboard.html", nil)
	})))

	// ── Client portal (root) ──────────────────────────────────────────────────
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		clientIP, ok := VPNClientIP(r, vpnNet)
		if !ok {
			http.Redirect(w, r, "/panel/login", http.StatusSeeOther)
			return
		}
		vpnToName, _ := ippSt.Get()
		commonName, found := vpnToName[clientIP.String()]
		if !found {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#070b0f;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center"><p>Your VPN session was not found. Please reconnect.</p></body></html>`)
			return
		}
		data := model.ClientPortalData{
			CommonName: commonName,
			VPNAddress: clientIP.String(),
		}
		c, err := database.ClientByVPNAddress(r.Context(), clientIP.String())
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			logger.Error("client portal db: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		if c != nil {
			onlineSet := online.Get()
			data.Online = onlineSet[c.CommonName]
			data.ConnectedSince = c.ConnectedSince
			data.LastSeen = c.LastSeen
		}
		renderTemplate(w, tmpl, "client.html", data)
	})
}
