package handler

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
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

type settingsPageData struct {
	Settings   map[string]string
	Saved      bool
	Restarting bool
}

func Register(
	mux *http.ServeMux,
	database *db.DB,
	sessions *auth.SessionStore,
	online *tracker.OnlineTracker,
	ippSt *ipp.Store,
	tmpl *template.Template,
	vpnNet *net.IPNet,
	sessionTTL time.Duration,
	logger *slog.Logger,
	templatesDir string,
	cache *sysinfo.StatsCache,
) {
	// ── Static files ─────────────────────────────────────────────────────────
	mux.Handle("/static/", http.StripPrefix("/static/",
		http.FileServer(http.Dir(filepath.Join(templatesDir, "static")))))

	// ── Admin API ────────────────────────────────────────────────────────────
	mux.Handle("/api/server-stats", auth.AuthMiddleware(sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, data := cache.Get()
		if data == nil {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
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

	// ── WebSocket real-time stats ─────────────────────────────────────────────
	mux.Handle("/ws", auth.AuthMiddleware(sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := wsUpgrade(w, r)
		if err != nil {
			return
		}
		defer conn.Close()

		ch := cache.Subscribe()
		defer cache.Unsubscribe(ch)

		if _, data := cache.Get(); data != nil {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			wsWriteText(rw.Writer, data)
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 256)
			for {
				conn.SetReadDeadline(time.Now().Add(120 * time.Second))
				if _, err := conn.Read(buf); err != nil {
					return
				}
			}
		}()

		for {
			select {
			case data, ok := <-ch:
				if !ok {
					return
				}
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := wsWriteText(rw.Writer, data); err != nil {
					return
				}
			case <-done:
				return
			case <-r.Context().Done():
				return
			}
		}
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
		cutoff, kind := db.CutoffFor(filter)
		c, err := database.ClientStatsByName(r.Context(), commonName, cutoff, kind)
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
			// Read credentials from DB on each attempt so changes take effect immediately.
			settings, err := database.GetAllSettings(r.Context())
			if err != nil {
				logger.Error("login: read settings: " + err.Error())
				http.Error(w, "Internal Error", http.StatusInternalServerError)
				return
			}
			passOK := bcrypt.CompareHashAndPassword([]byte(settings["admin_pass"]), []byte(pass)) == nil
			if user == settings["admin_user"] && passOK {
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

	// ── Settings page (GET + POST) ────────────────────────────────────────────
	mux.Handle("/settings", auth.AuthMiddleware(sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			current, err := database.GetAllSettings(r.Context())
			if err != nil {
				logger.Error("settings: read current: " + err.Error())
				http.Error(w, "Internal Error", http.StatusInternalServerError)
				return
			}

			keys := []string{
				"addr", "admin_user",
				"openvpn_status_log", "openvpn_cert_dir",
				"openvpn_ipp_file", "openvpn_server_config",
			}
			addrChanged := r.FormValue("addr") != current["addr"]
			for _, key := range keys {
				val := r.FormValue(key)
				if err := database.SaveSetting(r.Context(), key, val); err != nil {
					logger.Error("settings: save "+key+": "+err.Error())
					http.Error(w, "Failed to save settings", http.StatusInternalServerError)
					return
				}
			}

			// Only change the password when a new one is supplied; store it hashed.
			if newPass := r.FormValue("admin_pass"); newPass != "" && newPass != current["admin_pass"] {
				hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
				if err != nil {
					logger.Error("settings: hash password: " + err.Error())
					http.Error(w, "Failed to save settings", http.StatusInternalServerError)
					return
				}
				if err := database.SaveSetting(r.Context(), "admin_pass", string(hash)); err != nil {
					logger.Error("settings: save admin_pass: " + err.Error())
					http.Error(w, "Failed to save settings", http.StatusInternalServerError)
					return
				}
			}

			if addrChanged {
				go func() {
					time.Sleep(500 * time.Millisecond)
					os.Exit(0)
				}()
				http.Redirect(w, r, "/settings?saved=1&restarting=1", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
			return
		}

		settings, err := database.GetAllSettings(r.Context())
		if err != nil {
			logger.Error("settings: read: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		data := settingsPageData{
			Settings:   settings,
			Saved:      r.URL.Query().Get("saved") == "1",
			Restarting: r.URL.Query().Get("restarting") == "1",
		}
		renderTemplate(w, tmpl, "settings.html", data)
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
