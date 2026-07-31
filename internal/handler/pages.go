package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
	"ovpnmonitor/internal/auth"
	"ovpnmonitor/internal/model"
)

type settingsPageData struct {
	Settings   map[string]string
	Saved      bool
	Restarting bool
}

// registerPages mounts the HTML routes: admin login/logout, the panel pages,
// the settings page and the client portal at the root.
func registerPages(mux *http.ServeMux, d Deps) {
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
			settings, err := d.DB.GetAllSettings(r.Context())
			if err != nil {
				d.Logger.Error("login: read settings: " + err.Error())
				http.Error(w, "Internal Error", http.StatusInternalServerError)
				return
			}
			passOK := bcrypt.CompareHashAndPassword([]byte(settings["admin_pass"]), []byte(pass)) == nil
			if user == settings["admin_user"] && passOK {
				token := auth.GenerateToken()
				d.Sessions.Set(token)
				http.SetCookie(w, &http.Cookie{
					Name:     "session",
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					MaxAge:   int(d.SessionTTL.Seconds()),
				})
				http.Redirect(w, r, "/panel", http.StatusSeeOther)
				return
			}
			renderTemplate(w, d.Templates, "login.html", map[string]interface{}{
				"Error": "Invalid username or password",
			})
			return
		}
		renderTemplate(w, d.Templates, "login.html", nil)
	})

	// ── Admin logout ──────────────────────────────────────────────────────────
	mux.HandleFunc("/panel/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil {
			d.Sessions.Delete(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/panel/login", http.StatusSeeOther)
	})

	// ── Admin dashboard ───────────────────────────────────────────────────────
	mux.Handle("/panel", auth.AuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, d.Templates, "dashboard.html", nil)
	})))

	// ── Clients page ──────────────────────────────────────────────────────────
	mux.Handle("/panel/clients", auth.AuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, d.Templates, "dashboard.html", nil)
	})))

	// ── Client detail page ────────────────────────────────────────────────────
	// Row clicks on the Clients page navigate here; the page fetches the client
	// aggregate and its visited-domain history over the JSON APIs (see api.go).
	mux.Handle("GET /panel/clients/{name}", auth.AuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, d.Templates, "clientdetail.html", map[string]interface{}{
			"Name": r.PathValue("name"),
		})
	})))

	// ── Settings page (GET + POST) ────────────────────────────────────────────
	mux.Handle("/settings", auth.AuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			current, err := d.DB.GetAllSettings(r.Context())
			if err != nil {
				d.Logger.Error("settings: read current: " + err.Error())
				http.Error(w, "Internal Error", http.StatusInternalServerError)
				return
			}

			keys := []string{
				"addr", "admin_user", "poll_interval",
				"openvpn_status_log", "openvpn_cert_dir",
				"openvpn_ipp_file", "openvpn_server_config",
				"wireguard_conf", "wireguard_interface",
				"wireguard_handshake_timeout",
				"sniffer_ifaces", "sniffer_wg_conf", "sniffer_snaplen",
				"sniffer_workers", "sniffer_queue", "sniffer_flush", "sniffer_dedup",
			}
			addrChanged := r.FormValue("addr") != current["addr"]
			for _, key := range keys {
				val := r.FormValue(key)
				if err := d.DB.SaveSetting(r.Context(), key, val); err != nil {
					d.Logger.Error("settings: save " + key + ": " + err.Error())
					http.Error(w, "Failed to save settings", http.StatusInternalServerError)
					return
				}
			}

			// Only change the password when a new one is supplied; store it hashed.
			if newPass := r.FormValue("admin_pass"); newPass != "" && newPass != current["admin_pass"] {
				hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
				if err != nil {
					d.Logger.Error("settings: hash password: " + err.Error())
					http.Error(w, "Failed to save settings", http.StatusInternalServerError)
					return
				}
				if err := d.DB.SaveSetting(r.Context(), "admin_pass", string(hash)); err != nil {
					d.Logger.Error("settings: save admin_pass: " + err.Error())
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

		settings, err := d.DB.GetAllSettings(r.Context())
		if err != nil {
			d.Logger.Error("settings: read: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		data := settingsPageData{
			Settings:   settings,
			Saved:      r.URL.Query().Get("saved") == "1",
			Restarting: r.URL.Query().Get("restarting") == "1",
		}
		renderTemplate(w, d.Templates, "settings.html", data)
	})))

	// ── Client portal (root) ──────────────────────────────────────────────────
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		clientIP, ok := VPNClientIP(r, d.VPNNet, d.WGRegistry)
		if !ok {
			http.Redirect(w, r, "/panel/login", http.StatusSeeOther)
			return
		}
		// Resolve the visitor's name: OpenVPN's ipp.txt first, then the
		// WireGuard registry's allowed-ips map for wg-subnet visitors.
		vpnToName, _ := d.IPP.Get()
		commonName, found := vpnToName[clientIP.String()]
		if !found {
			commonName, found = d.WGRegistry.NameByIP(clientIP.String())
		}
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
		// Look up by the resolved NAME rather than by vpn_address: for a client
		// provisioned in both systems, the clients.vpn_address column holds
		// whichever system wrote last, so an address lookup could miss even
		// though the visitor was just identified.
		c, err := d.DB.ClientByName(r.Context(), commonName)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			d.Logger.Error("client portal db: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		if c != nil {
			data.Online = d.OVPNOnline.Get()[c.CommonName] || d.WGOnline.Get()[c.CommonName]
			data.ConnectedSince = c.ConnectedSince
			data.LastSeen = c.LastSeen
		}
		renderTemplate(w, d.Templates, "client.html", data)
	})
}
