package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"ovpnmonitor/internal/auth"
	"ovpnmonitor/internal/model"
	"ovpnmonitor/internal/web"
)

// settingsSection is one entry of the settings sidebar submenu: a sub-page
// showing only its own fields.
//
// Keys is an explicit allow-list of the setting keys the section owns, and it
// is the ONLY thing a POST to that section may write. Splitting the settings
// form across pages means each submission carries just a subset of the fields,
// so a save must never touch keys outside the submitted section — otherwise
// saving, say, WireGuard would blank the OpenVPN paths (see saveSettings).
type settingsSection struct {
	Key   string
	Title string
	Keys  []string
}

// settingsSections lists the sub-pages in sidebar order. The first entry is
// the default landing section for /settings.
var settingsSections = []settingsSection{
	{"general", "General", []string{"addr", "admin_user", "poll_interval"}},
	{"openvpn", "OpenVPN", []string{
		"openvpn_status_log", "openvpn_cert_dir",
		"openvpn_ipp_file", "openvpn_server_config",
	}},
	{"wireguard", "WireGuard", []string{
		"wireguard_conf", "wireguard_interface", "wireguard_handshake_timeout",
	}},
	{"domains", "Domain Tracking", []string{
		"sniffer_ifaces", "sniffer_wg_conf", "sniffer_snaplen",
		"sniffer_workers", "sniffer_queue", "sniffer_flush", "sniffer_dedup",
	}},
}

// findSettingsSection resolves a URL path segment to its section.
func findSettingsSection(key string) (settingsSection, bool) {
	for _, s := range settingsSections {
		if s.Key == key {
			return s, true
		}
	}
	return settingsSection{}, false
}

// allSettingsKeys is every key across every section, used by the legacy
// whole-form POST target.
func allSettingsKeys() []string {
	var keys []string
	for _, s := range settingsSections {
		keys = append(keys, s.Keys...)
	}
	return keys
}

// registerPages mounts the page routes: admin login/logout, the SPA pages
// (all served from the embedded index.html; the React router reads the URL),
// the settings POST endpoints, and the client portal at the root.
func registerPages(mux *http.ServeMux, d Deps) {
	// ── /login → redirect to /panel/login ────────────────────────────────────
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/panel/login", http.StatusMovedPermanently)
	})

	// ── /logout → redirect to /panel/logout ──────────────────────────────────
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/panel/logout", http.StatusMovedPermanently)
	})

	// ── Admin login ───────────────────────────────────────────────────────────
	// GET serves the embedded login SPA. The synchronizer-token CSRF check on
	// the POST needs server-side state pre-auth, so a visitor without a live
	// session gets a PRE-AUTH one here (see preAuthCSRF): a session cookie
	// whose record holds the CSRF token injected into the page.
	mux.Handle("GET /panel/login", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		web.ServePage(w, "login.html", d.preAuthCSRF(w, r))
	}))

	mux.Handle("POST /panel/login", auth.CSRFMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			// Session fixation protection: the pre-auth session dies with the
			// login and the authenticated session is a brand-new token (with
			// its own fresh CSRF token).
			if c, err := r.Cookie("session"); err == nil {
				d.Sessions.Delete(c.Value)
			}
			token, _ := d.Sessions.Create(true)
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Invalid username or password",
		})
	})))

	// ── Admin logout ──────────────────────────────────────────────────────────
	// Method-specific patterns: an all-method /panel/logout would conflict with
	// the GET /panel/ SPA subtree in the stdlib mux. GET and POST cover every
	// real caller (sidebar navigation and form posts alike).
	logout := func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil {
			d.Sessions.Delete(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/panel/login", http.StatusSeeOther)
	}
	mux.HandleFunc("GET /panel/logout", logout)
	mux.HandleFunc("POST /panel/logout", logout)

	// ── SPA pages ─────────────────────────────────────────────────────────────
	// Every authenticated page is the same embedded index.html; the React
	// router resolves /panel, /panel/clients/{name}/domains/{root}, /settings/*
	// etc. client-side and fetches its data over the JSON APIs. The subtree
	// patterns double as the SPA fallback: any unknown GET under /panel/ or
	// /settings/ still serves the app (never a 404), so refreshes and deep
	// links work. Method-specific patterns keep POSTs (login, settings saves)
	// out of the GET-only SPA handlers. The session's stored CSRF token is
	// injected into the meta for the SPA's http layer.
	spa := auth.AuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// AuthMiddleware has already validated the session cookie, so the
		// lookup cannot miss.
		csrf, _ := d.Sessions.CSRFToken(sessionCookie(r))
		web.ServePage(w, "index.html", csrf)
	}))
	mux.Handle("GET /panel", spa)   // exact; "/panel/{$}" would only match "/panel/"
	mux.Handle("GET /panel/", spa)  // subtree + SPA fallback
	mux.Handle("GET /settings", spa)
	mux.Handle("GET /settings/", spa)

	// ── Settings saves ────────────────────────────────────────────────────────
	// Legacy target for a cached copy of the old single-page form: accepts
	// every known key. Still presence-checked, so it can only write fields the
	// submitted form actually carried.
	mux.Handle("POST /settings", auth.AuthMiddleware(d.Sessions, auth.CSRFMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.saveSettings(w, r, allSettingsKeys(), "/settings/"+settingsSections[0].Key)
	}))))

	mux.Handle("POST /settings/{section}", auth.AuthMiddleware(d.Sessions, auth.CSRFMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		section, ok := findSettingsSection(r.PathValue("section"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		d.saveSettings(w, r, section.Keys, "/settings/"+section.Key)
	}))))

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
		web.ServePortal(w, data)
	})
}

// sessionCookie returns the request's session token, "" when absent.
func sessionCookie(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return c.Value
}

// preAuthCSRF resolves the CSRF token injected into the login page. A request
// that already carries a live session (pre-auth or authenticated) reuses the
// token stored with it; anything else gets a fresh PRE-AUTH session — the
// session cookie is set here (same attributes as the login POST sets) so the
// synchronizer-token check on POST /panel/login has server-side state to
// compare the header against.
func (d Deps) preAuthCSRF(w http.ResponseWriter, r *http.Request) string {
	if token, ok := d.Sessions.CSRFToken(sessionCookie(r)); ok {
		return token
	}
	sessionToken, csrf := d.Sessions.Create(false)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(d.SessionTTL.Seconds()),
	})
	return csrf
}

// saveSettings persists a settings form submission and confirms the save —
// a 303 redirect back to redirectTo with a "saved" flash for HTML forms, or
// a JSON {"ok":true,"restarting":...} body for API clients (see
// respondSettingsSaved).
//
// keys is the allow-list of setting keys this request may write — the keys of
// the section that was submitted. Two rules make partial forms safe now that
// the settings UI is split across sub-pages:
//
//   - Only keys in the allow-list are considered, so a crafted request cannot
//     reach a field that isn't on the page it claims to be.
//   - Within that list, only keys actually PRESENT in the request body are
//     written. A missing field means "this form doesn't own that setting",
//     never "set it to empty" — blanking, say, wireguard_conf or
//     openvpn_status_log would silently disable a whole monitoring subsystem.
//
// Values come from r.PostForm (body only), never r.Form, so query-string
// parameters on the POST URL can't inject a value for a field the form
// itself did not submit.
func (d Deps) saveSettings(w http.ResponseWriter, r *http.Request, keys []string, redirectTo string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	current, err := d.DB.GetAllSettings(r.Context())
	if err != nil {
		d.Logger.Error("settings: read current: " + err.Error())
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}

	// A listening-address change requires a restart. It is only ever detected
	// from a form that OWNS addr and actually carried it: an absent field means
	// "unchanged", and a section that doesn't own addr must not be able to
	// trigger a restart by smuggling one into its request body.
	addrChanged := false

	for _, key := range keys {
		vals, ok := r.PostForm[key]
		if !ok || len(vals) == 0 {
			continue // not part of this form; leave the stored value alone
		}
		if key == "addr" && vals[0] != current["addr"] {
			addrChanged = true
		}
		if err := d.DB.SaveSetting(r.Context(), key, vals[0]); err != nil {
			d.Logger.Error("settings: save " + key + ": " + err.Error())
			http.Error(w, "Failed to save settings", http.StatusInternalServerError)
			return
		}
	}

	// The password lives on the same page as admin_user, and is only accepted
	// from a form that owns that field — otherwise a browser password manager
	// autofilling an unrelated section's page could silently change it.
	//
	// It is never echoed back into the form, so an empty value means "leave it
	// as it is". Only a non-empty value sets a new one, stored hashed.
	if newPass := r.PostForm.Get("admin_pass"); newPass != "" && slices.Contains(keys, "admin_user") {
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
		if hashErr != nil {
			d.Logger.Error("settings: hash password: " + hashErr.Error())
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
		respondSettingsSaved(w, r, redirectTo, true)
		return
	}
	respondSettingsSaved(w, r, redirectTo, false)
}

// respondSettingsSaved answers a successful settings save. API clients (the
// React SPA) ask for JSON via an Accept: application/json or
// Content-Type: application/json header and get {"ok":true,"restarting":...};
// a plain HTML form post keeps the classic 303 redirect with the flash query
// parameters.
func respondSettingsSaved(w http.ResponseWriter, r *http.Request, redirectTo string, restarting bool) {
	if strings.Contains(r.Header.Get("Accept"), "application/json") ||
		strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":         true,
			"restarting": restarting,
		})
		return
	}
	if restarting {
		http.Redirect(w, r, redirectTo+"?saved=1&restarting=1", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, redirectTo+"?saved=1", http.StatusSeeOther)
}
