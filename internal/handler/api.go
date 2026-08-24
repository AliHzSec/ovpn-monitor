package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"time"

	"ovpnmonitor/internal/auth"
	"ovpnmonitor/internal/db"
	"ovpnmonitor/internal/domain"
	"ovpnmonitor/internal/model"
	"ovpnmonitor/internal/sysinfo"
)

// registerAPI mounts the JSON and WebSocket endpoints: the authenticated admin
// API under /api and /ws, plus the unauthenticated (VPN-subnet-only)
// /api/client-stats used by the client portal.
func registerAPI(mux *http.ServeMux, d Deps) {
	// ── Admin API ────────────────────────────────────────────────────────────
	mux.Handle("/api/server-stats", auth.APIAuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, data := d.Cache.Get()
		if data == nil {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})))

	// ── Service control (OpenVPN / WireGuard) ────────────────────────────────
	// Only these fixed keys may be acted on; the unit names are resolved
	// server-side and the frontend never supplies a unit string.
	serviceUnits := map[string]string{
		"openvpn":   sysinfo.OpenVPNUnit(),
		"wireguard": sysinfo.WGUnit,
	}
	mux.Handle("POST /api/service/{name}/{action}", auth.APIAuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unit, known := serviceUnits[r.PathValue("name")]
		action := r.PathValue("action")
		if !known || (action != "start" && action != "stop" && action != "restart") {
			http.Error(w, "Unknown service or action", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "systemctl", action, unit).CombinedOutput()
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			d.Logger.Error("service control failed",
				"unit", unit, "action", action, "err", err, "output", strings.TrimSpace(string(out)))
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":     false,
				"active": sysinfo.ServiceActive(unit),
				"error":  "systemctl " + action + " failed",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":     true,
			"active": sysinfo.ServiceActive(unit),
		})
	})))

	mux.Handle("/api/clients", auth.APIAuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("filter")
		clients, err := d.DB.QueryClients(r.Context(), filter)
		if err != nil {
			d.Logger.Error("querying clients: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		// Exclude clients that are valid in NEITHER system: certificate revoked
		// (certs — sourced from pki/index.txt — only contains currently-valid
		// common names) AND not a current WireGuard peer. A name valid in either
		// source stays listed, so WireGuard-only clients appear and the list
		// matches the Overview's Total Clients count. Filtered in place; a valid
		// client that has never connected has no sessions and is simply Offline.
		ovpnOnline := d.OVPNOnline.Get()
		wgOnlineSet := d.WGOnline.Get()
		valid := clients[:0]
		for i := range clients {
			if !d.Certs.Contains(clients[i].CommonName) && !d.WGRegistry.Contains(clients[i].CommonName) {
				continue
			}
			d.annotate(&clients[i], ovpnOnline, wgOnlineSet)
			valid = append(valid, clients[i])
		}
		clients = valid
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(clients)
	})))

	// ── Single client (all-time aggregate) for the detail page ───────────────
	mux.Handle("GET /api/clients/{name}", auth.APIAuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		c, err := d.DB.ClientByName(r.Context(), name)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			d.Logger.Error("client by name: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		d.annotate(c, d.OVPNOnline.Get(), d.WGOnline.Get())
		// Per-protocol split for the detail page's traffic card. Best-effort:
		// a failure leaves the split at zero without hiding the client.
		if ovpnBytes, wgBytes, err := d.DB.ClientProtocolSplit(r.Context(), name); err != nil {
			d.Logger.Error("client protocol split: " + err.Error())
		} else {
			c.TrafficOpenVPN = ovpnBytes
			c.TrafficWireGuard = wgBytes
			c.TrafficOpenVPNReadable = db.FormatBytes(ovpnBytes)
			c.TrafficWireGuardReadable = db.FormatBytes(wgBytes)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	})))

	// ── Visited domains for one client, collapsed to root domains ────────────
	// One row per site, with first/last seen and visits rolled up across every
	// hostname under it. The per-hostname breakdown lives at the route below.
	mux.Handle("GET /api/clients/{name}/domains", auth.APIAuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		domains, err := d.DB.QueryVisitedRootDomains(r.Context(), name)
		if err != nil {
			d.Logger.Error("visited root domains: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		if domains == nil {
			domains = []model.VisitedDomain{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(domains)
	})))

	// ── Hostnames under one root domain, for the domain detail page ──────────
	// The root domain is matched against the stored grouping key, so a value
	// that is not a root domain (or that this client never visited) simply
	// yields an empty list rather than an error.
	mux.Handle("GET /api/clients/{name}/domains/{root}", auth.APIAuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		root := domain.Normalize(r.PathValue("root"))
		subdomains, err := d.DB.QueryVisitedSubdomains(r.Context(), name, root)
		if err != nil {
			d.Logger.Error("visited subdomains: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		if subdomains == nil {
			subdomains = []model.VisitedDomain{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(subdomains)
	})))

	// ── Settings sections as JSON ──────────────────────────────────────────
	// Same section allow-list as the HTML settings pages (see pages.go), for
	// the React settings page. admin_pass is write-only: the general section
	// reports it as an empty string, never the stored hash.
	mux.Handle("GET /api/settings/{section}", auth.APIAuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		section, ok := findSettingsSection(r.PathValue("section"))
		if !ok {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		settings, err := d.DB.GetAllSettings(r.Context())
		if err != nil {
			d.Logger.Error("api settings: read: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		out := make(map[string]string, len(section.Keys)+1)
		for _, key := range section.Keys {
			out[key] = settings[key]
		}
		if slices.Contains(section.Keys, "admin_user") {
			out["admin_pass"] = ""
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})))

	// ── WebSocket real-time stats ─────────────────────────────────────────────
	mux.Handle("/ws", auth.APIAuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := wsUpgrade(w, r)
		if err != nil {
			return
		}
		defer conn.Close()

		ch := d.Cache.Subscribe()
		defer d.Cache.Unsubscribe(ch)

		if _, data := d.Cache.Get(); data != nil {
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
		clientIP, ok := VPNClientIP(r, d.VPNNet, d.WGRegistry)
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
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
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		filter := r.URL.Query().Get("filter")
		cutoff, kind := db.CutoffFor(filter)
		c, err := d.DB.ClientStatsByName(r.Context(), commonName, cutoff, kind)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			d.Logger.Error("client stats: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		d.annotate(c, d.OVPNOnline.Get(), d.WGOnline.Get())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	})
}
