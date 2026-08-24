package handler

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"ovpnmonitor/internal/auth"
	"ovpnmonitor/internal/db"
	"ovpnmonitor/internal/model"
	"ovpnmonitor/internal/openvpn"
	"ovpnmonitor/internal/sysinfo"
	"ovpnmonitor/internal/tracker"
	"ovpnmonitor/internal/web"
	"ovpnmonitor/internal/wireguard"
)

// VPNClientIP extracts the request's source IP and reports whether it belongs
// to a monitored VPN subnet: the OpenVPN subnet (vpnNet, may be nil when
// undetected) or the WireGuard subnet (from the registry, which tracks the
// wg0.conf Address line and refreshes with it — so it is consulted live
// rather than captured once at startup).
func VPNClientIP(r *http.Request, vpnNet *net.IPNet, wgReg *wireguard.Registry) (net.IP, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	if vpnNet != nil && vpnNet.Contains(ip) {
		return ip, true
	}
	if wgReg != nil && wgReg.SubnetContains(ip) {
		return ip, true
	}
	return ip, false
}

// Deps bundles everything the HTTP layer depends on, so Register takes one
// value instead of a positional parameter list that grows with every feature.
type Deps struct {
	DB         *db.DB
	Sessions   *auth.SessionStore
	OVPNOnline *tracker.OnlineTracker // OpenVPN online set, fed by the watcher
	WGOnline   *tracker.OnlineTracker // WireGuard online set, fed by the wg poller
	Certs      *openvpn.CertWhitelist
	WGRegistry *wireguard.Registry
	IPP        *openvpn.IPPStore
	VPNNet     *net.IPNet // OpenVPN subnet; nil when undetected
	SessionTTL time.Duration
	Logger     *slog.Logger
	Cache      *sysinfo.StatsCache
}

// annotate fills a client's per-system connection state: Online stays the
// union (existing consumers depend on it), the per-system flags drive the
// protocol badges, and Sources lists where the client is provisioned.
func (d Deps) annotate(c *model.Client, ovpnOnline, wgOnlineSet map[string]bool) {
	c.OnlineOpenVPN = ovpnOnline[c.CommonName]
	c.OnlineWireGuard = wgOnlineSet[c.CommonName]
	c.Online = c.OnlineOpenVPN || c.OnlineWireGuard
	c.Sources = nil
	if d.Certs.Contains(c.CommonName) {
		c.Sources = append(c.Sources, "openvpn")
	}
	if d.WGRegistry.Contains(c.CommonName) {
		c.Sources = append(c.Sources, "wireguard")
	}
}

// Register mounts every route — the embedded frontend assets (web package),
// the JSON/WebSocket APIs (api.go) and the SPA pages (pages.go) — onto mux.
func Register(mux *http.ServeMux, d Deps) {
	web.RegisterAssets(mux)
	registerAPI(mux, d)
	registerPages(mux, d)
}
