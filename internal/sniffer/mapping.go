package sniffer

import (
	"bufio"
	"database/sql"
	"log/slog"
	"maps"
	"os"
	"strings"
	"sync"

	"ovpnmonitor/internal/wireguard"
)

// Mapper resolves a VPN source IP to the client/peer name it belongs to, for
// BOTH OpenVPN and WireGuard, mirroring the mapping mechanisms the panel already
// relies on:
//
//   - OpenVPN: the ipp.txt persistence file ("name,ip,..."), the same file the
//     panel's openvpn package parses (IPPStore).
//   - WireGuard: the wg config file, associating each [Peer]'s AllowedIPs with a
//     human name taken from the surrounding comment markers written by the
//     common install scripts ("# BEGIN_PEER <name>" or "# Name = <name>").
//
// BOTH paths are resolved from the settings table on every refresh (see
// ippFilePath and wireGuardConfPath), never captured once at construction, so
// moving either file takes effect within one refresh instead of at the next
// restart. The paths passed to NewMapper are only the fallback for a settings
// table that cannot be read.
//
// The table is rebuilt atomically on each refresh so lookups never see a
// partial map.
type Mapper struct {
	db      *sql.DB
	ippPath string
	wgConf  string
	logger  *slog.Logger

	mu       sync.RWMutex
	ipToName map[string]string
}

func NewMapper(db *sql.DB, ippPath, wgConf string, logger *slog.Logger) *Mapper {
	return &Mapper{
		db:       db,
		ippPath:  ippPath,
		wgConf:   wgConf,
		logger:   logger,
		ipToName: map[string]string{},
	}
}

// Lookup returns the client name for a VPN IP, if known.
func (m *Mapper) Lookup(ip string) (string, bool) {
	m.mu.RLock()
	name, ok := m.ipToName[ip]
	m.mu.RUnlock()
	return name, ok
}

// Refresh rebuilds the IP→name table from both sources.
func (m *Mapper) Refresh() {
	// Each source is loaded into its own table so the refresh log can report
	// per-source counts. "wireguard=0" is the single symptom that separates a
	// mis-resolved WireGuard config from a genuinely idle peer set: without it,
	// unmapped peers look exactly like peers that simply browsed nothing,
	// because an unmapped packet is dropped silently in processJob.
	ovpn := map[string]string{}
	wg := map[string]string{}

	if path := m.ippFilePath(); path != "" {
		if err := loadIPP(path, ovpn); err != nil && !os.IsNotExist(err) {
			m.logger.Warn("read ipp.txt failed", "path", path, "err", err)
		}
	}
	if path := m.wireGuardConfPath(); path != "" {
		if err := loadWireGuard(path, wg); err != nil && !os.IsNotExist(err) {
			m.logger.Warn("read wireguard conf failed", "path", path, "err", err)
		}
	}

	// Merged OpenVPN first, then WireGuard, so an address claimed by both
	// resolves exactly as it did when both loaders shared one map.
	next := make(map[string]string, len(ovpn)+len(wg))
	maps.Copy(next, ovpn)
	maps.Copy(next, wg)

	m.mu.Lock()
	m.ipToName = next
	m.mu.Unlock()
	m.logger.Info("ip→client map refreshed",
		"entries", len(next), "openvpn", len(ovpn), "wireguard", len(wg))
}

// ippFilePath resolves the OpenVPN ipp.txt to map from, preferring the panel's
// openvpn_ipp_file setting so the sniffer follows whatever the admin configured.
func (m *Mapper) ippFilePath() string {
	if p, ok := m.setting("openvpn_ipp_file"); ok && p != "" {
		return p
	}
	return m.ippPath
}

// wireGuardConfPath resolves the WireGuard config the peer→name mapping is built
// from. sniffer_wg_conf wins when it is set, keeping the Domain Tracking page's
// override meaningful; otherwise the panel's authoritative wireguard_conf is
// used.
//
// That fallback is the point of this function. The two settings live on
// DIFFERENT settings pages, and wireguard_conf is the one an admin edits when
// the config moves. Without the fallback the sniffer kept reading the stale
// sniffer_wg_conf path and mapped no WireGuard peers at all — and because a
// missing file is not an error worth logging (os.IsNotExist is ignored above)
// and an unmapped packet is dropped without a trace, the only symptom was an
// empty Visited Domains list for every WireGuard client.
//
// An empty result means WireGuard is not configured, which is precisely when
// there are no peers to map.
func (m *Mapper) wireGuardConfPath() string {
	if p, ok := m.setting("sniffer_wg_conf"); ok && p != "" {
		return p
	}
	if p, ok := m.setting("wireguard_conf"); ok {
		return p
	}
	// The settings table could not be read (no DB handle, or a failed query):
	// keep using the path captured at construction rather than dropping
	// WireGuard mapping until the table comes back.
	return m.wgConf
}

// setting reads one key from the panel's settings table. The bool separates
// "stored, but empty" — a deliberate blank, e.g. WireGuard switched off — from
// "could not be read", which callers fall back on differently. Best-effort by
// design: the sniffer must keep mapping against its last-known configuration if
// the panel's own table is briefly unavailable.
func (m *Mapper) setting(key string) (string, bool) {
	if m.db == nil {
		return "", false
	}
	var v string
	if err := m.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return "", false
	}
	return strings.TrimSpace(v), true
}

// loadIPP parses OpenVPN's ipp.txt ("common_name,vpn_ip,..." per line).
func loadIPP(path string, out map[string]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		ip := strings.TrimSpace(fields[1])
		if name != "" && ip != "" {
			out[ip] = name
		}
	}
	return sc.Err()
}

// loadWireGuard maps each peer's AllowedIPs host addresses to its peer name
// using the panel's single shared config parser (wireguard.ParseConfFile) — the same
// parser the WireGuard poller's registry uses — so browsing history recorded
// here and traffic accounted there always land under the SAME client name,
// including the deterministic fallback name for peers without a name comment.
func loadWireGuard(path string, out map[string]string) error {
	conf, err := wireguard.ParseConfFile(path)
	if err != nil {
		return err
	}
	for _, p := range conf.Peers {
		for _, ip := range p.AllowedIPs {
			out[ip] = p.Name
		}
	}
	return nil
}
