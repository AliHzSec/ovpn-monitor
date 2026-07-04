package sniffer

import (
	"bufio"
	"database/sql"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Mapper resolves a VPN source IP to the client/peer name it belongs to, for
// BOTH OpenVPN and WireGuard, mirroring the mapping mechanisms the panel already
// relies on:
//
//   - OpenVPN: the ipp.txt persistence file ("name,ip,..."), the same file the
//     panel's ipp package parses. Its path is read from the panel's settings
//     table when available, else from the -ipp flag.
//   - WireGuard: the wg config file, associating each [Peer]'s AllowedIPs with a
//     human name taken from the surrounding comment markers written by the
//     common install scripts ("# BEGIN_PEER <name>" or "# Name = <name>").
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
	next := make(map[string]string)

	ippPath := m.ippPath
	if p := m.settingIPPPath(); p != "" {
		ippPath = p // prefer the panel's configured path
	}
	if ippPath != "" {
		if err := loadIPP(ippPath, next); err != nil && !os.IsNotExist(err) {
			m.logger.Warn("read ipp.txt failed", "path", ippPath, "err", err)
		}
	}
	if m.wgConf != "" {
		if err := loadWireGuard(m.wgConf, next); err != nil && !os.IsNotExist(err) {
			m.logger.Warn("read wireguard conf failed", "path", m.wgConf, "err", err)
		}
	}

	m.mu.Lock()
	m.ipToName = next
	m.mu.Unlock()
	m.logger.Info("ip→client map refreshed", "entries", len(next))
}

// settingIPPPath reads openvpn_ipp_file from the panel's settings table, so the
// sniffer follows whatever the admin configured in the panel. Best-effort.
func (m *Mapper) settingIPPPath() string {
	if m.db == nil {
		return ""
	}
	var v string
	err := m.db.QueryRow(`SELECT value FROM settings WHERE key='openvpn_ipp_file'`).Scan(&v)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
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

// loadWireGuard parses a wg config, mapping each peer's AllowedIPs host address
// to the peer name found in the surrounding comment. It recognises the two
// conventions produced by the popular install scripts:
//
//	# BEGIN_PEER alice        and        # Name = alice
//	[Peer]                                [Peer]
//	PublicKey = ...                       PublicKey = ...
//	AllowedIPs = 10.7.0.2/32              AllowedIPs = 10.7.0.2/32
//	# END_PEER alice
//
// A peer with no discoverable name is mapped under its first AllowedIP so its
// traffic is still attributable rather than silently dropped.
func loadWireGuard(path string, out map[string]string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var pendingName string // name seen just before/inside the current [Peer]
	inPeer := false

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "# BEGIN_PEER"):
			pendingName = strings.TrimSpace(strings.TrimPrefix(line, "# BEGIN_PEER"))
		case strings.HasPrefix(line, "#") && strings.Contains(strings.ToLower(line), "name"):
			// "# Name = alice" or "# name: alice"
			if i := strings.IndexAny(line, "=:"); i >= 0 {
				pendingName = strings.TrimSpace(line[i+1:])
			}
		case strings.EqualFold(line, "[Peer]"):
			inPeer = true
		case strings.EqualFold(line, "[Interface]"):
			inPeer = false
			pendingName = ""
		case inPeer && strings.HasPrefix(strings.ToLower(line), "allowedips"):
			if i := strings.IndexByte(line, '='); i >= 0 {
				for _, cidr := range strings.Split(line[i+1:], ",") {
					ip := strings.TrimSpace(cidr)
					if j := strings.IndexByte(ip, '/'); j >= 0 {
						ip = ip[:j]
					}
					if ip == "" {
						continue
					}
					name := pendingName
					if name == "" {
						name = ip
					}
					out[ip] = name
				}
			}
		}
	}
	return sc.Err()
}
