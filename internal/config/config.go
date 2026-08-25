package config

import (
	"context"
	"database/sql"
	"strconv"
	"time"
)

type Options struct {
	Addr         string
	AdminUser    string
	AdminPass    string
	Log          string
	CertsDir     string
	IPPFile      string
	ServerConfig string
	SessionTTL   time.Duration

	// PollInterval is the shared refresh cadence for BOTH VPN systems: the
	// WireGuard poller ticks on it and the OpenVPN watcher uses it as its
	// guaranteed resync interval (fsnotify events still apply sooner). Zero
	// (missing or malformed setting) is replaced with the default in main.
	PollInterval time.Duration

	// WireGuard poller (see the wireguard package). An empty WGConf disables
	// WireGuard monitoring; a zero duration and an empty interface are replaced
	// with defaults in main, so a malformed setting degrades to the default
	// rather than a broken poller.
	WGConf             string
	WGIface            string
	WGHandshakeTimeout time.Duration

	// Systemd units restarted by the IPv6 toggle (see the ipv6 package). There
	// are no DB settings for these; empty values are replaced with the defaults
	// in main, following the same degrade-to-default pattern.
	WGUnit   string
	OVPNUnit string

	// Domain sniffer tunables (see the sniffer package). Zero/empty values are
	// replaced with defaults by sniffer.Config.applyDefaults, so a missing or
	// malformed setting can never disable capture outright.
	SnifferIfaces  string
	SnifferWGConf  string
	SnifferSnaplen int
	SnifferWorkers int
	SnifferQueue   int
	SnifferFlush   time.Duration
	SnifferDedup   time.Duration
}

func LoadFromDB(ctx context.Context, sqldb *sql.DB) (Options, error) {
	rows, err := sqldb.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return Options{}, err
	}
	defer rows.Close()
	vals := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return Options{}, err
		}
		vals[k] = v
	}
	if err := rows.Err(); err != nil {
		return Options{}, err
	}
	return Options{
		Addr:         vals["addr"],
		AdminUser:    vals["admin_user"],
		AdminPass:    vals["admin_pass"],
		Log:          vals["openvpn_status_log"],
		CertsDir:     vals["openvpn_cert_dir"],
		IPPFile:      vals["openvpn_ipp_file"],
		ServerConfig: vals["openvpn_server_config"],
		SessionTTL:   24 * time.Hour,

		PollInterval: durationSetting(vals["poll_interval"]),

		WGConf:             vals["wireguard_conf"],
		WGIface:            vals["wireguard_interface"],
		WGHandshakeTimeout: durationSetting(vals["wireguard_handshake_timeout"]),

		SnifferIfaces:  vals["sniffer_ifaces"],
		SnifferWGConf:  vals["sniffer_wg_conf"],
		SnifferSnaplen: atoiSetting(vals["sniffer_snaplen"]),
		SnifferWorkers: atoiSetting(vals["sniffer_workers"]),
		SnifferQueue:   atoiSetting(vals["sniffer_queue"]),
		SnifferFlush:   durationSetting(vals["sniffer_flush"]),
		SnifferDedup:   durationSetting(vals["sniffer_dedup"]),
	}, nil
}

// atoiSetting parses an integer setting, returning 0 (= "use default") when
// the value is missing or not a number.
func atoiSetting(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// durationSetting parses a duration setting like "2m" or "60s", returning 0
// (= "use default") when the value is missing or malformed.
func durationSetting(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
