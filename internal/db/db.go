package db

import (
	"context"
	"database/sql"
	"errors"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	db *sql.DB

	// absent tracks, per client_id, the number of consecutive valid
	// (END-marker-confirmed) reads in which the client was missing. A session is
	// only closed once this reaches 2, so a single missed read can't churn
	// sessions. Guarded by mu; only ProcessLogEntries / CloseAllOpenSessions
	// touch it.
	mu     sync.Mutex
	absent map[int64]int
}

func New(sqldb *sql.DB) *DB { return &DB{db: sqldb, absent: make(map[int64]int)} }

func (d *DB) Migrate(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return err
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			id           INTEGER PRIMARY KEY,
			common_name  TEXT NOT NULL UNIQUE,
			vpn_address  TEXT NOT NULL DEFAULT '',
			real_address TEXT NOT NULL DEFAULT '',
			last_seen    TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id              INTEGER PRIMARY KEY,
			client_id       INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
			connected_since TEXT NOT NULL,
			disconnected_at TEXT,
			bytes_received  INTEGER NOT NULL DEFAULT 0 CHECK (bytes_received >= 0),
			bytes_sent      INTEGER NOT NULL DEFAULT 0 CHECK (bytes_sent >= 0),
			real_address    TEXT NOT NULL DEFAULT '',
			vpn_address     TEXT NOT NULL DEFAULT '',
			protocol        TEXT NOT NULL DEFAULT '',
			UNIQUE (client_id, connected_since, protocol)
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT ''
		)`,
		// Persisted WireGuard poller state: the last raw kernel counters applied
		// per peer. WireGuard counters are volatile (they reset to zero on any
		// interface restart or reboot), so sessions are built from deltas against
		// this baseline. Rows are written in the same transaction as the session
		// increment they baseline, which is what makes the delta math crash-safe.
		`CREATE TABLE IF NOT EXISTS wg_peer_state (
			pubkey     TEXT PRIMARY KEY,
			name       TEXT NOT NULL,
			last_rx    INTEGER NOT NULL DEFAULT 0,
			last_tx    INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_client_id ON sessions(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_connected_since ON sessions(connected_since)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_disconnected_at ON sessions(disconnected_at)`,
		// One open session per client PER FAMILY (WireGuard vs everything else):
		// a person online via OpenVPN and WireGuard simultaneously legitimately
		// holds two open sessions, so the uniqueness key includes the boolean
		// expression (protocol = 'wireguard') rather than client_id alone.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_one_open_session_per_client ON sessions(client_id, (protocol = 'wireguard')) WHERE disconnected_at IS NULL`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('addr', '0.0.0.0:80')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_user', 'admin')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_pass', 'admin')`,
		// Shared refresh cadence for BOTH VPN systems: the WireGuard poller's
		// tick and the OpenVPN watcher's resync tick (fsnotify still reacts to
		// status-file writes immediately, in between ticks).
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('poll_interval', '10s')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('openvpn_status_log', '/var/log/openvpn/status.log')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('openvpn_cert_dir', '/etc/openvpn/server/easy-rsa/pki/issued')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('openvpn_ipp_file', '/etc/openvpn/server/ipp.txt')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('openvpn_server_config', '/etc/openvpn/server/server.conf')`,
		// WireGuard poller (see the wireguard package). Blank wireguard_conf disables
		// WireGuard monitoring entirely.
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('wireguard_conf', '/etc/wireguard/wg0.conf')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('wireguard_interface', 'wg0')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('wireguard_handshake_timeout', '180s')`,
	}
	for _, s := range stmts {
		if _, err := d.db.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	// Ensure the admin password is stored as a bcrypt hash. This converts the
	// default 'admin' seed and any pre-existing plaintext value to a hash.
	if err := d.ensureHashedAdminPassword(ctx); err != nil {
		return err
	}
	return nil
}

// ensureHashedAdminPassword migrates a plaintext admin_pass to a bcrypt hash.
// A value that is already a valid bcrypt hash is left untouched.
func (d *DB) ensureHashedAdminPassword(ctx context.Context) error {
	var stored string
	err := d.db.QueryRowContext(ctx,
		`SELECT value FROM settings WHERE key = 'admin_pass'`).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := bcrypt.Cost([]byte(stored)); err == nil {
		return nil // already a bcrypt hash
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(stored), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = d.db.ExecContext(ctx,
		`UPDATE settings SET value = ? WHERE key = 'admin_pass'`, string(hash))
	return err
}

func (d *DB) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	vals := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		vals[k] = v
	}
	return vals, rows.Err()
}

func (d *DB) SaveSetting(ctx context.Context, key, value string) error {
	_, err := d.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)`, key, value)
	return err
}
