package db

import (
	"context"
	"database/sql"
	"errors"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"ovpnmonitor/internal/domain"
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
		// Aggregated per-(client, hostname) browsing history. One row per unique
		// (client, hostname) pair — NOT one row per visit — so storage is bounded
		// by (clients × distinct hostnames), independent of traffic volume. Populated
		// by the in-process domain sniffer (see the sniffer package) which upserts here.
		// client_name is the OpenVPN common name or WireGuard peer name (a plain
		// string, not a clients.id FK, so WireGuard peers with no clients row work too).
		//
		// root_domain is the site the hostname belongs to, as resolved by the shared
		// internal/domain package. It is stored rather than derived at query time so
		// the top-level Visited Domains list is a plain indexed GROUP BY, and so every
		// row's grouping is decided by exactly one implementation. Existing databases
		// gain the column and a backfill from ensureVisitedRootDomain below.
		`CREATE TABLE IF NOT EXISTS visited_domains (
			id          INTEGER PRIMARY KEY,
			client_name TEXT NOT NULL,
			domain      TEXT NOT NULL,
			root_domain TEXT NOT NULL DEFAULT '',
			first_seen  TEXT NOT NULL,
			last_seen   TEXT NOT NULL,
			visit_count INTEGER NOT NULL DEFAULT 1 CHECK (visit_count >= 0),
			UNIQUE (client_name, domain)
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
		`CREATE INDEX IF NOT EXISTS idx_visited_client ON visited_domains(client_name)`,
		`CREATE INDEX IF NOT EXISTS idx_visited_last_seen ON visited_domains(last_seen)`,
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
		// Domain sniffer tunables (see the sniffer package). '0' means "auto".
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('sniffer_ifaces', 'tun0,wg0')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('sniffer_wg_conf', '/etc/wireguard/wg0.conf')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('sniffer_snaplen', '1600')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('sniffer_workers', '0')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('sniffer_queue', '4096')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('sniffer_flush', '2m')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('sniffer_dedup', '60s')`,
	}
	for _, s := range stmts {
		if _, err := d.db.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	// Bring a pre-existing visited_domains table up to the current shape. Runs
	// after the CREATE TABLE above so a fresh database is a no-op.
	if err := d.ensureVisitedRootDomain(ctx); err != nil {
		return err
	}
	// Indexed on the same expression the Visited Domains queries group and
	// filter by (see rootGroupExpr), not on the bare column — an index on
	// root_domain alone would not be usable by either query.
	if _, err := d.db.ExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_visited_root
		 ON visited_domains(client_name, COALESCE(NULLIF(root_domain, ''), domain))`); err != nil {
		return err
	}
	// Ensure the admin password is stored as a bcrypt hash. This converts the
	// default 'admin' seed and any pre-existing plaintext value to a hash.
	if err := d.ensureHashedAdminPassword(ctx); err != nil {
		return err
	}
	return nil
}

// ensureVisitedRootDomain adds visited_domains.root_domain to a database created
// before the column existed, and fills it in for every row that lacks one.
//
// Databases from earlier versions hold one row per ROOT domain (the sniffer used
// to collapse the hostname before writing), so the backfill maps each stored
// value through domain.Root and the row simply becomes "the root was visited
// directly" — no history is lost, only the subdomain detail that was never
// captured. It also repairs rows written by the version whose root detection let
// private-suffix hosts such as firebaseremoteconfig.googleapis.com stand alone:
// those now resolve to googleapis.com and join the right group.
//
// A value domain.Root cannot resolve (a stored bare IP, or a name from a future
// suffix list this binary does not know) falls back to grouping under itself, so
// the row still appears in the UI instead of vanishing into an empty group.
func (d *DB) ensureVisitedRootDomain(ctx context.Context) error {
	rows, err := d.db.QueryContext(ctx, `PRAGMA table_info(visited_domains)`)
	if err != nil {
		return err
	}
	hasColumn := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "root_domain" {
			hasColumn = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasColumn {
		if _, err := d.db.ExecContext(ctx,
			`ALTER TABLE visited_domains ADD COLUMN root_domain TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}

	// Read the un-backfilled rows first, then write them in one transaction.
	// Only rows with an empty root_domain are touched, so a migration that is
	// interrupted simply resumes on the next start.
	pending, err := d.db.QueryContext(ctx,
		`SELECT id, domain FROM visited_domains WHERE root_domain = ''`)
	if err != nil {
		return err
	}
	type backfill struct {
		id   int64
		root string
	}
	var todo []backfill
	for pending.Next() {
		var id int64
		var host string
		if err := pending.Scan(&id, &host); err != nil {
			pending.Close()
			return err
		}
		root, ok := domain.Root(host)
		if !ok {
			root = domain.Normalize(host)
		}
		if root == "" {
			continue // nothing sensible to group an empty hostname under
		}
		todo = append(todo, backfill{id: id, root: root})
	}
	pending.Close()
	if err := pending.Err(); err != nil {
		return err
	}
	if len(todo) == 0 {
		return nil
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `UPDATE visited_domains SET root_domain = ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, b := range todo {
		if _, err := stmt.ExecContext(ctx, b.root, b.id); err != nil {
			return err
		}
	}
	return tx.Commit()
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
