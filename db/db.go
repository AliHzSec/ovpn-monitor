package db

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"ovpnmonitor/model"
)

type DB struct{ db *sql.DB }

func New(sqldb *sql.DB) *DB { return &DB{db: sqldb} }

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
			vpn_address     TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_client_id ON sessions(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_connected_since ON sessions(connected_since)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_disconnected_at ON sessions(disconnected_at)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_one_open_session_per_client ON sessions(client_id) WHERE disconnected_at IS NULL`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('addr', '0.0.0.0:80')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_user', 'admin')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_pass', 'admin')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('openvpn_status_log', '/var/log/openvpn/status.log')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('openvpn_cert_dir', '/etc/openvpn/server/easy-rsa/pki/issued')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('openvpn_ipp_file', '/etc/openvpn/server/ipp.txt')`,
		`INSERT OR IGNORE INTO settings (key, value) VALUES ('openvpn_server_config', '/etc/openvpn/server/server.conf')`,
	}
	for _, s := range stmts {
		if _, err := d.db.ExecContext(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) UpsertKnownClient(ctx context.Context, name string) error {
	const s = `INSERT OR IGNORE INTO clients (common_name) VALUES (?)`
	_, err := d.db.ExecContext(ctx, s, name)
	return err
}

func (d *DB) UpdateClientVPNAddress(ctx context.Context, name, ip string) error {
	_, err := d.db.ExecContext(ctx,
		`UPDATE clients SET vpn_address = ? WHERE common_name = ?`, ip, name)
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

func (d *DB) ProcessLogEntries(ctx context.Context, entries []model.LogEntry) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Remove duplicate open sessions — keep only the newest per client.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE disconnected_at IS NULL AND id NOT IN (
			SELECT MAX(id) FROM sessions WHERE disconnected_at IS NULL GROUP BY client_id
		)`); err != nil {
		return err
	}

	now := time.Now().Format("2006-01-02 15:04:05")
	seenClientIDs := make(map[int64]bool, len(entries))

	for _, entry := range entries {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO clients (common_name) VALUES (?)`, entry.CommonName); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE clients SET real_address=?, vpn_address=?, last_seen=? WHERE common_name=?`,
			entry.RealAddress, entry.VPNAddress, now, entry.CommonName); err != nil {
			return err
		}

		var clientID int64
		if err := tx.QueryRowContext(ctx,
			`SELECT id FROM clients WHERE common_name=?`, entry.CommonName).Scan(&clientID); err != nil {
			return err
		}
		seenClientIDs[clientID] = true

		// Close any open session whose connected_since differs — client reconnected.
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET disconnected_at=? WHERE client_id=? AND disconnected_at IS NULL AND connected_since != ?`,
			now, clientID, entry.ConnectedSince); err != nil {
			return err
		}

		var sessionID int64
		var sessionBytesReceived, sessionBytesSent int64
		err := tx.QueryRowContext(ctx,
			`SELECT id, bytes_received, bytes_sent FROM sessions WHERE client_id=? AND disconnected_at IS NULL`,
			clientID).Scan(&sessionID, &sessionBytesReceived, &sessionBytesSent)

		if errors.Is(err, sql.ErrNoRows) {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO sessions (client_id, connected_since, bytes_received, bytes_sent, real_address, vpn_address)
				 VALUES (?, ?, ?, ?, ?, ?)`,
				clientID, entry.ConnectedSince, entry.BytesReceived, entry.BytesSent,
				entry.RealAddress, entry.VPNAddress); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}

		if entry.BytesReceived >= sessionBytesReceived && entry.BytesSent >= sessionBytesSent {
			if _, err := tx.ExecContext(ctx,
				`UPDATE sessions SET bytes_received=?, bytes_sent=? WHERE id=?`,
				entry.BytesReceived, entry.BytesSent, sessionID); err != nil {
				return err
			}
		} else {
			// Counter regression — close current and open a fresh session.
			if _, err := tx.ExecContext(ctx,
				`UPDATE sessions SET disconnected_at=? WHERE id=?`, now, sessionID); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO sessions (client_id, connected_since, bytes_received, bytes_sent, real_address, vpn_address)
				 VALUES (?, ?, ?, ?, ?, ?)`,
				clientID, entry.ConnectedSince, entry.BytesReceived, entry.BytesSent,
				entry.RealAddress, entry.VPNAddress); err != nil {
				return err
			}
		}
	}

	openRows, err := tx.QueryContext(ctx,
		`SELECT DISTINCT client_id FROM sessions WHERE disconnected_at IS NULL`)
	if err != nil {
		return err
	}
	var openClientIDs []int64
	for openRows.Next() {
		var id int64
		if err := openRows.Scan(&id); err != nil {
			openRows.Close()
			return err
		}
		openClientIDs = append(openClientIDs, id)
	}
	openRows.Close()
	if err := openRows.Err(); err != nil {
		return err
	}

	for _, id := range openClientIDs {
		if !seenClientIDs[id] {
			if _, err := tx.ExecContext(ctx,
				`UPDATE sessions SET disconnected_at=? WHERE client_id=? AND disconnected_at IS NULL`,
				now, id); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func CutoffFor(filter string) string {
	now := time.Now()
	switch filter {
	case "today":
		return now.Format("2006-01-02") + " 00:00:00"
	case "week":
		return now.AddDate(0, 0, -7).Format("2006-01-02 15:04:05")
	case "month":
		return now.AddDate(0, -1, 0).Format("2006-01-02 15:04:05")
	default:
		return ""
	}
}

func (d *DB) QueryClients(ctx context.Context, filter string) ([]model.Client, error) {
	cutoff := CutoffFor(filter)

	const withCutoff = `
		SELECT
			c.common_name,
			c.real_address,
			c.vpn_address,
			COALESCE(SUM(s.bytes_received), 0)                AS bytes_received,
			COALESCE(SUM(s.bytes_sent), 0)                    AS bytes_sent,
			COALESCE(SUM(s.bytes_received + s.bytes_sent), 0) AS total_traffic,
			COALESCE(MAX(s.connected_since), '')              AS connected_since,
			c.last_seen
		FROM clients c
		LEFT JOIN sessions s ON s.client_id = c.id AND s.connected_since >= ?
		GROUP BY c.id
		ORDER BY total_traffic DESC`

	const noCutoff = `
		SELECT
			c.common_name,
			c.real_address,
			c.vpn_address,
			COALESCE(SUM(s.bytes_received), 0)                AS bytes_received,
			COALESCE(SUM(s.bytes_sent), 0)                    AS bytes_sent,
			COALESCE(SUM(s.bytes_received + s.bytes_sent), 0) AS total_traffic,
			COALESCE(MAX(s.connected_since), '')              AS connected_since,
			c.last_seen
		FROM clients c
		LEFT JOIN sessions s ON s.client_id = c.id
		GROUP BY c.id
		ORDER BY total_traffic DESC`

	var (
		rows *sql.Rows
		err  error
	)
	if cutoff != "" {
		rows, err = d.db.QueryContext(ctx, withCutoff, cutoff)
	} else {
		rows, err = d.db.QueryContext(ctx, noCutoff)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []model.Client
	for rows.Next() {
		var c model.Client
		if err := rows.Scan(
			&c.CommonName, &c.RealAddress, &c.VPNAddress,
			&c.BytesReceived, &c.BytesSent,
			&c.TotalTraffic, &c.ConnectedSince, &c.LastSeen,
		); err != nil {
			return nil, err
		}
		c.BytesReceivedReadable = formatBytes(c.BytesReceived)
		c.BytesSentReadable = formatBytes(c.BytesSent)
		c.TotalTrafficReadable = formatBytes(c.TotalTraffic)
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return clients, nil
}

func (d *DB) ClientByVPNAddress(ctx context.Context, vpnAddr string) (*model.Client, error) {
	const q = `
		SELECT
			c.common_name,
			c.vpn_address,
			COALESCE(SUM(s.bytes_received), 0),
			COALESCE(SUM(s.bytes_sent), 0),
			COALESCE(SUM(s.bytes_received + s.bytes_sent), 0),
			COALESCE(MAX(s.connected_since), ''),
			c.last_seen
		FROM clients c
		LEFT JOIN sessions s ON s.client_id = c.id
		WHERE c.vpn_address = ?
		GROUP BY c.id`
	var c model.Client
	err := d.db.QueryRowContext(ctx, q, vpnAddr).Scan(
		&c.CommonName, &c.VPNAddress,
		&c.BytesReceived, &c.BytesSent,
		&c.TotalTraffic, &c.ConnectedSince, &c.LastSeen,
	)
	if err != nil {
		return nil, err
	}
	c.BytesReceivedReadable = formatBytes(c.BytesReceived)
	c.BytesSentReadable = formatBytes(c.BytesSent)
	c.TotalTrafficReadable = formatBytes(c.TotalTraffic)
	return &c, nil
}

func (d *DB) ClientStatsByName(ctx context.Context, commonName, cutoff string) (*model.Client, error) {
	const withCutoff = `
		SELECT
			c.common_name,
			c.vpn_address,
			COALESCE(SUM(s.bytes_received), 0),
			COALESCE(SUM(s.bytes_sent), 0),
			COALESCE(SUM(s.bytes_received + s.bytes_sent), 0),
			COALESCE(MAX(s.connected_since), ''),
			c.last_seen
		FROM clients c
		LEFT JOIN sessions s ON s.client_id = c.id AND s.connected_since >= ?
		WHERE c.common_name = ?
		GROUP BY c.id`
	const noCutoff = `
		SELECT
			c.common_name,
			c.vpn_address,
			COALESCE(SUM(s.bytes_received), 0),
			COALESCE(SUM(s.bytes_sent), 0),
			COALESCE(SUM(s.bytes_received + s.bytes_sent), 0),
			COALESCE(MAX(s.connected_since), ''),
			c.last_seen
		FROM clients c
		LEFT JOIN sessions s ON s.client_id = c.id
		WHERE c.common_name = ?
		GROUP BY c.id`
	var row *sql.Row
	if cutoff != "" {
		row = d.db.QueryRowContext(ctx, withCutoff, cutoff, commonName)
	} else {
		row = d.db.QueryRowContext(ctx, noCutoff, commonName)
	}
	var c model.Client
	if err := row.Scan(
		&c.CommonName, &c.VPNAddress,
		&c.BytesReceived, &c.BytesSent,
		&c.TotalTraffic, &c.ConnectedSince, &c.LastSeen,
	); err != nil {
		return nil, err
	}
	c.BytesReceivedReadable = formatBytes(c.BytesReceived)
	c.BytesSentReadable = formatBytes(c.BytesSent)
	c.TotalTrafficReadable = formatBytes(c.TotalTraffic)
	return &c, nil
}

func (d *DB) SumAllTraffic(ctx context.Context) (sent, recv uint64, err error) {
	const q = `SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0) FROM sessions`
	err = d.db.QueryRowContext(ctx, q).Scan(&sent, &recv)
	return
}

func (d *DB) CountClients(ctx context.Context) (int, error) {
	var count int
	err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM clients`).Scan(&count)
	return count, err
}

func formatBytes(bytes int64) string {
	const (
		KB = 1 << 10
		MB = 1 << 20
		GB = 1 << 30
		TB = 1 << 40
	)
	switch {
	case bytes >= TB:
		return strconv.FormatFloat(float64(bytes)/TB, 'f', 2, 64) + " TB"
	case bytes >= GB:
		return strconv.FormatFloat(float64(bytes)/GB, 'f', 2, 64) + " GB"
	case bytes >= MB:
		return strconv.FormatFloat(float64(bytes)/MB, 'f', 2, 64) + " MB"
	case bytes >= KB:
		return strconv.FormatFloat(float64(bytes)/KB, 'f', 2, 64) + " KB"
	default:
		return strconv.FormatInt(bytes, 10) + " B"
	}
}
