package db

import (
	"context"
	"time"

	"ovpnmonitor/internal/model"
)

// CloseAllOpenSessions marks every currently-open OpenVPN-family session as
// disconnected. Used when OpenVPN appears unresponsive so clients don't linger
// as "online". WireGuard sessions are excluded: they are owned by the wg
// poller, and an OpenVPN outage says nothing about WireGuard connectivity.
func (d *DB) CloseAllOpenSessions(ctx context.Context) error {
	_, err := d.db.ExecContext(ctx,
		`UPDATE sessions SET disconnected_at = datetime('now','localtime') WHERE disconnected_at IS NULL AND protocol != 'wireguard'`)
	if err == nil {
		// Every OpenVPN client is now offline; forget any pending absence counts
		// (the absent map only ever tracks OpenVPN-session absence).
		d.mu.Lock()
		d.absent = make(map[int64]int)
		d.mu.Unlock()
	}
	return err
}

func (d *DB) ProcessLogEntries(ctx context.Context, entries []model.LogEntry) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

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

		// Close any still-open session for this client from a DIFFERENT connection
		// (different connected_since OR a different protocol at the same second —
		// e.g. a UDP↔TCP switch). Keeps the one-open-session-per-client invariant
		// before we (re)open the current one. WireGuard sessions are explicitly
		// exempt: they always have a "different protocol" and would otherwise be
		// killed on every OpenVPN log pass, but they belong to the wg poller and
		// coexisting open OVPN + WG sessions are a legal state.
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET disconnected_at=? WHERE client_id=? AND disconnected_at IS NULL AND protocol != 'wireguard' AND (connected_since != ? OR protocol != ?)`,
			now, clientID, entry.ConnectedSince, entry.Protocol); err != nil {
			return err
		}

		// Idempotent upsert keyed on (client_id, connected_since, protocol). A
		// reappearing connection updates its own row instead of spawning a new one,
		// so a false disconnect can never re-record the connection's cumulative
		// bytes. Bytes only ever ratchet up (MAX), so a transient low reading is
		// ignored rather than splitting the session. disconnected_at is cleared so a
		// session that was falsely closed simply reopens on its existing row.
		// protocol is part of the identity, so it is not overwritten on conflict.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO sessions (client_id, connected_since, bytes_received, bytes_sent, real_address, vpn_address, protocol)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(client_id, connected_since, protocol) DO UPDATE SET
				bytes_received  = MAX(sessions.bytes_received, excluded.bytes_received),
				bytes_sent      = MAX(sessions.bytes_sent, excluded.bytes_sent),
				real_address    = excluded.real_address,
				vpn_address     = excluded.vpn_address,
				disconnected_at = NULL`,
			clientID, entry.ConnectedSince, entry.BytesReceived, entry.BytesSent,
			entry.RealAddress, entry.VPNAddress, entry.Protocol); err != nil {
			return err
		}
	}

	// Only OpenVPN-family sessions feed the absence counter: a client that is
	// online via WireGuard alone is legitimately absent from the OpenVPN status
	// log forever, and counting it here would churn the absent map (and, before
	// the protocol scoping below, would have closed its WG session).
	openRows, err := tx.QueryContext(ctx,
		`SELECT DISTINCT client_id FROM sessions WHERE disconnected_at IS NULL AND protocol != 'wireguard'`)
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

	// Only close a client's session after it has been absent from 2 consecutive
	// valid reads. This block reaches ProcessLogEntries only on END-marker-confirmed
	// reads (partial reads are rejected upstream), so absence here is real, not a
	// torn-read artifact. A single missed/edge read no longer churns sessions.
	d.mu.Lock()
	for _, id := range openClientIDs {
		if seenClientIDs[id] {
			delete(d.absent, id)
			continue
		}
		d.absent[id]++
		if d.absent[id] >= 2 {
			// Scoped to non-WireGuard: disconnecting from OpenVPN while staying
			// on WireGuard must not close the WG session.
			if _, err := tx.ExecContext(ctx,
				`UPDATE sessions SET disconnected_at=? WHERE client_id=? AND disconnected_at IS NULL AND protocol != 'wireguard'`,
				now, id); err != nil {
				d.mu.Unlock()
				return err
			}
			delete(d.absent, id)
		}
	}
	d.mu.Unlock()

	return tx.Commit()
}
