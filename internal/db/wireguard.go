package db

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"ovpnmonitor/internal/model"
)

// CloseAllWGSessions is the WireGuard counterpart of CloseAllOpenSessions,
// used by the wg poller when WireGuard itself appears down (repeated dump
// failures) so its peers don't linger as "online" with open sessions.
func (d *DB) CloseAllWGSessions(ctx context.Context) error {
	_, err := d.db.ExecContext(ctx,
		`UPDATE sessions SET disconnected_at = datetime('now','localtime') WHERE disconnected_at IS NULL AND protocol = 'wireguard'`)
	return err
}

// ── WireGuard poller persistence ─────────────────────────────────────────────
//
// WireGuard sessions are synthetic: the kernel exposes only cumulative,
// volatile counters, so the wg poller computes per-poll byte DELTAS and these
// methods apply them. They deliberately do not reuse ProcessLogEntries — its
// MAX-ratchet upsert is built for OpenVPN's cumulative counters and would be
// wrong for increments. Every method that applies a delta persists the raw
// kernel counters (wg_peer_state) in the SAME transaction, so a crash between
// poll and commit can never double-apply: either the delta and its new
// baseline both land, or neither does.

// upsertWGPeerState writes the peer's raw-counter baseline inside tx.
func upsertWGPeerState(ctx context.Context, tx *sql.Tx, p model.WGPeerDelta, now string) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO wg_peer_state (pubkey, name, last_rx, last_tx, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(pubkey) DO UPDATE SET
			name = excluded.name,
			last_rx = excluded.last_rx,
			last_tx = excluded.last_tx,
			updated_at = excluded.updated_at`,
		p.PubKey, p.Name, p.LastRX, p.LastTX, now)
	return err
}

// WGPeerStates loads every persisted peer baseline, keyed by public key. The
// poller reads this once at startup and mirrors it in memory afterwards.
func (d *DB) WGPeerStates(ctx context.Context) (map[string]model.WGPeerState, error) {
	rows, err := d.db.QueryContext(ctx,
		`SELECT pubkey, name, last_rx, last_tx FROM wg_peer_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := make(map[string]model.WGPeerState)
	for rows.Next() {
		var s model.WGPeerState
		if err := rows.Scan(&s.PubKey, &s.Name, &s.LastRX, &s.LastTX); err != nil {
			return nil, err
		}
		states[s.PubKey] = s
	}
	return states, rows.Err()
}

// SaveWGPeerState persists a peer's counter baseline WITHOUT touching any
// session. Used on the first sighting of an offline peer: its historical
// counters predate monitoring and there is no session to attribute them to,
// so they are recorded as the baseline and never credited.
func (d *DB) SaveWGPeerState(ctx context.Context, p model.WGPeerDelta) error {
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := d.db.ExecContext(ctx,
		`INSERT INTO wg_peer_state (pubkey, name, last_rx, last_tx, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(pubkey) DO UPDATE SET
			name = excluded.name,
			last_rx = excluded.last_rx,
			last_tx = excluded.last_tx,
			updated_at = excluded.updated_at`,
		p.PubKey, p.Name, p.LastRX, p.LastTX, now)
	return err
}

// ApplyWGPeerDelta records one poll of an ONLINE WireGuard peer in a single
// transaction: upsert the client row, refresh its addresses/last_seen, ensure
// an open WG session exists (opening one with connected_since = now on the
// offline→online transition), increment the session's bytes by the deltas, and
// persist the new counter baseline.
//
// Reopening after a same-second close hits the UNIQUE(client_id,
// connected_since, protocol) key; the conflict arm ADDS the deltas (they are
// increments, never cumulative values, so addition cannot double-count) and
// clears disconnected_at to resume the row.
func (d *DB) ApplyWGPeerDelta(ctx context.Context, p model.WGPeerDelta) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Format("2006-01-02 15:04:05")

	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO clients (common_name) VALUES (?)`, p.Name); err != nil {
		return err
	}
	// Endpoint can be temporarily unknown to the kernel ("(none)"); keep the
	// last known real address rather than blanking it.
	if _, err := tx.ExecContext(ctx,
		`UPDATE clients SET
			real_address = CASE WHEN ? = '' THEN real_address ELSE ? END,
			vpn_address  = CASE WHEN ? = '' THEN vpn_address ELSE ? END,
			last_seen    = ?
		 WHERE common_name = ?`,
		p.RealAddress, p.RealAddress, p.VPNAddress, p.VPNAddress, now, p.Name); err != nil {
		return err
	}

	var clientID int64
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM clients WHERE common_name = ?`, p.Name).Scan(&clientID); err != nil {
		return err
	}

	var sessionID int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM sessions WHERE client_id = ? AND protocol = 'wireguard' AND disconnected_at IS NULL`,
		clientID).Scan(&sessionID)
	switch {
	case err == nil:
		// Open session (possibly surviving a panel restart): resume incrementing.
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET
				bytes_received = bytes_received + ?,
				bytes_sent     = bytes_sent + ?,
				real_address   = CASE WHEN ? = '' THEN real_address ELSE ? END,
				vpn_address    = CASE WHEN ? = '' THEN vpn_address ELSE ? END
			 WHERE id = ?`,
			p.DeltaDown, p.DeltaUp, p.RealAddress, p.RealAddress,
			p.VPNAddress, p.VPNAddress, sessionID); err != nil {
			return err
		}
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO sessions (client_id, connected_since, bytes_received, bytes_sent, real_address, vpn_address, protocol)
			 VALUES (?, ?, ?, ?, ?, ?, 'wireguard')
			 ON CONFLICT(client_id, connected_since, protocol) DO UPDATE SET
				bytes_received  = sessions.bytes_received + excluded.bytes_received,
				bytes_sent      = sessions.bytes_sent + excluded.bytes_sent,
				real_address    = excluded.real_address,
				vpn_address     = excluded.vpn_address,
				disconnected_at = NULL`,
			clientID, now, p.DeltaDown, p.DeltaUp, p.RealAddress, p.VPNAddress); err != nil {
			return err
		}
	default:
		return err
	}

	if err := upsertWGPeerState(ctx, tx, p, now); err != nil {
		return err
	}
	return tx.Commit()
}

// CloseWGPeerSession ends a peer's open WG session on the online→offline
// transition: any trailing deltas from this final poll are folded into the
// session before it is marked disconnected, and the counter baseline is
// persisted, all in one transaction.
func (d *DB) CloseWGPeerSession(ctx context.Context, p model.WGPeerDelta) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Format("2006-01-02 15:04:05")

	var clientID int64
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM clients WHERE common_name = ?`, p.Name).Scan(&clientID)
	switch {
	case err == nil:
		if p.DeltaDown > 0 || p.DeltaUp > 0 {
			if _, err := tx.ExecContext(ctx,
				`UPDATE sessions SET bytes_received = bytes_received + ?, bytes_sent = bytes_sent + ?
				 WHERE client_id = ? AND protocol = 'wireguard' AND disconnected_at IS NULL`,
				p.DeltaDown, p.DeltaUp, clientID); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE sessions SET disconnected_at = ?
			 WHERE client_id = ? AND protocol = 'wireguard' AND disconnected_at IS NULL`,
			now, clientID); err != nil {
			return err
		}
	case errors.Is(err, sql.ErrNoRows):
		// Client row already reaped: nothing to close, but the baseline must
		// still advance or the same delta would be re-derived forever.
	default:
		return err
	}

	if err := upsertWGPeerState(ctx, tx, p, now); err != nil {
		return err
	}
	return tx.Commit()
}

// ApplyWGTrailingDelta handles the rare case of counters growing while the
// peer is offline with NO open session (e.g. a few bytes landing between the
// close and the next poll). The delta is folded into the most recently closed
// WG session when one exists; otherwise it is dropped (folded=false) — a
// phantom session is never opened for it. The baseline is persisted either
// way, so a dropped delta is dropped exactly once, not re-derived every poll.
func (d *DB) ApplyWGTrailingDelta(ctx context.Context, p model.WGPeerDelta) (folded bool, err error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	now := time.Now().Format("2006-01-02 15:04:05")

	res, err := tx.ExecContext(ctx,
		`UPDATE sessions SET bytes_received = bytes_received + ?, bytes_sent = bytes_sent + ?
		 WHERE id = (
			SELECT s.id FROM sessions s
			JOIN clients c ON c.id = s.client_id
			WHERE c.common_name = ? AND s.protocol = 'wireguard' AND s.disconnected_at IS NOT NULL
			ORDER BY s.disconnected_at DESC, s.id DESC
			LIMIT 1
		 )`,
		p.DeltaDown, p.DeltaUp, p.Name)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		folded = true
	}

	if err := upsertWGPeerState(ctx, tx, p, now); err != nil {
		return false, err
	}
	return folded, tx.Commit()
}

// CloseWGSessionByName closes a client's open WG session without touching the
// counter baseline. Used when a peer disappears from the dump entirely
// (removed from the interface), where no final counters exist to fold in.
func (d *DB) CloseWGSessionByName(ctx context.Context, name string) error {
	_, err := d.db.ExecContext(ctx,
		`UPDATE sessions SET disconnected_at = datetime('now','localtime')
		 WHERE protocol = 'wireguard' AND disconnected_at IS NULL
		   AND client_id IN (SELECT id FROM clients WHERE common_name = ?)`, name)
	return err
}

// OpenWGSessionNames returns the client names holding an open WireGuard
// session. The poller seeds its in-memory online set from this at startup so
// a session left open across a panel restart is either resumed (peer still
// online) or properly closed with its trailing delta (peer went away).
func (d *DB) OpenWGSessionNames(ctx context.Context) ([]string, error) {
	rows, err := d.db.QueryContext(ctx,
		`SELECT c.common_name FROM sessions s
		 JOIN clients c ON c.id = s.client_id
		 WHERE s.protocol = 'wireguard' AND s.disconnected_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}
