package db

import (
	"context"
	"database/sql"
	"time"

	"ovpnmonitor/internal/model"
)

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

// ClientProtocolSplit returns a client's all-time traffic grouped into
// WireGuard sessions vs everything else, for the detail page's per-protocol
// breakdown. One query, no per-session iteration.
func (d *DB) ClientProtocolSplit(ctx context.Context, commonName string) (ovpn, wireguard int64, err error) {
	err = d.db.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(CASE WHEN s.protocol != 'wireguard' THEN s.bytes_received + s.bytes_sent ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN s.protocol  = 'wireguard' THEN s.bytes_received + s.bytes_sent ELSE 0 END), 0)
		FROM sessions s
		JOIN clients c ON c.id = s.client_id
		WHERE c.common_name = ?`, commonName).Scan(&ovpn, &wireguard)
	return
}

// CutoffFor returns the lower-bound timestamp for a traffic filter together
// with the filter kind, which selects the session JOIN condition (see
// joinCondition). An unbounded filter (e.g. "all") yields empty strings.
func CutoffFor(filter string) (cutoff, kind string) {
	now := time.Now()
	switch filter {
	case "today":
		return now.Format("2006-01-02") + " 00:00:00", "today"
	case "week":
		return now.AddDate(0, 0, -7).Format("2006-01-02 15:04:05"), "week"
	case "month":
		return now.AddDate(0, -1, 0).Format("2006-01-02 15:04:05"), "month"
	default:
		return "", ""
	}
}

// joinCondition returns the session LEFT JOIN predicate for a filter kind.
// Both bounded kinds bind the cutoff timestamp twice. The returned fragment is
// a fixed internal constant (no user input), so concatenating it is injection-safe.
func joinCondition(kind string) string {
	switch kind {
	case "today":
		// Today's window: include sessions started today, still-open sessions,
		// and sessions that ended today. A still-open session that began before
		// midnight only over-counts its (small) pre-midnight portion.
		return ` AND (s.connected_since >= ? OR s.disconnected_at IS NULL OR s.disconnected_at >= ?)`
	case "week", "month":
		// Longer windows: include sessions that started within the window, or
		// closed sessions that ended within it. Deliberately exclude still-open
		// sessions that began before the window, whose full cumulative bytes
		// (potentially weeks of history) would otherwise be counted.
		return ` AND (s.connected_since >= ? OR (s.disconnected_at IS NOT NULL AND s.disconnected_at >= ?))`
	default:
		return ""
	}
}

func (d *DB) QueryClients(ctx context.Context, filter string) ([]model.Client, error) {
	cutoff, kind := CutoffFor(filter)

	query := `
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
		LEFT JOIN sessions s ON s.client_id = c.id` + joinCondition(kind) + `
		GROUP BY c.id
		ORDER BY total_traffic DESC`

	var (
		rows *sql.Rows
		err  error
	)
	if cutoff != "" {
		rows, err = d.db.QueryContext(ctx, query, cutoff, cutoff)
	} else {
		rows, err = d.db.QueryContext(ctx, query)
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
		c.BytesReceivedReadable = FormatBytes(c.BytesReceived)
		c.BytesSentReadable = FormatBytes(c.BytesSent)
		c.TotalTrafficReadable = FormatBytes(c.TotalTraffic)
		c.ConnectedSinceEpoch = parseLocalEpoch(c.ConnectedSince)
		c.LastSeenEpoch = parseLocalEpoch(c.LastSeen)
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
	c.BytesReceivedReadable = FormatBytes(c.BytesReceived)
	c.BytesSentReadable = FormatBytes(c.BytesSent)
	c.TotalTrafficReadable = FormatBytes(c.TotalTraffic)
	c.ConnectedSinceEpoch = parseLocalEpoch(c.ConnectedSince)
	c.LastSeenEpoch = parseLocalEpoch(c.LastSeen)
	return &c, nil
}

// ClientByName returns a client's all-time aggregate keyed on common name,
// including the last-known real (public) address. Used by the client detail page.
func (d *DB) ClientByName(ctx context.Context, commonName string) (*model.Client, error) {
	const q = `
		SELECT
			c.common_name,
			c.real_address,
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
	var c model.Client
	err := d.db.QueryRowContext(ctx, q, commonName).Scan(
		&c.CommonName, &c.RealAddress, &c.VPNAddress,
		&c.BytesReceived, &c.BytesSent,
		&c.TotalTraffic, &c.ConnectedSince, &c.LastSeen,
	)
	if err != nil {
		return nil, err
	}
	c.BytesReceivedReadable = FormatBytes(c.BytesReceived)
	c.BytesSentReadable = FormatBytes(c.BytesSent)
	c.TotalTrafficReadable = FormatBytes(c.TotalTraffic)
	c.ConnectedSinceEpoch = parseLocalEpoch(c.ConnectedSince)
	c.LastSeenEpoch = parseLocalEpoch(c.LastSeen)
	return &c, nil
}

func (d *DB) ClientStatsByName(ctx context.Context, commonName, cutoff, kind string) (*model.Client, error) {
	query := `
		SELECT
			c.common_name,
			c.vpn_address,
			COALESCE(SUM(s.bytes_received), 0),
			COALESCE(SUM(s.bytes_sent), 0),
			COALESCE(SUM(s.bytes_received + s.bytes_sent), 0),
			COALESCE(MAX(s.connected_since), ''),
			c.last_seen
		FROM clients c
		LEFT JOIN sessions s ON s.client_id = c.id` + joinCondition(kind) + `
		WHERE c.common_name = ?
		GROUP BY c.id`
	var row *sql.Row
	if cutoff != "" {
		row = d.db.QueryRowContext(ctx, query, cutoff, cutoff, commonName)
	} else {
		row = d.db.QueryRowContext(ctx, query, commonName)
	}
	var c model.Client
	if err := row.Scan(
		&c.CommonName, &c.VPNAddress,
		&c.BytesReceived, &c.BytesSent,
		&c.TotalTraffic, &c.ConnectedSince, &c.LastSeen,
	); err != nil {
		return nil, err
	}
	c.BytesReceivedReadable = FormatBytes(c.BytesReceived)
	c.BytesSentReadable = FormatBytes(c.BytesSent)
	c.TotalTrafficReadable = FormatBytes(c.TotalTraffic)
	c.ConnectedSinceEpoch = parseLocalEpoch(c.ConnectedSince)
	c.LastSeenEpoch = parseLocalEpoch(c.LastSeen)
	return &c, nil
}

// rootGroupExpr is the grouping key of the Visited Domains list: a row's stored
// root_domain, falling back to the hostname itself. The fallback only fires for
// a row the backfill could not resolve (see ensureVisitedRootDomain); it groups
// such a row under itself rather than silently dropping it into an empty bucket.
const rootGroupExpr = `COALESCE(NULLIF(root_domain, ''), domain)`

// QueryVisitedRootDomains returns one row per ROOT domain the client visited,
// newest activity first. Each row's first_seen is the earliest and last_seen the
// latest across every hostname under that root, and visit_count is their sum —
// including the root itself when it was browsed directly.
//
// MIN/MAX over the timestamp columns is a lexicographic comparison, which is
// exactly chronological for the fixed "YYYY-MM-DD HH:MM:SS" format every writer
// uses (the same property the sniffer's flush upsert relies on).
//
// The result is bounded by the number of distinct root domains the client has
// visited, so callers can safely paginate on the client.
func (d *DB) QueryVisitedRootDomains(ctx context.Context, clientName string) ([]model.VisitedDomain, error) {
	q := `
		SELECT ` + rootGroupExpr + ` AS root,
		       MIN(first_seen), MAX(last_seen), SUM(visit_count),
		       COUNT(*), GROUP_CONCAT(domain, ' ')
		FROM visited_domains
		WHERE client_name = ?
		GROUP BY root
		ORDER BY MAX(last_seen) DESC`
	rows, err := d.db.QueryContext(ctx, q, clientName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.VisitedDomain
	for rows.Next() {
		var v model.VisitedDomain
		var hostnames sql.NullString
		if err := rows.Scan(&v.Domain, &v.FirstSeen, &v.LastSeen, &v.VisitCount,
			&v.SubdomainCount, &hostnames); err != nil {
			return nil, err
		}
		v.Hostnames = hostnames.String
		v.FirstSeenEpoch = parseLocalEpoch(v.FirstSeen)
		v.LastSeenEpoch = parseLocalEpoch(v.LastSeen)
		out = append(out, v)
	}
	return out, rows.Err()
}

// QueryVisitedSubdomains returns the individual hostname rows folded into one
// root domain of one client, newest activity first — the detail behind a single
// row of QueryVisitedRootDomains. The root domain itself is included when it was
// visited directly, since it is stored like any other hostname.
func (d *DB) QueryVisitedSubdomains(ctx context.Context, clientName, rootDomain string) ([]model.VisitedDomain, error) {
	q := `
		SELECT domain, first_seen, last_seen, visit_count
		FROM visited_domains
		WHERE client_name = ? AND ` + rootGroupExpr + ` = ?
		ORDER BY last_seen DESC`
	rows, err := d.db.QueryContext(ctx, q, clientName, rootDomain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.VisitedDomain
	for rows.Next() {
		var v model.VisitedDomain
		if err := rows.Scan(&v.Domain, &v.FirstSeen, &v.LastSeen, &v.VisitCount); err != nil {
			return nil, err
		}
		v.FirstSeenEpoch = parseLocalEpoch(v.FirstSeen)
		v.LastSeenEpoch = parseLocalEpoch(v.LastSeen)
		out = append(out, v)
	}
	return out, rows.Err()
}

// PurgeVisitedDomainsOlderThan deletes aggregated domain rows whose last_seen is
// older than the retention window, returning the number of rows removed. Used by
// the daily cleanup job so browsing history is kept for a bounded period only.
func (d *DB) PurgeVisitedDomainsOlderThan(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention).Format("2006-01-02 15:04:05")
	res, err := d.db.ExecContext(ctx,
		`DELETE FROM visited_domains WHERE last_seen < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) SumAllTraffic(ctx context.Context) (sent, recv uint64, err error) {
	const q = `SELECT COALESCE(SUM(bytes_sent), 0), COALESCE(SUM(bytes_received), 0) FROM sessions`
	err = d.db.QueryRowContext(ctx, q).Scan(&sent, &recv)
	return
}

// AllClientNames returns the common_name of every row in the clients table.
//
// Rows are pruned by the revoked-client reaper (see DeleteClientData and
// main.reapRevokedClients) once a name leaves BOTH validity sources (the
// certificate whitelist and the WireGuard peer registry), but that runs on an
// interval — so between a removal and the next reap pass this list can still
// hold a just-removed name. Callers therefore continue to intersect it with the
// union of both sources to exclude such clients from counts and listings; the
// reaper then removes them entirely on its next tick.
func (d *DB) AllClientNames(ctx context.Context) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT common_name FROM clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// DeleteClientData permanently removes every row belonging to a single client
// across all per-client tables — sessions, visited_domains and clients — in one
// transaction, returning the number of rows deleted from each for audit logging.
// It is the cleanup counterpart to the append-only write path: once a client's
// certificate is revoked or removed, its owner's data is purged outright rather
// than kept and filtered at read time, so the database does not grow without bound.
//
// sessions is deleted explicitly (rather than left to the clients→sessions
// ON DELETE CASCADE) for two reasons: the exact per-table count is needed for the
// audit log, and it removes any dependence on the foreign_keys pragma being enabled
// on the executing connection. visited_domains is keyed by client_name (a plain
// string, not a foreign key), so it must always be deleted explicitly.
func (d *DB) DeleteClientData(ctx context.Context, name string) (sessionRows, domainRows, clientRows int64, err error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, 0, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`DELETE FROM sessions WHERE client_id IN (SELECT id FROM clients WHERE common_name = ?)`, name)
	if err != nil {
		return 0, 0, 0, err
	}
	sessionRows, _ = res.RowsAffected()

	res, err = tx.ExecContext(ctx,
		`DELETE FROM visited_domains WHERE client_name = ?`, name)
	if err != nil {
		return 0, 0, 0, err
	}
	domainRows, _ = res.RowsAffected()

	// WireGuard counter baselines are keyed by pubkey but carry the peer name;
	// deleting them here keeps the state table from accumulating rows for
	// removed peers. Not separately counted — it is poller bookkeeping, not
	// user-visible data.
	if _, err = tx.ExecContext(ctx,
		`DELETE FROM wg_peer_state WHERE name = ?`, name); err != nil {
		return 0, 0, 0, err
	}

	res, err = tx.ExecContext(ctx,
		`DELETE FROM clients WHERE common_name = ?`, name)
	if err != nil {
		return 0, 0, 0, err
	}
	clientRows, _ = res.RowsAffected()

	if err := tx.Commit(); err != nil {
		return 0, 0, 0, err
	}
	return sessionRows, domainRows, clientRows, nil
}
