package main

import (
	"context"
	"log/slog"

	"ovpnmonitor/internal/db"
	"ovpnmonitor/internal/openvpn"
	"ovpnmonitor/internal/wireguard"
)

// reapRevokedClients permanently deletes the database rows of every client that
// is no longer valid in EITHER system: its common name is absent from the
// active-certificate whitelist (revoked/expired, or .crt removed from
// pki/issued/) AND absent from the current WireGuard peer set (removed from
// wg0.conf). A name valid in either source is always kept — the two systems
// share client identity by name, so deleting on one system's absence alone
// would destroy the other system's history. This turns the panel's write path
// from append-only into self-pruning, so removed clients stop accumulating
// dead traffic history.
//
// Safety: it never acts on an untrustworthy validity set, for either source.
//
//   - Certificates: never act on an empty whitelist. A successful index.txt
//     read that parses to zero valid names is indistinguishable from a
//     transient empty/garbage read, and treating "nobody is valid" as
//     "everybody is revoked" would wipe the entire database. Because
//     RefreshLoop keeps the last-good whitelist on any read error and only
//     triggers this after a successful reload, an empty set here means the
//     file genuinely parsed empty — so we skip and log rather than risk mass
//     deletion. (A truly all-revoked server keeps its dead rows until at
//     least one valid cert exists; that is the deliberate, safe trade-off,
//     and it extends to WireGuard-only deployments with no certs at all.)
//
//   - WireGuard: never act while the registry is unhealthy — i.e. its last
//     conf read failed (including the conf vanishing after having been seen).
//     The registry keeps its last-good peer set in that state, but "last-good"
//     is not fresh enough to justify deletions, so we skip entirely rather
//     than delete a peer that may still exist in an unreadable conf. A conf
//     that never existed leaves the registry empty-but-healthy (WireGuard not
//     installed), which correctly degrades to certificate-only reaping.
func reapRevokedClients(ctx context.Context, database *db.DB, certs *openvpn.CertWhitelist, wgReg *wireguard.Registry, logger *slog.Logger) {
	valid := certs.All()
	if len(valid) == 0 {
		logger.Warn("skipping revoked-client cleanup: certificate whitelist is empty; not deleting any client data")
		return
	}
	if !wgReg.Healthy() {
		logger.Warn("skipping revoked-client cleanup: wireguard conf could not be read; not deleting any client data")
		return
	}
	validSet := make(map[string]bool, len(valid))
	for _, n := range valid {
		validSet[n] = true
	}
	for _, n := range wgReg.Names() {
		validSet[n] = true
	}

	names, err := database.AllClientNames(ctx)
	if err != nil {
		logger.Warn("revoked-client cleanup: could not list clients", "err", err)
		return
	}
	for _, name := range names {
		if validSet[name] {
			continue
		}
		sessionRows, clientRows, err := database.DeleteClientData(ctx, name)
		if err != nil {
			logger.Error("revoked-client cleanup: delete failed", "client", name, "err", err)
			continue
		}
		if clientRows > 0 || sessionRows > 0 {
			logger.Info("deleted revoked client data",
				"client", name,
				"clients_rows", clientRows,
				"sessions_rows", sessionRows)
		}
	}
}
