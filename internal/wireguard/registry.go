package wireguard

import (
	"context"
	"log/slog"
	"maps"
	"net"
	"os"
	"sync"
	"time"

	"ovpnmonitor/internal/db"
)

// Registry is the thread-safe store of the CURRENT WireGuard peer set parsed
// from the server config — the WireGuard analogue of openvpn.CertWhitelist. It is one of
// the two validity sources the revoked-client reaper unions (a client name
// present in either the certificate whitelist or here must never be deleted),
// so it carries the same contract: a failed read keeps the last-good set and
// marks the registry unhealthy, and the reaper skips deletions while
// unhealthy.
type Registry struct {
	mu        sync.RWMutex
	byPubKey  map[string]string // pubkey → name
	nameByIP  map[string]string // VPN host IP (v4 and v6) → name
	vpnByName map[string]string // name → first IPv4 (for the clients table sync)
	names     map[string]bool
	subnet    *net.IPNet

	// healthy reports whether the last Load attempt is trustworthy for
	// deletions. loadedOnce distinguishes "conf has never existed" (WireGuard
	// simply not installed → empty registry, healthy, panel behaves exactly
	// like the pure-OpenVPN build) from "conf existed and then vanished"
	// (treated as a failed read: keep last-good, unhealthy — a transiently
	// missing file must never mass-delete WireGuard-only clients).
	healthy    bool
	loadedOnce bool
}

// Load re-reads the WireGuard config and atomically replaces the peer set.
// On error the previous set is kept (see Registry doc for the health rules).
func (r *Registry) Load(path string) error {
	conf, err := ParseConfFile(path)
	if err != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		if os.IsNotExist(err) && !r.loadedOnce {
			r.byPubKey = map[string]string{}
			r.nameByIP = map[string]string{}
			r.vpnByName = map[string]string{}
			r.names = map[string]bool{}
			r.subnet = nil
			r.healthy = true
			return nil
		}
		r.healthy = false
		return err
	}

	byPubKey := make(map[string]string, len(conf.Peers))
	nameByIP := make(map[string]string)
	vpnByName := make(map[string]string, len(conf.Peers))
	names := make(map[string]bool, len(conf.Peers))
	for _, p := range conf.Peers {
		byPubKey[p.PublicKey] = p.Name
		names[p.Name] = true
		vpnByName[p.Name] = p.VPNAddr
		for _, ip := range p.AllowedIPs {
			nameByIP[ip] = p.Name
		}
	}

	r.mu.Lock()
	r.byPubKey = byPubKey
	r.nameByIP = nameByIP
	r.vpnByName = vpnByName
	r.names = names
	r.subnet = conf.Subnet
	r.healthy = true
	r.loadedOnce = true
	r.mu.Unlock()
	return nil
}

// MarkDisabled puts the registry into the deliberate empty-but-healthy state,
// used when WireGuard monitoring is switched off by configuration (blank
// wireguard_conf). Without this, a never-loaded registry would report
// unhealthy and permanently suppress the revoked-client reaper — a regression
// for pure-OpenVPN deployments, where reaping must keep working against the
// certificate whitelist alone.
func (r *Registry) MarkDisabled() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byPubKey = map[string]string{}
	r.nameByIP = map[string]string{}
	r.vpnByName = map[string]string{}
	r.names = map[string]bool{}
	r.subnet = nil
	r.healthy = true
	r.loadedOnce = false
}

// Contains reports whether name is a current WireGuard peer.
func (r *Registry) Contains(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.names[name]
}

// Names returns all current peer names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.names))
	for n := range r.names {
		out = append(out, n)
	}
	return out
}

// NameByPubKey resolves a peer's configured name from its public key.
func (r *Registry) NameByPubKey(pubkey string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	name, ok := r.byPubKey[pubkey]
	return name, ok
}

// NameByIP resolves a peer name from one of its VPN addresses. Used by the
// client portal for visitors arriving from the WireGuard subnet.
func (r *Registry) NameByIP(ip string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	name, ok := r.nameByIP[ip]
	return name, ok
}

// SubnetContains reports whether ip falls inside the WireGuard subnet (the
// [Interface] Address network). False when no subnet is known.
func (r *Registry) SubnetContains(ip net.IP) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.subnet != nil && r.subnet.Contains(ip)
}

// Healthy reports whether the last Load attempt succeeded and the peer set
// can be trusted for destructive decisions (the reaper).
func (r *Registry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.healthy
}

// vpnAddrs returns a copy of the name → first-IPv4 map.
func (r *Registry) vpnAddrs() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(r.vpnByName))
	maps.Copy(out, r.vpnByName)
	return out
}

// RefreshLoop reloads the registry from confPath every minute (matching the
// cert whitelist cadence), starting with an immediate load. After each
// SUCCESSFUL load it syncs the peers into the clients table — so a
// provisioned-but-never-connected peer shows up as Offline exactly like an
// OpenVPN client with an unused certificate — and then invokes onReload
// (when non-nil), mirroring openvpn.CertWhitelist.RefreshLoop's contract: work that
// must only ever see a fresh, fully-read peer set (the reaper) hangs off this
// hook, and a failed load skips it.
func (r *Registry) RefreshLoop(ctx context.Context, confPath string, database *db.DB, logger *slog.Logger, onReload func()) {
	if confPath == "" {
		return
	}
	load := func() {
		if err := r.Load(confPath); err != nil {
			logger.Warn("wireguard conf refresh failed", "path", confPath, "err", err)
			return
		}
		dbCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		for name, ip := range r.vpnAddrs() {
			if err := database.UpsertKnownClient(dbCtx, name); err != nil {
				logger.Warn("wireguard client upsert failed", "name", name, "err", err)
				continue
			}
			if ip != "" {
				if err := database.UpdateClientVPNAddress(dbCtx, name, ip); err != nil {
					logger.Warn("wireguard vpn address update failed", "name", name, "err", err)
				}
			}
		}
		cancel()
		if onReload != nil {
			onReload()
		}
	}
	load()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			load()
		case <-ctx.Done():
			return
		}
	}
}
