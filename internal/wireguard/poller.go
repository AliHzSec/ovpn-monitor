package wireguard

import (
	"context"
	"log/slog"
	"maps"
	"os/exec"
	"time"

	"ovpnmonitor/internal/db"
	"ovpnmonitor/internal/model"
	"ovpnmonitor/internal/tracker"
)

// maxDumpFailures is how many consecutive `wg show` failures are tolerated
// before WireGuard is declared down and all its open sessions are closed —
// the analogue of the OpenVPN watcher's stale-status-log handling.
const maxDumpFailures = 3

// Poller drives WireGuard monitoring: every Interval (the panel-wide
// poll_interval setting, shared with the OpenVPN watcher's resync tick) it
// runs one `wg show <iface> dump`, computes per-peer byte deltas against the
// persisted baselines, and applies them to the sessions table. All fields
// must be set before Run.
type Poller struct {
	DB               *db.DB
	Logger           *slog.Logger
	Registry         *Registry
	Online           *tracker.OnlineTracker
	Iface            string
	Interval         time.Duration
	HandshakeTimeout time.Duration

	// states mirrors wg_peer_state: the last raw counters applied per pubkey.
	// Only updated after the corresponding DB transaction commits, so memory
	// can never run ahead of the persisted baseline.
	states map[string]model.WGPeerState
	// online is the previous poll's per-NAME online set; transitions against
	// it open and close sessions.
	online map[string]bool
	fails  int  // consecutive dump failures
	down   bool // whether we have declared WireGuard down (throttles logging)
}

// Run polls until ctx is cancelled. It is resilient to WireGuard being
// absent: a missing wg binary or interface just produces dump failures, which
// after maxDumpFailures close any open WG sessions and then keep being
// retried quietly — so bringing WireGuard up later starts monitoring without
// a panel restart.
func (p *Poller) Run(ctx context.Context) {
	p.states = make(map[string]model.WGPeerState)
	p.online = make(map[string]bool)

	initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	if states, err := p.DB.WGPeerStates(initCtx); err != nil {
		p.Logger.Error("wg: load peer state: " + err.Error())
	} else {
		p.states = states
	}
	// Seed the online set from sessions left open by a previous run. A peer
	// still online resumes incrementing into its existing row; one that went
	// away while the panel was down is detected as an online→offline
	// transition on the first poll and closed properly.
	if names, err := p.DB.OpenWGSessionNames(initCtx); err != nil {
		p.Logger.Error("wg: load open sessions: " + err.Error())
	} else {
		for _, n := range names {
			p.online[n] = true
		}
	}
	cancel()

	p.poll(ctx)
	ticker := time.NewTicker(p.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.poll(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// dump runs one `wg show <iface> dump`.
func (p *Poller) dump(ctx context.Context) (string, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "wg", "show", p.Iface, "dump").Output()
	return string(out), err
}

func (p *Poller) poll(ctx context.Context) {
	out, err := p.dump(ctx)
	if err != nil {
		p.fails++
		if p.fails == maxDumpFailures {
			// WireGuard is down (service stopped, interface gone, binary
			// missing). Close its sessions so peers don't linger as online —
			// mirror of the watcher's "OpenVPN unresponsive" path. Counter
			// baselines are kept: if WireGuard was merely unresponsive the
			// counters are unchanged, and if it restarted the reset detection
			// handles the zeroed counters either way.
			p.Logger.Warn("wireguard unresponsive; closing its open sessions",
				"iface", p.Iface, "err", err.Error())
			dbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := p.DB.CloseAllWGSessions(dbCtx); err != nil {
				p.Logger.Error("wg: close stale sessions: " + err.Error())
			}
			cancel()
			p.online = make(map[string]bool)
			p.Online.Set(map[string]bool{})
			p.down = true
		}
		return
	}
	if p.down {
		p.Logger.Info("wireguard monitoring resumed", "iface", p.Iface)
		p.down = false
	}
	p.fails = 0

	dbCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	now := time.Now()
	current := make(map[string]bool) // online after this poll, by name
	seen := make(map[string]bool)    // present in the dump at all, by name

	for _, peer := range parseDump(out, p.Logger) {
		name, ok := p.Registry.NameByPubKey(peer.PublicKey)
		if !ok {
			// In the kernel but not in the conf: either the conf failed to load
			// (last-good keeps most peers resolvable) or the peer was removed
			// from the conf without a service restart. The conf is the source
			// of truth for peer existence — the reaper deletes by conf names —
			// so an unnamed peer is skipped rather than tracked under a name
			// the reaper would immediately delete (create/delete churn).
			p.Logger.Debug("wg: skipping peer not present in conf", "pubkey", peer.PublicKey)
			continue
		}
		seen[name] = true

		st, known := p.states[peer.PublicKey]
		up, down := deltas(known, st.LastRX, st.LastTX, peer.RX, peer.TX)
		online := peer.Handshake > 0 &&
			now.Sub(time.Unix(peer.Handshake, 0)) <= p.HandshakeTimeout

		d := model.WGPeerDelta{
			Name:        name,
			PubKey:      peer.PublicKey,
			RealAddress: peer.Endpoint,
			VPNAddress:  peer.VPNAddr,
			DeltaDown:   down,
			DeltaUp:     up,
			LastRX:      peer.RX,
			LastTX:      peer.TX,
		}

		switch {
		case online:
			// Online (fresh handshake): the peer's display state is online
			// regardless of DB success; the delta is only considered applied —
			// and the in-memory baseline only advances — when the transaction
			// commits, so a failed write is simply retried as a larger delta
			// on the next poll.
			current[name] = true
			if !p.online[name] {
				p.Logger.Info("wireguard peer online", "client", name, "vpn_address", peer.VPNAddr)
			}
			if err := p.DB.ApplyWGPeerDelta(dbCtx, d); err != nil {
				p.Logger.Error("wg: apply delta: "+err.Error(), "client", name)
				continue
			}
		case p.online[name]:
			// Online → offline: the handshake went stale. A single stale
			// observation closes the session — unlike the OpenVPN status log
			// there are no torn reads to debounce (the dump is atomic kernel
			// state), and the handshake timeout itself already provides ~3
			// minutes of slack.
			if err := p.DB.CloseWGPeerSession(dbCtx, d); err != nil {
				p.Logger.Error("wg: close session: "+err.Error(), "client", name)
				// Keep the peer marked online so the close is retried next poll
				// instead of leaking an open session forever.
				current[name] = true
				continue
			}
			p.Logger.Info("wireguard peer offline", "client", name)
		case !known:
			// First sighting of an offline peer: record the baseline without
			// crediting anything — its counters predate monitoring and there
			// is no session to attribute them to.
			if err := p.DB.SaveWGPeerState(dbCtx, d); err != nil {
				p.Logger.Error("wg: save initial state: "+err.Error(), "client", name)
				continue
			}
		case up != 0 || down != 0:
			// Rare trailing bytes while offline (landed between the close and
			// this poll): fold into the just-closed session when possible.
			folded, err := p.DB.ApplyWGTrailingDelta(dbCtx, d)
			if err != nil {
				p.Logger.Error("wg: trailing delta: "+err.Error(), "client", name)
				continue
			}
			if !folded {
				p.Logger.Debug("wg: dropped trailing delta with no session to fold into",
					"client", name, "up", up, "down", down)
			}
		default:
			// Offline, known, counters unchanged: nothing to write. Idle peers
			// cost zero SQL per poll.
			continue
		}
		p.states[peer.PublicKey] = model.WGPeerState{
			PubKey: peer.PublicKey, Name: name, LastRX: peer.RX, LastTX: peer.TX,
		}
	}

	// Peers that were online but are gone from the dump entirely (removed from
	// the interface, e.g. conf edit + service restart): close their sessions.
	// No final counters exist to fold in, so the baseline is left untouched —
	// if the peer is re-added its counters restart at zero and reset detection
	// takes over.
	for name := range p.online {
		if seen[name] || current[name] {
			continue
		}
		if err := p.DB.CloseWGSessionByName(dbCtx, name); err != nil {
			p.Logger.Error("wg: close removed peer session: "+err.Error(), "client", name)
			current[name] = true // retry next poll
			continue
		}
		p.Logger.Info("wireguard peer removed from interface; session closed", "client", name)
	}

	p.online = current
	set := make(map[string]bool, len(current))
	maps.Copy(set, current)
	p.Online.Set(set)
}
