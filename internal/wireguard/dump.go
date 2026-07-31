package wireguard

import (
	"log/slog"
	"strconv"
	"strings"
)

// DumpPeer is one peer line of `wg show <iface> dump` (tab-separated:
// public-key, preshared-key, endpoint, allowed-ips, latest-handshake,
// rx-bytes, tx-bytes, persistent-keepalive).
//
// Counter orientation: RX is what the server received FROM the peer (client
// upload) and TX is what the server sent TO the peer (client download). The
// sessions table stores bytes_received = client download and bytes_sent =
// client upload (see the OpenVPN watcher's parse comments), so deltas map
// TX→bytes_received and RX→bytes_sent.
type DumpPeer struct {
	PublicKey string
	Endpoint  string // "" when the kernel has no endpoint ("(none)")
	VPNAddr   string // host part of the first IPv4 allowed-ips entry
	Handshake int64  // unix epoch of the latest handshake; 0 = never
	RX        int64  // cumulative bytes received by the server from the peer
	TX        int64  // cumulative bytes sent by the server to the peer
}

// parseDump parses the output of `wg show <iface> dump`. The first line is
// the interface summary (4 fields) and is skipped; malformed peer lines are
// skipped with a warning rather than aborting the poll, mirroring the OpenVPN
// log parser's defensive stance.
func parseDump(out string, logger *slog.Logger) []DumpPeer {
	var peers []DumpPeer
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if i == 0 || line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			logger.Warn("skipping malformed wg dump line", "fields", len(f))
			continue
		}
		hs, err1 := strconv.ParseInt(f[4], 10, 64)
		rx, err2 := strconv.ParseInt(f[5], 10, 64)
		tx, err3 := strconv.ParseInt(f[6], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || hs < 0 || rx < 0 || tx < 0 {
			logger.Warn("skipping wg dump line with unparseable numbers", "pubkey", f[0])
			continue
		}
		endpoint := f[2]
		if endpoint == "(none)" {
			endpoint = ""
		}
		peers = append(peers, DumpPeer{
			PublicKey: f[0],
			Endpoint:  endpoint,
			VPNAddr:   firstIPv4Host(f[3]),
			Handshake: hs,
			RX:        rx,
			TX:        tx,
		})
	}
	return peers
}

// deltas converts a peer's raw cumulative counters into the byte increments
// to apply to its session, handling the two non-monotonic cases:
//
//   - First sighting (known == false, i.e. no persisted baseline exists):
//     none of this peer's traffic has ever been accounted for anywhere, so the
//     full current counters ARE the delta. This is correct exactly once,
//     because the same DB transaction that applies the delta persists the
//     counters as the new baseline — a crash applies both or neither, so the
//     initial credit can never be repeated.
//
//   - Counter reset (current < last): the interface or server restarted and
//     the kernel counters restarted from zero, so everything counted since
//     the reset is new traffic (delta = current). Bytes transferred between
//     our previous poll and the reset are unavoidably lost; the short poll
//     interval keeps that window small.
func deltas(known bool, lastRX, lastTX, curRX, curTX int64) (up, down int64) {
	if !known {
		return curRX, curTX
	}
	up = curRX - lastRX
	if up < 0 {
		up = curRX
	}
	down = curTX - lastTX
	if down < 0 {
		down = curTX
	}
	return up, down
}
