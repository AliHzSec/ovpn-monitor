// Package wireguard adds WireGuard peer monitoring to the panel. It parses the
// server config for peer identity (name ⇄ pubkey ⇄ VPN IP), polls
// `wg show <iface> dump` for the kernel's volatile cumulative counters, and
// converts counter deltas into rows of the same sessions table the OpenVPN
// watcher writes — so every existing query, filter and the client portal
// include WireGuard traffic with no query changes.
package wireguard

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// Peer is one [Peer] block from a WireGuard server config.
type Peer struct {
	Name       string   // from the comment convention, or a deterministic fallback
	PublicKey  string   // base64 public key (the peer's stable identity)
	VPNAddr    string   // host part of the first IPv4 AllowedIPs entry ("" if none)
	AllowedIPs []string // host parts of every AllowedIPs entry (IPv4 and IPv6)
}

// Conf is a parsed WireGuard server config: the interface subnet plus peers.
type Conf struct {
	Subnet *net.IPNet // first IPv4 network of the [Interface] Address line (nil if none)
	Peers  []Peer
}

// ParseConfFile parses a WireGuard server config. It is the single, shared
// peer-name parser for the whole panel, so every subsystem lands on the same
// client name. It recognises the naming conventions of the popular install
// scripts:
//
//	### Client alice          (angristan/wireguard-install)
//	# BEGIN_PEER alice        (Nyr/wireguard-install)
//	# Name = alice            (generic "name" comment, also "# name: alice")
//
// A name comment before a [Peer] header names that peer; one inside the block
// names it too (first one wins). A peer with no discoverable name gets a
// deterministic fallback derived from its public key (see fallbackName), so it
// is still visible and attributable rather than silently dropped.
func ParseConfFile(path string) (*Conf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	conf := &Conf{}
	var current *Peer  // the [Peer] block being read, nil outside one
	var pending string // name comment seen before the next [Peer] header
	inInterface := false

	// flush finalizes the current peer. A block with no PublicKey is malformed
	// (it cannot be matched to kernel state) and is skipped outright.
	flush := func() {
		if current != nil && current.PublicKey != "" {
			if current.Name == "" {
				current.Name = fallbackName(current.PublicKey)
			}
			conf.Peers = append(conf.Peers, *current)
		}
		current = nil
	}

	sc := bufio.NewScanner(f)
	// Config lines are short; the buffer guards against a corrupt oversized
	// line aborting the whole scan (same defensive pattern as cert parsing).
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(line, "### Client"):
			setPeerName(current, &pending, strings.TrimSpace(strings.TrimPrefix(line, "### Client")))
		case strings.HasPrefix(line, "# BEGIN_PEER"):
			setPeerName(current, &pending, strings.TrimSpace(strings.TrimPrefix(line, "# BEGIN_PEER")))
		case strings.HasPrefix(line, "#") && strings.Contains(lower, "name"):
			// "# Name = alice" or "# name: alice"
			if i := strings.IndexAny(line, "=:"); i >= 0 {
				setPeerName(current, &pending, strings.TrimSpace(line[i+1:]))
			}
		case strings.EqualFold(line, "[Peer]"):
			flush()
			current = &Peer{Name: pending}
			pending = ""
			inInterface = false
		case strings.EqualFold(line, "[Interface]"):
			flush()
			pending = ""
			inInterface = true
		case inInterface && strings.HasPrefix(lower, "address"):
			if conf.Subnet == nil {
				if i := strings.IndexByte(line, '='); i >= 0 {
					conf.Subnet = firstIPv4Net(line[i+1:])
				}
			}
		case current != nil && strings.HasPrefix(lower, "publickey"):
			if i := strings.IndexByte(line, '='); i >= 0 {
				current.PublicKey = strings.TrimSpace(line[i+1:])
			}
		case current != nil && strings.HasPrefix(lower, "allowedips"):
			if i := strings.IndexByte(line, '='); i >= 0 {
				for entry := range strings.SplitSeq(line[i+1:], ",") {
					ip := hostPart(entry)
					if ip == "" {
						continue
					}
					current.AllowedIPs = append(current.AllowedIPs, ip)
					if current.VPNAddr == "" && isIPv4(ip) {
						current.VPNAddr = ip
					}
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return conf, nil
}

// setPeerName routes a name comment to the right target: the peer block it
// appears inside (if still unnamed), otherwise the next [Peer] header.
func setPeerName(current *Peer, pending *string, name string) {
	if name == "" {
		return
	}
	if current != nil && current.Name == "" {
		current.Name = name
		return
	}
	*pending = name
}

// fallbackName derives a stable display name for a peer with no name comment:
// "wg-" plus the first 10 characters of its base64 public key, with '+' and
// '/' mapped to their URL-safe variants so the name stays path- and
// query-string-safe. Deterministic, so the same peer always maps to the same
// client row across restarts.
func fallbackName(pubkey string) string {
	s := strings.NewReplacer("+", "-", "/", "_").Replace(pubkey)
	if len(s) > 10 {
		s = s[:10]
	}
	return "wg-" + s
}

// hostPart strips the CIDR mask from an entry like "10.7.0.2/32", returning
// the bare host address (or "" for a blank entry).
func hostPart(entry string) string {
	ip := strings.TrimSpace(entry)
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	return ip
}

func isIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// firstIPv4Net parses a comma-separated Address list ("10.66.66.1/24,
// fd42::1/64") and returns the network of the first IPv4 entry, nil if none.
func firstIPv4Net(list string) *net.IPNet {
	for entry := range strings.SplitSeq(list, ",") {
		s := strings.TrimSpace(entry)
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil || ip.To4() == nil {
			continue
		}
		return ipNet
	}
	return nil
}

// firstIPv4Host returns the host part of the first IPv4 entry of a
// comma-separated allowed-ips list, "" if none. Shared by the conf parser and
// the dump parser so both derive the same VPN address for a peer.
func firstIPv4Host(list string) string {
	for entry := range strings.SplitSeq(list, ",") {
		ip := hostPart(entry)
		if ip != "" && isIPv4(ip) {
			return ip
		}
	}
	return ""
}
