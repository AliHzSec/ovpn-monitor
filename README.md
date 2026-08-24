# ovpn-monitor

A single-binary monitoring panel for OpenVPN/WireGuard servers: web UI, client
sessions and traffic history, and per-client **visited domain** tracking — all
in one process, backed by one SQLite database (`db.sqlite`, created next to the
binary).

## Build

The web UI is a React SPA (`frontend/`) that is embedded into the Go binary.
`./build.sh` builds the frontend (into `internal/web/dist/`) and then the
binary:

```sh
./build.sh
```

The frontend build needs **Node.js ≥ 24 at build time only**. The
domain-tracking subsystem uses gopacket's libpcap bindings, so the Go build
requires **cgo and the libpcap headers**:

```sh
sudo apt-get install -y libpcap-dev        # Debian/Ubuntu
CGO_ENABLED=1 go build -o ovpnmonitor .    # when the frontend is already built
```

Run it as root (raw packet capture needs `CAP_NET_RAW`, and the panel reads
root-owned files like `wg0.conf` and `ipp.txt`). If a systemd unit for the
panel uses hardening directives, make sure they don't block capture:
`RestrictAddressFamilies=` (if present) must include `AF_PACKET`, and
`ProtectSystem=strict` needs `ReadWritePaths=` covering the panel's directory.

Configuration lives in the `settings` table and is edited on the `/settings`
page of the web UI; defaults are seeded on first start.

## Visited domain tracking

The panel passively records which **root domains** each VPN client visits, so
browsing is auditable. It reads only the plaintext **TLS SNI** (port 443) and
**HTTP `Host` header** (port 80) — it never decrypts traffic, never terminates
TLS, and never writes packet payloads to disk. It runs as a subsystem of the
panel process itself, writing through the panel's own database handle (it was
previously a separate systemd service; that no longer exists).

### How it works

- Opens a live libpcap capture on each configured VPN interface (`tun0`,
  `wg0`, …) with the in-kernel BPF filter
  `tcp and (dst port 443 or dst port 80)` and a small snaplen (default
  1600 B). The kernel drops everything else, so only the first bytes of client
  requests reach userspace.
- Parses the SNI / `Host` from the request head, then reduces the hostname to
  its registrable **root domain** via the public suffix list
  (`www.youtube.com` → `youtube.com`, `foo.bar.bbc.co.uk` → `bbc.co.uk`),
  which collapses CDN/subdomain noise.
- Maps the packet's **source IP → client name** for both VPN types:
  - **OpenVPN**: the `ipp.txt` file from the panel's `openvpn_ipp_file`
    setting.
  - **WireGuard**: the wg config, associating each peer's `AllowedIPs` with
    the name in the surrounding `# BEGIN_PEER <name>` / `# Name = <name>`
    comment.
- Aggregates in memory as one bucket per `(client, domain)` and
  **batch-flushes** to SQLite every flush interval (default 2 min) — never a
  write per packet. Storage is therefore bounded by
  `clients × distinct domains`, not by traffic volume. A dedup window (default
  60 s) prevents a burst of repeat connections from inflating `visit_count`
  (but `last_seen` always advances).
- A **bounded worker pool** parses packets; under load, packets are
  **dropped** rather than growing an unbounded queue or blocking capture.
- Results appear in the **Visited Domains** section of each client's detail
  page. A daily cleanup purges rows whose `last_seen` is older than 90 days.

### Crash isolation

Because capture runs inside the panel process, every sniffer goroutine
(per-interface capture, parse workers, flush loop) recovers its own panics: a
parser bug on a hostile payload costs one packet, and a capture failure or
panic on one interface triggers a reopen of just that interface with backoff —
the web UI and the rest of the panel are unaffected. An interface that is
missing at startup (VPN not up yet) is likewise retried instead of skipped.

### Settings

All under the **Domain Tracking** section of `/settings` (applied on the next
service restart):

| Setting           | Default                   | Purpose |
|-------------------|---------------------------|---------|
| `sniffer_ifaces`  | `tun0,wg0`                | Comma-separated interfaces to capture. |
| `sniffer_wg_conf` | `/etc/wireguard/wg0.conf` | WireGuard peer↔name source. |
| `sniffer_snaplen` | `1600`                    | Capture length; enough for a ClientHello / `Host`. |
| `sniffer_workers` | `0` (auto, ≤8)            | Packet-parsing workers. |
| `sniffer_queue`   | `4096`                    | Bounded parse queue; overflow is dropped. |
| `sniffer_flush`   | `2m`                      | DB batch-upsert interval. |
| `sniffer_dedup`   | `60s`                     | Window in which repeat visits don't re-increment the counter. |

The OpenVPN IP↔name mapping uses the existing `openvpn_ipp_file` setting.

### Privacy scope

Domain-level only. No full URLs/paths, no per-visit timestamps beyond
first/last seen, no payloads, no decryption.
