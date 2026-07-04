# VPN Domain Sniffer

A lightweight, standalone collector that records which **root domains** each VPN
client visits, so browsing is auditable. It reads only the plaintext **TLS SNI**
(port 443) and **HTTP `Host` header** (port 80) — it never decrypts traffic,
never terminates TLS, and never writes packet payloads to disk.

It is a **separate process / systemd service** from the main panel
(`ovpnmonitor`). Both share the panel's SQLite database; the sniffer batch-upserts
aggregated rows into the `visited_domains` table, and the panel reads them for the
client detail page.

## How it works

- Opens a live libpcap capture on each configured VPN interface (`tun0`, `wg0`, …)
  with the in-kernel BPF filter `tcp and (dst port 443 or dst port 80)` and a
  small snaplen (default 1600 B). The kernel drops everything else, so only the
  first bytes of client requests reach userspace.
- Parses the SNI / `Host` from the request head, then reduces the hostname to its
  registrable **root domain** via the public suffix list
  (`www.youtube.com` → `youtube.com`, `foo.bar.bbc.co.uk` → `bbc.co.uk`), which
  collapses CDN/subdomain noise.
- Maps the packet's **source IP → client name** for both VPN types:
  - **OpenVPN**: the panel's `ipp.txt` (path taken from the panel's own
    `openvpn_ipp_file` setting when present, else the `-ipp` flag).
  - **WireGuard**: `wg0.conf`, associating each peer's `AllowedIPs` with the name
    in the surrounding `# BEGIN_PEER <name>` / `# Name = <name>` comment.
- Aggregates in memory as one bucket per `(client, domain)` and **batch-flushes**
  to SQLite every `-flush` interval (default 2 min) — never a write per packet.
  Storage is therefore bounded by `clients × distinct domains`, not by traffic
  volume. A `-dedup` window (default 60 s) prevents a burst of repeat connections
  from inflating `visit_count` (but `last_seen` always advances).
- A **bounded worker pool** parses packets; under load, packets are **dropped**
  rather than growing an unbounded queue or blocking capture (`-queue` cap).

Retention (90-day purge of stale rows) is handled by the **panel**, not the
sniffer — it runs a daily cleanup that deletes `visited_domains` rows whose
`last_seen` is older than 90 days.

## Build

Requires `libpcap-dev` (headers) at build time and `cgo`:

```sh
sudo apt-get install -y libpcap-dev        # Debian/Ubuntu
cd cmd/sniffer
CGO_ENABLED=1 go build -o sniffer .
```

This is a nested Go module, so it is intentionally excluded from the main
project's `go build ./...` and its gopacket/libpcap dependency stays out of the
panel binary.

## Flags

| Flag       | Default                         | Purpose |
|------------|---------------------------------|---------|
| `-db`      | `db.sqlite`                     | Path to the panel's SQLite DB (must match the panel's). |
| `-ifaces`  | `tun0,wg0`                      | Comma-separated interfaces to capture. |
| `-ipp`     | `/etc/openvpn/server/ipp.txt`   | OpenVPN IP↔name file (panel setting wins if set). |
| `-wg-conf` | `/etc/wireguard/wg0.conf`       | WireGuard peer↔name source. |
| `-snaplen` | `1600`                          | Capture length; enough for a ClientHello / `Host`. |
| `-workers` | auto (≤8)                       | Packet-parsing workers. |
| `-queue`   | `4096`                          | Bounded parse queue; overflow is dropped. |
| `-flush`   | `2m`                            | DB batch-upsert interval. |
| `-dedup`   | `60s`                           | Window in which repeat visits don't re-increment the counter. |

## Install as a service

```sh
sudo install -m 0755 sniffer /opt/ovpn-monitor/sniffer
sudo cp ovpn-domain-sniffer.service /etc/systemd/system/
# edit the ExecStart paths in the unit to match your install, then:
sudo systemctl daemon-reload
sudo systemctl enable --now ovpn-domain-sniffer
sudo journalctl -u ovpn-domain-sniffer -f
```

The unit runs as root with `CAP_NET_RAW`/`CAP_NET_ADMIN` (raw capture, and read
access to the root-only `wg0.conf`/`ipp.txt` and the DB), plus systemd hardening.
To run as a non-root user instead, grant the binary ambient `CAP_NET_RAW` and
ensure that user can read the mapping files and write the DB.

## Privacy scope

Domain-level only. No full URLs/paths, no per-visit timestamps beyond
first/last seen, no payloads, no decryption.
