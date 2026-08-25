# ovpn-monitor

A single-binary monitoring panel for OpenVPN/WireGuard servers: web UI, client
sessions and traffic history — all in one process, backed by one SQLite
database (`db.sqlite`, created next to the binary).

## Build

The web UI is a React SPA (`frontend/`) that is embedded into the Go binary.
`./build.sh` builds the frontend (into `internal/web/dist/`) and then the
binary:

```sh
./build.sh
```

The frontend build needs **Node.js ≥ 24 at build time only**. The Go build
uses cgo for SQLite:

```sh
CGO_ENABLED=1 go build -o ovpnmonitor .    # when the frontend is already built
```

Run it as root (the panel reads root-owned files like `wg0.conf` and
`ipp.txt`). If a systemd unit for the panel uses `ProtectSystem=strict`, add
`ReadWritePaths=` covering the panel's directory.

Configuration lives in the `settings` table and is edited on the `/settings`
page of the web UI; defaults are seeded on first start.
