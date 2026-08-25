#!/usr/bin/env bash
# build.sh — build the ovpn-monitor single binary: the React frontend first
# (Vite outputs to internal/web/dist, embedded via //go:embed), then the Go
# binary itself.
set -euo pipefail

cd "$(dirname "$0")"

step() { printf '\n==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

step "Checking build tools"
command -v node >/dev/null 2>&1 || die "Node.js/npm required at build time only — install Node >= 24"
command -v npm >/dev/null 2>&1 || die "Node.js/npm required at build time only — install Node >= 24"
node --version

step "Installing frontend dependencies"
cd frontend
if [ -f package-lock.json ]; then
	npm ci || die "npm ci failed"
else
	npm install || die "npm install failed"
fi

step "Building frontend (outputs to internal/web/dist)"
npm run build || die "frontend build (vite) failed"
cd ..

step "Building Go binary (CGO_ENABLED=1; required by go-sqlite3)"
CGO_ENABLED=1 go build -o ovpnmonitor . ||
	die "go build failed"

bin="$(pwd)/ovpnmonitor"
size="$(du -h "$bin" | cut -f1)"
step "Success"
printf 'Binary: %s (%s)\n' "$bin" "$size"
