package sniffer

import (
	"bytes"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"regexp"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// settingsDB builds a database holding just the panel's settings table — the
// only part of the schema the Mapper reads.
func settingsDB(t *testing.T, kv map[string]string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "settings.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(
		`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	for k, v := range kv {
		if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)`, k, v); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// wgConfFor writes a one-peer WireGuard config naming that peer.
func wgConfFor(t *testing.T, dir, file, peer, ip string) string {
	t.Helper()
	return writeFile(t, dir, file,
		"[Interface]\nAddress = 172.16.0.1/24\n\n# BEGIN_PEER "+peer+"\n[Peer]\nPublicKey = key-"+peer+"\nAllowedIPs = "+ip+"/32\n")
}

func quietMapper(db *sql.DB, ippPath, wgConf string) *Mapper {
	return NewMapper(db, ippPath, wgConf, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// An explicitly set sniffer_wg_conf stays authoritative: the Domain Tracking
// page's override must keep working.
func TestWireGuardConfPathPrefersSnifferSetting(t *testing.T) {
	dir := t.TempDir()
	override := wgConfFor(t, dir, "override.conf", "from-override", "172.16.0.5")
	wgConfFor(t, dir, "panel.conf", "from-panel", "172.16.0.6")

	m := quietMapper(settingsDB(t, map[string]string{
		"sniffer_wg_conf": override,
		"wireguard_conf":  filepath.Join(dir, "panel.conf"),
	}), "", "/unused/at/construction.conf")
	m.Refresh()

	if name, ok := m.Lookup("172.16.0.5"); !ok || name != "from-override" {
		t.Errorf("Lookup(172.16.0.5) = %q,%v want from-override,true", name, ok)
	}
	if _, ok := m.Lookup("172.16.0.6"); ok {
		t.Error("peer from wireguard_conf was mapped even though sniffer_wg_conf is set")
	}
}

// The fix: a blank sniffer_wg_conf falls back to the panel's authoritative
// wireguard_conf instead of silently mapping no WireGuard peers.
func TestWireGuardConfPathFallsBackToPanelSetting(t *testing.T) {
	dir := t.TempDir()
	panelConf := wgConfFor(t, dir, "panel.conf", "phone", "172.16.0.7")

	m := quietMapper(settingsDB(t, map[string]string{
		"sniffer_wg_conf": "",
		"wireguard_conf":  panelConf,
	}), "", "/stale/path/wg0.conf")
	m.Refresh()

	if name, ok := m.Lookup("172.16.0.7"); !ok || name != "phone" {
		t.Errorf("Lookup(172.16.0.7) = %q,%v want phone,true", name, ok)
	}
}

// Resolution happens on every Refresh, so moving the config takes effect within
// one refresh cycle rather than at the next restart.
func TestWireGuardConfPathReResolvesOnEachRefresh(t *testing.T) {
	dir := t.TempDir()
	first := wgConfFor(t, dir, "first.conf", "before", "172.16.0.8")
	second := wgConfFor(t, dir, "second.conf", "after", "172.16.0.9")

	db := settingsDB(t, map[string]string{"sniffer_wg_conf": "", "wireguard_conf": first})
	m := quietMapper(db, "", "")

	m.Refresh()
	if name, _ := m.Lookup("172.16.0.8"); name != "before" {
		t.Fatalf("first refresh: Lookup(172.16.0.8) = %q, want before", name)
	}

	// The admin edits the path on the WireGuard settings page; no restart.
	if _, err := db.Exec(`UPDATE settings SET value = ? WHERE key = 'wireguard_conf'`, second); err != nil {
		t.Fatal(err)
	}
	m.Refresh()

	if name, ok := m.Lookup("172.16.0.9"); !ok || name != "after" {
		t.Errorf("second refresh: Lookup(172.16.0.9) = %q,%v want after,true", name, ok)
	}
	if _, ok := m.Lookup("172.16.0.8"); ok {
		t.Error("second refresh still serves peers from the old config path")
	}
}

// Both settings blank means WireGuard monitoring is switched off, so there is
// nothing to map — the construction-time default must not resurrect it.
func TestWireGuardConfPathDisabledWhenBothBlank(t *testing.T) {
	m := quietMapper(settingsDB(t, map[string]string{
		"sniffer_wg_conf": "",
		"wireguard_conf":  "",
	}), "", "/etc/wireguard/wg0.conf")
	m.Refresh()

	if got := m.wireGuardConfPath(); got != "" {
		t.Errorf("wireGuardConfPath() = %q, want empty when WireGuard is disabled", got)
	}
}

// An unreadable settings table must not drop WireGuard mapping; the path passed
// at construction is the safety net.
func TestWireGuardConfPathFallsBackToConstructionPath(t *testing.T) {
	dir := t.TempDir()
	conf := wgConfFor(t, dir, "wg0.conf", "laptop", "172.16.0.10")

	m := quietMapper(nil, "", conf) // no DB handle at all
	m.Refresh()

	if name, ok := m.Lookup("172.16.0.10"); !ok || name != "laptop" {
		t.Errorf("Lookup(172.16.0.10) = %q,%v want laptop,true", name, ok)
	}
}

// The refresh log must break the total down per source, so "wireguard=0" is
// diagnosable without querying the database.
func TestRefreshLogsPerSourceCounts(t *testing.T) {
	dir := t.TempDir()
	ipp := writeFile(t, dir, "ipp.txt", "alice,10.8.0.6,\nbob,10.8.0.10\n")
	// One peer with an IPv4 and an IPv6 allowed-ips entry: two mapped addresses.
	wg := writeFile(t, dir, "wg0.conf",
		"[Interface]\nAddress = 172.16.0.1/24\n\n# BEGIN_PEER phone\n[Peer]\nPublicKey = k1\nAllowedIPs = 172.16.0.5/32, fddd::5/128\n")

	var buf bytes.Buffer
	m := NewMapper(settingsDB(t, map[string]string{
		"openvpn_ipp_file": ipp,
		"sniffer_wg_conf":  wg,
	}), "", "", slog.New(slog.NewTextHandler(&buf, nil)))
	m.Refresh()

	line := buf.String()
	for _, want := range []string{"entries=4", "openvpn=2", "wireguard=2"} {
		if !regexp.MustCompile(regexp.QuoteMeta(want) + `(\s|$)`).MatchString(line) {
			t.Errorf("refresh log missing %q; got: %s", want, line)
		}
	}
}

// A WireGuard config that resolves to nothing must still be reported, since a
// zero count is the whole point of the per-source breakdown.
func TestRefreshLogsZeroWireGuardCount(t *testing.T) {
	var buf bytes.Buffer
	m := NewMapper(settingsDB(t, map[string]string{
		"sniffer_wg_conf": "/nonexistent/wg0.conf",
		"wireguard_conf":  "/nonexistent/wg0.conf",
	}), "", "", slog.New(slog.NewTextHandler(&buf, nil)))
	m.Refresh()

	if !regexp.MustCompile(`wireguard=0(\s|$)`).MatchString(buf.String()) {
		t.Errorf("expected wireguard=0 in refresh log; got: %s", buf.String())
	}
}
