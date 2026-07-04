package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadIPP(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "ipp.txt", "# comment\nalice,10.8.0.6,\nbob,10.8.0.10\n\nbad-line\n")
	out := map[string]string{}
	if err := loadIPP(p, out); err != nil {
		t.Fatal(err)
	}
	if out["10.8.0.6"] != "alice" || out["10.8.0.10"] != "bob" {
		t.Errorf("ipp map = %v", out)
	}
	if len(out) != 2 {
		t.Errorf("expected 2 entries, got %d: %v", len(out), out)
	}
}

func TestLoadWireGuard(t *testing.T) {
	dir := t.TempDir()
	conf := `[Interface]
Address = 10.7.0.1/24
PrivateKey = xxx
ListenPort = 51820

# BEGIN_PEER carol
[Peer]
PublicKey = key1
AllowedIPs = 10.7.0.2/32,fddd:2c4:2c4:2c4::2/128
# END_PEER carol

# Name = dave
[Peer]
PublicKey = key2
AllowedIPs = 10.7.0.3/32
`
	p := writeFile(t, dir, "wg0.conf", conf)
	out := map[string]string{}
	if err := loadWireGuard(p, out); err != nil {
		t.Fatal(err)
	}
	if out["10.7.0.2"] != "carol" {
		t.Errorf("carol v4 = %q", out["10.7.0.2"])
	}
	if out["fddd:2c4:2c4:2c4::2"] != "carol" {
		t.Errorf("carol v6 = %q", out["fddd:2c4:2c4:2c4::2"])
	}
	if out["10.7.0.3"] != "dave" {
		t.Errorf("dave = %q", out["10.7.0.3"])
	}
}
