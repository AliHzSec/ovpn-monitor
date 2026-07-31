package wireguard

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

func TestParseConfFileAngristan(t *testing.T) {
	conf := `[Interface]
Address = 10.66.66.1/24,fd42:42:42::1/64
ListenPort = 51820
PrivateKey = xxx

### Client AliHzSec
[Peer]
PublicKey = keyAli=
PresharedKey = pskAli
AllowedIPs = 10.66.66.2/32,fd42:42:42::2/128

### Client phone
[Peer]
PublicKey = keyPhone=
AllowedIPs = 10.66.66.3/32
`
	p := writeFile(t, t.TempDir(), "wg0.conf", conf)
	c, err := ParseConfFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subnet == nil || c.Subnet.String() != "10.66.66.0/24" {
		t.Errorf("subnet = %v, want 10.66.66.0/24", c.Subnet)
	}
	if len(c.Peers) != 2 {
		t.Fatalf("peers = %d, want 2: %+v", len(c.Peers), c.Peers)
	}
	ali := c.Peers[0]
	if ali.Name != "AliHzSec" || ali.PublicKey != "keyAli=" || ali.VPNAddr != "10.66.66.2" {
		t.Errorf("peer 0 = %+v", ali)
	}
	if len(ali.AllowedIPs) != 2 || ali.AllowedIPs[1] != "fd42:42:42::2" {
		t.Errorf("peer 0 allowed ips = %v", ali.AllowedIPs)
	}
	if c.Peers[1].Name != "phone" || c.Peers[1].VPNAddr != "10.66.66.3" {
		t.Errorf("peer 1 = %+v", c.Peers[1])
	}
}

func TestParseConfFileOtherConventions(t *testing.T) {
	conf := `[Interface]
Address = 10.7.0.1/24

# BEGIN_PEER carol
[Peer]
PublicKey = key1
AllowedIPs = 10.7.0.2/32
# END_PEER carol

# Name = dave
[Peer]
PublicKey = key2
AllowedIPs = 10.7.0.3/32
`
	p := writeFile(t, t.TempDir(), "wg0.conf", conf)
	c, err := ParseConfFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Peers) != 2 || c.Peers[0].Name != "carol" || c.Peers[1].Name != "dave" {
		t.Errorf("peers = %+v", c.Peers)
	}
}

func TestParseConfFileFallbackName(t *testing.T) {
	conf := `[Interface]
Address = 10.7.0.1/24

[Peer]
PublicKey = AbC+dEf/gHiJkLmNoPqRsTuVwXyZ0123456789abcde=
AllowedIPs = 10.7.0.2/32

[Peer]
AllowedIPs = 10.7.0.3/32
`
	p := writeFile(t, t.TempDir(), "wg0.conf", conf)
	c, err := ParseConfFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// The unnamed peer gets a deterministic, sanitized pubkey-derived name;
	// the block with no PublicKey is malformed and dropped.
	if len(c.Peers) != 1 {
		t.Fatalf("peers = %+v, want 1", c.Peers)
	}
	if c.Peers[0].Name != "wg-AbC-dEf_gH" {
		t.Errorf("fallback name = %q, want wg-AbC-dEf_gH", c.Peers[0].Name)
	}
}

func TestParseConfFileMissing(t *testing.T) {
	_, err := ParseConfFile(filepath.Join(t.TempDir(), "nope.conf"))
	if !os.IsNotExist(err) {
		t.Errorf("err = %v, want IsNotExist", err)
	}
}

func TestRegistryLoadStates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")

	// Conf absent from the start: WireGuard not installed → empty but healthy,
	// so certificate-only reaping keeps working.
	r := &Registry{}
	if err := r.Load(path); err != nil {
		t.Fatalf("absent conf: %v", err)
	}
	if !r.Healthy() {
		t.Error("registry should be healthy when the conf never existed")
	}
	if r.Contains("AliHzSec") {
		t.Error("empty registry should contain nothing")
	}

	writeFile(t, dir, "wg0.conf", `[Interface]
Address = 10.66.66.1/24
### Client AliHzSec
[Peer]
PublicKey = k1
AllowedIPs = 10.66.66.2/32
`)
	if err := r.Load(path); err != nil {
		t.Fatal(err)
	}
	if !r.Healthy() || !r.Contains("AliHzSec") {
		t.Error("registry should be healthy and contain AliHzSec after load")
	}
	if name, ok := r.NameByPubKey("k1"); !ok || name != "AliHzSec" {
		t.Errorf("NameByPubKey = %q, %v", name, ok)
	}
	if name, ok := r.NameByIP("10.66.66.2"); !ok || name != "AliHzSec" {
		t.Errorf("NameByIP = %q, %v", name, ok)
	}

	// Conf vanishing AFTER a successful load is a failed read: last-good set
	// kept, unhealthy — the reaper must not delete WG-only clients on it.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := r.Load(path); err == nil {
		t.Error("vanished conf should return an error")
	}
	if r.Healthy() {
		t.Error("registry should be unhealthy after the conf vanished")
	}
	if !r.Contains("AliHzSec") {
		t.Error("last-good peer set should survive a failed load")
	}
}

func TestRegistryMarkDisabled(t *testing.T) {
	// Monitoring switched off by configuration: the registry must be healthy
	// (so certificate-only reaping keeps running) and empty.
	r := &Registry{}
	r.MarkDisabled()
	if !r.Healthy() {
		t.Error("disabled registry must report healthy")
	}
	if len(r.Names()) != 0 {
		t.Errorf("disabled registry names = %v, want none", r.Names())
	}
}
