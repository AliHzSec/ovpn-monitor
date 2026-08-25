package ipv6

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wgEnabledConf = `[Interface]
PrivateKey = SERVERPRIVATEKEY
Address = 10.66.66.1/24, fd42:42:42::1/64
ListenPort = 51820
PostUp = iptables -I FORWARD -i wg0 -j ACCEPT
PostUp = ip6tables -I FORWARD -i wg0 -j ACCEPT
#PostUp = ip6tables -I FORWARD -i wg0 -j REJECT --reject-with icmp6-adm-prohibited
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = ip6tables -D FORWARD -i wg0 -j ACCEPT
#PostDown = ip6tables -D FORWARD -i wg0 -j REJECT --reject-with icmp6-adm-prohibited
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

### Client alice
[Peer]
PublicKey = ALICEPUBKEY
PresharedKey = ALICEPSK
AllowedIPs = 10.66.66.2/32, fd42:42:42::2/128
`

const wgDisabledConf = `[Interface]
PrivateKey = SERVERPRIVATEKEY
Address = 10.66.66.1/24, fd42:42:42::1/64
ListenPort = 51820
PostUp = iptables -I FORWARD -i wg0 -j ACCEPT
#PostUp = ip6tables -I FORWARD -i wg0 -j ACCEPT
PostUp = ip6tables -I FORWARD -i wg0 -j REJECT --reject-with icmp6-adm-prohibited
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
#PostDown = ip6tables -D FORWARD -i wg0 -j ACCEPT
PostDown = ip6tables -D FORWARD -i wg0 -j REJECT --reject-with icmp6-adm-prohibited
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

### Client alice
[Peer]
PublicKey = ALICEPUBKEY
PresharedKey = ALICEPSK
AllowedIPs = 10.66.66.2/32, fd42:42:42::2/128
`

// wgLegacyConf only has the ACCEPT lines, like an older install script wrote.
const wgLegacyConf = `[Interface]
PrivateKey = SERVERPRIVATEKEY
Address = 10.66.66.1/24
ListenPort = 51820
PostUp = ip6tables -I FORWARD -i wg0 -j ACCEPT
PostDown = ip6tables -D FORWARD -i wg0 -j ACCEPT

[Peer]
PublicKey = ALICEPUBKEY
AllowedIPs = 10.66.66.2/32
`

const ovpnEnabledConf = `port 1194
proto udp
dev tun
server 10.8.0.0 255.255.255.0
server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "redirect-gateway def1 bypass-dhcp"
push "redirect-gateway ipv6"
push "route-ipv6 2000::/3"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "dhcp-option DNS 2001:4860:4860::8888"
push "dhcp-option DNS 2001:4860:4860::8844"
keepalive 10 120
`

// ovpnDisabledCustomConf is the disabled state with a hand-modified IPv6
// prefix and DNS servers — the editor must match by key and preserve values.
const ovpnDisabledCustomConf = `port 1194
proto udp
dev tun
server 10.8.0.0 255.255.255.0
#server-ipv6 fd00:dead:beef::/64
#tun-ipv6
#push tun-ipv6
push "redirect-gateway def1 bypass-dhcp"
#push "redirect-gateway ipv6"
#push "route-ipv6 2000::/3"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
#push "dhcp-option DNS 2606:4700:4700::1111"
#push "dhcp-option DNS 2606:4700:4700::1001"
keepalive 10 120
`

func newWGService(t *testing.T, conf string) (*Service, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := NewWireGuard(path, "wg-quick@wg0", "wg0",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.Restart = func(context.Context, string) error { return nil }
	return svc, path
}

func newOVPNService(t *testing.T, conf string) (*Service, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	svc := NewOpenVPN(path, "openvpn-server@server",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.Restart = func(context.Context, string) error { return nil }
	return svc, path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ── WireGuard ──────────────────────────────────────────────────────────────

func TestWGStateRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf string
		want State
	}{
		{"enabled", wgEnabledConf, StateEnabled},
		{"disabled", wgDisabledConf, StateDisabled},
		{"legacy accept-only reads enabled", wgLegacyConf, StateEnabled},
		{"no markers is unknown", "[Interface]\nAddress = 10.0.0.1/24\n", StateUnknown},
		{"inconsistent mix is unknown", `[Interface]
PostUp = ip6tables -I FORWARD -i wg0 -j ACCEPT
#PostDown = ip6tables -D FORWARD -i wg0 -j ACCEPT
PostDown = ip6tables -D FORWARD -i wg0 -j REJECT --reject-with icmp6-adm-prohibited
`, StateUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wgState("wg0")([]byte(tc.conf)); got != tc.want {
				t.Errorf("state = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWGToggleEnableDisable(t *testing.T) {
	svc, path := newWGService(t, wgEnabledConf)

	state, err := svc.Set(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if state != StateDisabled {
		t.Errorf("state after disable = %q, want disabled", state)
	}
	if got := readFile(t, path); got != wgDisabledConf {
		t.Errorf("file after disable mismatch:\n%s", got)
	}

	state, err = svc.Set(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if state != StateEnabled {
		t.Errorf("state after enable = %q, want enabled", state)
	}
	if got := readFile(t, path); got != wgEnabledConf {
		t.Errorf("file after re-enable is not byte-identical to the original:\n%s", got)
	}
}

func TestWGToggleIdempotent(t *testing.T) {
	svc, path := newWGService(t, wgEnabledConf)
	if _, err := svc.Set(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != wgEnabledConf {
		t.Errorf("re-applying enabled changed the file:\n%s", got)
	}
}

func TestWGLegacyConfigGainsCounterpartLines(t *testing.T) {
	svc, path := newWGService(t, wgLegacyConf)
	if _, err := svc.Set(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	want := `[Interface]
PrivateKey = SERVERPRIVATEKEY
Address = 10.66.66.1/24
ListenPort = 51820
#PostUp = ip6tables -I FORWARD -i wg0 -j ACCEPT
PostUp = ip6tables -I FORWARD -i wg0 -j REJECT --reject-with icmp6-adm-prohibited
#PostDown = ip6tables -D FORWARD -i wg0 -j ACCEPT
PostDown = ip6tables -D FORWARD -i wg0 -j REJECT --reject-with icmp6-adm-prohibited

[Peer]
PublicKey = ALICEPUBKEY
AllowedIPs = 10.66.66.2/32
`
	if got != want {
		t.Errorf("legacy config after disable mismatch:\n%s", got)
	}
	if state := wgState("wg0")([]byte(got)); state != StateDisabled {
		t.Errorf("state after upgrade = %q, want disabled", state)
	}
}

func TestWGNoMarkersIsAnError(t *testing.T) {
	conf := "[Interface]\nAddress = 10.0.0.1/24\n"
	svc, path := newWGService(t, conf)
	if _, err := svc.Set(context.Background(), false); err == nil {
		t.Fatal("expected an error for a config without markers")
	}
	if got := readFile(t, path); got != conf {
		t.Errorf("file was modified despite the error:\n%s", got)
	}
}

func TestWGUntouchedLinesStayByteIdentical(t *testing.T) {
	svc, path := newWGService(t, wgEnabledConf)
	if _, err := svc.Set(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	// The MASQUERADE ip6tables line, the Address line and the whole [Peer]
	// block must be untouched.
	for _, keep := range []string{
		"PostUp = ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n",
		"Address = 10.66.66.1/24, fd42:42:42::1/64\n",
		"### Client alice\n[Peer]\nPublicKey = ALICEPUBKEY\nPresharedKey = ALICEPSK\nAllowedIPs = 10.66.66.2/32, fd42:42:42::2/128\n",
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("expected untouched content %q in:\n%s", keep, got)
		}
	}
}

// ── OpenVPN ────────────────────────────────────────────────────────────────

func TestOVPNStateRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf string
		want State
	}{
		{"enabled", ovpnEnabledConf, StateEnabled},
		{"disabled custom values", ovpnDisabledCustomConf, StateDisabled},
		{"no directives is unknown", "port 1194\nserver 10.8.0.0 255.255.255.0\n", StateUnknown},
		{"mixed is unknown", "server-ipv6 fd42::/112\n#tun-ipv6\n", StateUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ovpnState([]byte(tc.conf)); got != tc.want {
				t.Errorf("state = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOVPNToggleEnableDisable(t *testing.T) {
	svc, path := newOVPNService(t, ovpnEnabledConf)

	if _, err := svc.Set(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if state := ovpnState([]byte(got)); state != StateDisabled {
		t.Errorf("state after disable = %q, want disabled", state)
	}
	// IPv4 directives must be untouched.
	for _, keep := range []string{
		"push \"redirect-gateway def1 bypass-dhcp\"\n",
		"push \"dhcp-option DNS 8.8.8.8\"\n",
		"push \"dhcp-option DNS 8.8.4.4\"\n",
		"server 10.8.0.0 255.255.255.0\n",
	} {
		if !strings.Contains(got, keep) {
			t.Errorf("expected untouched IPv4 directive %q in:\n%s", keep, got)
		}
	}
	for _, off := range []string{
		"#server-ipv6 fd42:42:42:42::/112",
		"#tun-ipv6",
		"#push tun-ipv6",
		"#push \"redirect-gateway ipv6\"",
		"#push \"route-ipv6 2000::/3\"",
		"#push \"dhcp-option DNS 2001:4860:4860::8888\"",
		"#push \"dhcp-option DNS 2001:4860:4860::8844\"",
	} {
		if !strings.Contains(got, off+"\n") {
			t.Errorf("expected commented directive %q in:\n%s", off, got)
		}
	}

	if _, err := svc.Set(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != ovpnEnabledConf {
		t.Errorf("file after re-enable is not byte-identical to the original:\n%s", got)
	}
}

func TestOVPNCustomValuesPreserved(t *testing.T) {
	svc, path := newOVPNService(t, ovpnDisabledCustomConf)
	if _, err := svc.Set(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	// The hand-modified prefix and DNS servers must survive verbatim, just
	// uncommented.
	for _, want := range []string{
		"server-ipv6 fd00:dead:beef::/64\n",
		"push \"dhcp-option DNS 2606:4700:4700::1111\"\n",
		"push \"dhcp-option DNS 2606:4700:4700::1001\"\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected preserved value %q in:\n%s", want, got)
		}
	}
	if state := ovpnState([]byte(got)); state != StateEnabled {
		t.Errorf("state after enable = %q, want enabled", state)
	}
	// Toggling back restores the original file byte-for-byte.
	if _, err := svc.Set(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != ovpnDisabledCustomConf {
		t.Errorf("file after re-disable is not byte-identical to the original:\n%s", got)
	}
}

func TestOVPNToggleIdempotent(t *testing.T) {
	svc, path := newOVPNService(t, ovpnEnabledConf)
	if _, err := svc.Set(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != ovpnEnabledConf {
		t.Errorf("re-applying enabled changed the file:\n%s", got)
	}
}

func TestOVPNNoDirectivesIsAnError(t *testing.T) {
	conf := "port 1194\nserver 10.8.0.0 255.255.255.0\n"
	svc, path := newOVPNService(t, conf)
	if _, err := svc.Set(context.Background(), true); err == nil {
		t.Fatal("expected an error for a config without IPv6 directives")
	}
	if got := readFile(t, path); got != conf {
		t.Errorf("file was modified despite the error:\n%s", got)
	}
}

// ── Shared mechanics ───────────────────────────────────────────────────────

func TestFileModePreserved(t *testing.T) {
	svc, path := newWGService(t, wgEnabledConf)
	if _, err := svc.Set(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestBackupWritten(t *testing.T) {
	svc, path := newWGService(t, wgEnabledConf)
	if _, err := svc.Set(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(path + ".*.bak")
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected exactly one .bak next to the config, got %v (err %v)", matches, err)
	}
	if got := readFile(t, matches[0]); got != wgEnabledConf {
		t.Errorf("backup does not hold the original contents:\n%s", got)
	}
}

func TestFailedRestartRollsBack(t *testing.T) {
	svc, path := newWGService(t, wgEnabledConf)
	restarts := 0
	svc.Restart = func(context.Context, string) error {
		restarts++
		return errors.New("unit failed")
	}
	if _, err := svc.Set(context.Background(), false); err == nil {
		t.Fatal("expected an error when the restart fails")
	}
	if got := readFile(t, path); got != wgEnabledConf {
		t.Errorf("config was not rolled back to the original contents:\n%s", got)
	}
	// First restart attempt plus the rollback restart.
	if restarts != 2 {
		t.Errorf("restart calls = %d, want 2 (failed apply + rollback)", restarts)
	}
}

func TestStateEndpointParsesLiveFile(t *testing.T) {
	svc, path := newWGService(t, wgEnabledConf)
	state, err := svc.State()
	if err != nil || state != StateEnabled {
		t.Fatalf("state = %q, err %v; want enabled", state, err)
	}
	// A hand edit must be reflected immediately — no cached state.
	if err := os.WriteFile(path, []byte(wgDisabledConf), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err = svc.State()
	if err != nil || state != StateDisabled {
		t.Fatalf("state after hand edit = %q, err %v; want disabled", state, err)
	}
}
