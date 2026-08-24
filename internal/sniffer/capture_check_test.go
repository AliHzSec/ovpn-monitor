package sniffer

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestInterfaces(t *testing.T) {
	cases := map[string][]string{
		"":             {"tun0", "wg0"}, // unset falls back to the built-in default
		"tun0,wg0":     {"tun0", "wg0"},
		" tun0 , wg1 ": {"tun0", "wg1"}, // whitespace trimmed
		"wg0,,tun0":    {"wg0", "tun0"}, // empty entries dropped
		"wg1":          {"wg1"},
	}
	for in, want := range cases {
		got := Interfaces(in)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("Interfaces(%q) = %v, want %v", in, got, want)
		}
	}
}

// checkOutput runs the startup check and returns whatever it logged.
func checkOutput(wgConf, wgIface, ifaces string) string {
	var buf bytes.Buffer
	CheckWireGuardCapture(slog.New(slog.NewTextHandler(&buf, nil)), wgConf, wgIface, ifaces)
	return buf.String()
}

func TestCheckWireGuardCapture(t *testing.T) {
	cases := []struct {
		name                    string
		wgConf, wgIface, ifaces string
		warn                    bool
	}{
		{"interface is captured", "/etc/wireguard/wg0.conf", "wg0", "tun0,wg0", false},
		{"interface is captured, default list", "/etc/wireguard/wg0.conf", "wg0", "", false},
		{"interface is not captured", "/etc/wireguard/wg1.conf", "wg1", "tun0,wg0", true},
		{"only the OpenVPN interface is captured", "/etc/wireguard/wg0.conf", "wg0", "tun0", true},
		// WireGuard monitoring switched off: nothing is expected to be captured,
		// so a mismatch is not a misconfiguration.
		{"wireguard disabled", "", "wg1", "tun0,wg0", false},
		{"wireguard disabled, blank interface too", "", "", "tun0", false},
		// Whitespace in either setting must not fake a mismatch.
		{"whitespace tolerated", " /etc/wireguard/wg0.conf ", " wg0 ", " tun0 , wg0 ", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := checkOutput(c.wgConf, c.wgIface, c.ifaces)
			logged := out != ""
			if logged != c.warn {
				t.Fatalf("warned = %v, want %v (log: %q)", logged, c.warn, out)
			}
			if !c.warn {
				return
			}
			if !strings.Contains(out, "level=WARN") {
				t.Errorf("expected a WARN-level line, got: %s", out)
			}
			// The message has to name both settings, since the fix is to change
			// one of them and the admin must see which values disagree.
			for _, want := range []string{
				"wireguard_interface=" + strings.TrimSpace(c.wgIface),
				"sniffer_ifaces=",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("log missing %q; got: %s", want, out)
				}
			}
		})
	}
}
