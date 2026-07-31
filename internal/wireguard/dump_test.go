package wireguard

import (
	"io"
	"log/slog"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestParseDump(t *testing.T) {
	out := "privkey\tpubkey-if\t51820\toff\n" +
		"peerA=\t(none)\t203.0.113.9:51820\t10.66.66.2/32,fd42::2/128\t1722400000\t123\t456\t0\n" +
		"peerB=\t(none)\t(none)\t10.66.66.3/32\t0\t0\t0\toff\n" +
		"garbage-line\n" +
		"peerC=\t(none)\t1.2.3.4:1\t10.66.66.4/32\tnot-a-number\t1\t2\t0\n"
	peers := parseDump(out, discardLogger())
	if len(peers) != 2 {
		t.Fatalf("peers = %d, want 2 (malformed lines skipped): %+v", len(peers), peers)
	}

	a := peers[0]
	if a.PublicKey != "peerA=" || a.Endpoint != "203.0.113.9:51820" || a.VPNAddr != "10.66.66.2" {
		t.Errorf("peer A = %+v", a)
	}
	if a.Handshake != 1722400000 || a.RX != 123 || a.TX != 456 {
		t.Errorf("peer A numbers = %+v", a)
	}

	// "(none)" endpoint normalizes to empty; zero handshake means never.
	b := peers[1]
	if b.Endpoint != "" {
		t.Errorf("peer B endpoint = %q, want empty", b.Endpoint)
	}
	if b.Handshake != 0 {
		t.Errorf("peer B handshake = %d, want 0", b.Handshake)
	}
}

func TestParseDumpEmpty(t *testing.T) {
	// Interface line only (no peers configured).
	if peers := parseDump("privkey\tpubkey\t51820\toff\n", discardLogger()); len(peers) != 0 {
		t.Errorf("peers = %+v, want none", peers)
	}
	if peers := parseDump("", discardLogger()); len(peers) != 0 {
		t.Errorf("peers from empty output = %+v, want none", peers)
	}
}

func TestDeltas(t *testing.T) {
	cases := []struct {
		name           string
		known          bool
		lastRX, lastTX int64
		curRX, curTX   int64
		wantUp         int64
		wantDown       int64
	}{
		// Normal growth: plain difference.
		{"growth", true, 100, 200, 150, 260, 50, 60},
		// No change: zero deltas.
		{"idle", true, 100, 200, 100, 200, 0, 0},
		// Counter reset (wg restart / reboot): everything since the reset.
		{"reset", true, 1000, 2000, 30, 40, 30, 40},
		// Reset can be observed per-counter (one grew past, one still below).
		{"partial-reset", true, 1000, 5, 30, 40, 30, 35},
		// First sighting: no baseline exists anywhere, full counters credited.
		{"first-sighting", false, 0, 0, 700, 800, 700, 800},
	}
	for _, c := range cases {
		up, down := deltas(c.known, c.lastRX, c.lastTX, c.curRX, c.curTX)
		if up != c.wantUp || down != c.wantDown {
			t.Errorf("%s: deltas = (up %d, down %d), want (up %d, down %d)",
				c.name, up, down, c.wantUp, c.wantDown)
		}
	}
}
