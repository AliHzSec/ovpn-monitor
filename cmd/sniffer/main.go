// Command sniffer is a lightweight, standalone VPN domain collector for
// ovpn-monitor. It passively captures the plaintext SNI field of TLS
// ClientHellos (tcp/443) and the Host header of HTTP requests (tcp/80) on the
// OpenVPN and WireGuard tunnel interfaces, maps each source IP to a client, and
// batch-upserts an aggregated (client, root-domain) history into the panel's
// SQLite database.
//
// It never decrypts traffic, never terminates TLS, and never writes raw packets
// to disk — only the already-plaintext server name / Host header is read, using
// a kernel BPF filter and a small snaplen so the vast majority of bytes are
// dropped in-kernel. It requires CAP_NET_RAW (see the systemd unit).
package main

import (
	"context"
	"database/sql"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	_ "github.com/mattn/go-sqlite3"
)

// bpfFilter is applied in-kernel so only TLS/HTTP client traffic reaches
// userspace. Matching on destination port keeps us to the request direction
// (client → server), which is where SNI and Host live.
const bpfFilter = "tcp and (dst port 443 or dst port 80)"

// job is a single captured request payload awaiting parsing. payload is a copy
// (capture uses zero-copy reads, so the backing array is reused after return).
type job struct {
	srcIP   string
	dstPort uint16
	payload []byte
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	var (
		dbPath   = flag.String("db", "db.sqlite", "path to the panel's SQLite database")
		ifaces   = flag.String("ifaces", "tun0,wg0", "comma-separated VPN interfaces to monitor")
		ippPath  = flag.String("ipp", "/etc/openvpn/server/ipp.txt", "OpenVPN ipp.txt path (overridden by the panel's setting if present)")
		wgConf   = flag.String("wg-conf", "/etc/wireguard/wg0.conf", "WireGuard config path for peer→name mapping")
		snaplen  = flag.Int("snaplen", 1600, "capture snap length (bytes) — enough for a ClientHello/Host, no full payloads")
		workers  = flag.Int("workers", 0, "packet-parsing workers (0 = auto)")
		queue    = flag.Int("queue", 4096, "bounded parse queue; packets are dropped when full")
		flushInt = flag.Duration("flush", 2*time.Minute, "how often to batch-upsert aggregates into the DB")
		dedup    = flag.Duration("dedup", 60*time.Second, "per-domain window in which repeat visits don't re-increment the counter")
	)
	flag.Parse()

	if *workers <= 0 {
		*workers = runtime.NumCPU()
		if *workers > 8 {
			*workers = 8
		}
	}

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return err
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return err
	}
	if err := ensureTable(db); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	mapper := NewMapper(db, *ippPath, *wgConf, logger)
	mapper.Refresh()
	go refreshLoop(ctx, mapper, 45*time.Second)

	agg := NewAggregator(db, *dedup, logger)
	go agg.FlushLoop(ctx, *flushInt)

	jobs := make(chan job, *queue)
	var dropped, parsed, recorded atomic.Uint64

	// Worker pool: bounded parsing concurrency. Workers exit when jobs closes.
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				host, ok := extractHost(j)
				if !ok {
					continue
				}
				parsed.Add(1)
				root, ok := rootDomain(host)
				if !ok {
					continue
				}
				name, ok := mapper.Lookup(j.srcIP)
				if !ok {
					continue // unknown source — not one of our VPN clients
				}
				agg.Observe(name, root, time.Now())
				recorded.Add(1)
			}
		}()
	}

	// One capture goroutine per interface, all feeding the shared job queue.
	var capWG sync.WaitGroup
	names := splitList(*ifaces)
	if len(names) == 0 {
		return errNoIfaces
	}
	started := 0
	for _, ifn := range names {
		handle, err := openInterface(ifn, *snaplen)
		if err != nil {
			logger.Warn("skipping interface", "iface", ifn, "err", err)
			continue
		}
		started++
		capWG.Add(1)
		go func(ifn string, h *pcap.Handle) {
			defer capWG.Done()
			defer h.Close()
			capture(ctx, ifn, h, jobs, &dropped, logger)
		}(ifn, handle)
	}
	if started == 0 {
		return errNoIfaces
	}

	// Periodic stats so operators can see it's alive and how much is dropped.
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				logger.Info("sniffer stats",
					"parsed_hosts", parsed.Load(),
					"recorded", recorded.Load(),
					"dropped_packets", dropped.Load())
			case <-ctx.Done():
				return
			}
		}
	}()

	logger.Info("sniffer started",
		"interfaces", strings.Join(names, ","),
		"active", started, "workers", *workers, "snaplen", *snaplen,
		"flush", flushInt.String(), "dedup", dedup.String(), "db", *dbPath)

	<-ctx.Done()
	logger.Info("shutting down; draining")
	capWG.Wait() // capture goroutines observe ctx and return
	close(jobs)  // let workers drain the queue and exit
	wg.Wait()
	// FlushLoop performs a final flush on ctx.Done; give it a moment to finish.
	time.Sleep(500 * time.Millisecond)
	return nil
}

// extractHost pulls the domain from a job's payload based on its port.
func extractHost(j job) (string, bool) {
	switch j.dstPort {
	case 443:
		return parseTLSServerName(j.payload)
	case 80:
		return parseHTTPHost(j.payload)
	default:
		return "", false
	}
}

// openInterface opens a live capture on iface with the BPF filter installed.
func openInterface(iface string, snaplen int) (*pcap.Handle, error) {
	// Immediate mode via a short timeout keeps latency low without full
	// BlockForever semantics; promiscuous mode is off (tunnel traffic is ours).
	h, err := pcap.OpenLive(iface, int32(snaplen), false, 250*time.Millisecond)
	if err != nil {
		return nil, err
	}
	if err := h.SetBPFFilter(bpfFilter); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

// capture reads packets, extracts (srcIP, dstPort, payload), and enqueues a job.
// Under backpressure it drops rather than blocking the capture or growing an
// unbounded queue, keeping memory and capture latency bounded under load.
func capture(ctx context.Context, iface string, h *pcap.Handle, jobs chan<- job, dropped *atomic.Uint64, logger *slog.Logger) {
	logger.Info("capturing", "iface", iface, "link_type", h.LinkType().String())
	src := gopacket.NewPacketSource(h, h.LinkType())
	src.Lazy = true
	src.NoCopy = true
	src.DecodeStreamsAsDatagrams = false

	packets := src.Packets()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-packets:
			if !ok {
				return
			}
			tl := p.TransportLayer()
			if tl == nil {
				continue
			}
			tcp, ok := tl.(*layers.TCP)
			if !ok || len(tcp.Payload) == 0 {
				continue
			}
			nl := p.NetworkLayer()
			if nl == nil {
				continue
			}
			// Copy the payload: NoCopy reads reuse the backing buffer once the
			// next packet is read, and the job is processed asynchronously.
			buf := make([]byte, len(tcp.Payload))
			copy(buf, tcp.Payload)
			j := job{
				srcIP:   nl.NetworkFlow().Src().String(),
				dstPort: uint16(tcp.DstPort),
				payload: buf,
			}
			select {
			case jobs <- j:
			default:
				dropped.Add(1)
			}
		}
	}
}

func refreshLoop(ctx context.Context, m *Mapper, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			m.Refresh()
		case <-ctx.Done():
			return
		}
	}
}

// ensureTable creates visited_domains if the sniffer starts before the panel
// has migrated the DB, so the two processes can come up in any order.
func ensureTable(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS visited_domains (
			id          INTEGER PRIMARY KEY,
			client_name TEXT NOT NULL,
			domain      TEXT NOT NULL,
			first_seen  TEXT NOT NULL,
			last_seen   TEXT NOT NULL,
			visit_count INTEGER NOT NULL DEFAULT 1 CHECK (visit_count >= 0),
			UNIQUE (client_name, domain)
		)`)
	return err
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

var errNoIfaces = &ifaceError{"no capture interface could be opened"}

type ifaceError struct{ msg string }

func (e *ifaceError) Error() string { return e.msg }
