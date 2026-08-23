// Package sniffer is the panel's in-process VPN domain collector. It passively
// captures the plaintext SNI field of TLS ClientHellos (tcp/443) and the Host
// header of HTTP requests (tcp/80) on the OpenVPN and WireGuard tunnel
// interfaces, maps each source IP to a client, and batch-upserts an aggregated
// (client, hostname) history into the panel's visited_domains table, each row
// tagged with the root domain the shared internal/domain package resolves it
// to so the UI can group hostnames by site.
//
// It never decrypts traffic, never terminates TLS, and never writes raw packets
// to disk — only the already-plaintext server name / Host header is read, using
// a kernel BPF filter and a small snaplen so the vast majority of bytes are
// dropped in-kernel. Raw capture requires CAP_NET_RAW (the panel runs as root).
//
// Because it runs inside the panel process, every goroutine here recovers its
// own panics: a parser bug on a hostile payload costs one packet, a capture
// panic costs one reopen of that interface — never the web UI.
package sniffer

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"ovpnmonitor/internal/domain"
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

// Config holds the sniffer tunables, populated from the panel's settings
// table. Zero values fall back to the defaults the standalone sniffer used.
type Config struct {
	Ifaces  string        // comma-separated VPN interfaces to monitor
	IPPFile string        // OpenVPN ipp.txt path (the settings-table value, also used as the Mapper fallback)
	WGConf  string        // WireGuard config path for peer→name mapping
	Snaplen int           // capture snap length (bytes) — enough for a ClientHello/Host
	Workers int           // packet-parsing workers (0 = auto)
	Queue   int           // bounded parse queue; packets are dropped when full
	Flush   time.Duration // how often to batch-upsert aggregates into the DB
	Dedup   time.Duration // per-hostname window in which repeat visits don't re-increment the counter
}

func (c *Config) applyDefaults() {
	if strings.TrimSpace(c.Ifaces) == "" {
		c.Ifaces = "tun0,wg0"
	}
	if c.IPPFile == "" {
		c.IPPFile = "/etc/openvpn/server/ipp.txt"
	}
	if c.WGConf == "" {
		c.WGConf = "/etc/wireguard/wg0.conf"
	}
	if c.Snaplen <= 0 {
		c.Snaplen = 1600
	}
	if c.Workers <= 0 {
		c.Workers = runtime.NumCPU()
		if c.Workers > 8 {
			c.Workers = 8
		}
	}
	if c.Queue <= 0 {
		c.Queue = 4096
	}
	if c.Flush <= 0 {
		c.Flush = 2 * time.Minute
	}
	if c.Dedup <= 0 {
		c.Dedup = 60 * time.Second
	}
}

// Start launches the domain-tracking goroutines (IP→client mapper, aggregator
// flush loop, parse workers, one capture loop per interface) as part of the
// panel's own process, sharing the panel's *sql.DB handle. The visited_domains
// table itself is created by the panel's migration step before Start is called.
//
// The returned channel closes once everything has drained after ctx is
// cancelled — capture stopped, queued packets parsed, and a final flush
// committed — so the caller can wait for it before exiting.
func Start(ctx context.Context, db *sql.DB, cfg Config, logger *slog.Logger) <-chan struct{} {
	cfg.applyDefaults()
	done := make(chan struct{})

	mapper := NewMapper(db, cfg.IPPFile, cfg.WGConf, logger)
	agg := NewAggregator(db, cfg.Dedup, logger)

	// The flush loop gets its own context: it is cancelled only after the
	// workers have drained, so the final flush includes every observation.
	flushCtx, flushCancel := context.WithCancel(context.Background())
	var flushWG sync.WaitGroup
	flushWG.Add(1)
	go func() {
		defer flushWG.Done()
		withRecoverRestart(flushCtx, logger, "aggregator flush loop", func() {
			agg.FlushLoop(flushCtx, cfg.Flush)
		})
	}()

	go withRecoverRestart(ctx, logger, "mapper refresh loop", func() {
		mapper.Refresh()
		refreshLoop(ctx, mapper, 45*time.Second)
	})

	jobs := make(chan job, cfg.Queue)
	var dropped, parsed, recorded atomic.Uint64

	// Worker pool: bounded parsing concurrency. Workers exit when jobs closes.
	var workerWG sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for j := range jobs {
				processJob(j, mapper, agg, &parsed, &recorded, logger)
			}
		}()
	}

	// One self-restarting capture loop per interface, all feeding the shared
	// job queue. An interface that is missing at startup (VPN not up yet) is
	// retried with backoff instead of being skipped forever.
	var capWG sync.WaitGroup
	ifaces := splitList(cfg.Ifaces)
	for _, ifn := range ifaces {
		capWG.Add(1)
		go func(ifn string) {
			defer capWG.Done()
			captureWithRestart(ctx, ifn, cfg.Snaplen, jobs, &dropped, logger)
		}(ifn)
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
		"interfaces", strings.Join(ifaces, ","),
		"workers", cfg.Workers, "snaplen", cfg.Snaplen,
		"flush", cfg.Flush.String(), "dedup", cfg.Dedup.String())

	// Ordered drain: capture stops → queue closes → workers finish → final flush.
	go func() {
		<-ctx.Done()
		logger.Info("sniffer shutting down; draining")
		capWG.Wait()
		close(jobs)
		workerWG.Wait()
		flushCancel() // FlushLoop performs its final flush and returns
		flushWG.Wait()
		close(done)
	}()
	return done
}

// processJob parses one captured payload and records the visit. The recover
// means a parser bug on adversarial packet bytes costs this one packet, not
// the panel process.
func processJob(j job, mapper *Mapper, agg *Aggregator, parsed, recorded *atomic.Uint64, logger *slog.Logger) {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("sniffer worker panic",
				"panic", r, "src_ip", j.srcIP, "dst_port", j.dstPort,
				"stack", string(debug.Stack()))
		}
	}()
	host, ok := extractHost(j)
	if !ok {
		return
	}
	parsed.Add(1)
	// Record the full hostname, tagged with the root domain the UI groups it
	// under. Root also validates: a bare IP, a single-label name or malformed
	// capture data has no site to attribute the visit to and is dropped.
	host = domain.Normalize(host)
	root, ok := domain.Root(host)
	if !ok {
		return
	}
	name, ok := mapper.Lookup(j.srcIP)
	if !ok {
		return // unknown source — not one of our VPN clients
	}
	agg.Observe(name, host, root, time.Now())
	recorded.Add(1)
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

// captureWithRestart keeps a live capture running on one interface for the
// lifetime of ctx. Open failures (interface not up yet), a closed packet
// source, and recovered panics all lead to a reopen after a backoff — the
// interface is never silently abandoned and a capture bug never propagates.
func captureWithRestart(ctx context.Context, iface string, snaplen int, jobs chan<- job, dropped *atomic.Uint64, logger *slog.Logger) {
	backoff := time.Second
	const maxBackoff = 5 * time.Minute
	for {
		if ctx.Err() != nil {
			return
		}
		started := time.Now()
		err := captureOnce(ctx, iface, snaplen, jobs, dropped, logger)
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second // the capture was healthy for a while; reset
		}
		logger.Warn("sniffer capture stopped; will retry",
			"iface", iface, "err", err, "retry_in", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// captureOnce opens iface and pumps packets into jobs until ctx is cancelled
// or the capture ends. A panic anywhere in the capture/decode path is
// recovered and returned as an error so the caller can back off and reopen.
func captureOnce(ctx context.Context, iface string, snaplen int, jobs chan<- job, dropped *atomic.Uint64, logger *slog.Logger) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			logger.Error("sniffer capture panic",
				"iface", iface, "panic", r, "stack", string(debug.Stack()))
		}
	}()
	h, err := openInterface(iface, snaplen)
	if err != nil {
		return err
	}
	defer h.Close()
	capture(ctx, iface, h, jobs, dropped, logger)
	return nil
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

// withRecoverRestart runs fn, and if it panics, logs the panic and runs it
// again after a short delay — until fn returns normally or ctx is cancelled.
// It is the isolation layer that keeps a sniffer bug from taking down the
// whole panel process.
func withRecoverRestart(ctx context.Context, logger *slog.Logger, what string, fn func()) {
	for {
		panicked := func() (p bool) {
			defer func() {
				if r := recover(); r != nil {
					p = true
					logger.Error("sniffer goroutine panic; restarting",
						"goroutine", what, "panic", r, "stack", string(debug.Stack()))
				}
			}()
			fn()
			return false
		}()
		if !panicked || ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
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
