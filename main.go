package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"ovpnmonitor/internal/auth"
	"ovpnmonitor/internal/config"
	"ovpnmonitor/internal/db"
	"ovpnmonitor/internal/handler"
	"ovpnmonitor/internal/openvpn"
	"ovpnmonitor/internal/sniffer"
	"ovpnmonitor/internal/sysinfo"
	"ovpnmonitor/internal/tracker"
	"ovpnmonitor/internal/wireguard"
)

func main() {
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGABRT,
	)
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	if err := run(ctx, logger); err != nil {
		logger.Error("Exiting: " + err.Error())
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	// Derived so background subsystems (sniffer, loops) also stop when run
	// returns early on an error, not only on a signal.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	exe, err := os.Executable()
	if err != nil {
		exe = "."
	}
	exeDir := filepath.Dir(exe)

	dbPath := filepath.Join(exeDir, "db.sqlite")
	templatesDir := filepath.Join(exeDir, "templates")

	// Step 1: open database
	sqldb, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer sqldb.Close()
	sqldb.SetMaxOpenConns(1)
	sqldb.SetConnMaxLifetime(0)

	if _, err := sqldb.ExecContext(ctx, `PRAGMA journal_mode=WAL`); err != nil {
		return err
	}
	if _, err := sqldb.ExecContext(ctx, `PRAGMA busy_timeout=5000`); err != nil {
		return err
	}

	// Step 2: migrate schema (creates tables and inserts default settings)
	database := db.New(sqldb)
	if err := database.Migrate(ctx); err != nil {
		return err
	}

	// Step 3: load config from database
	opts, err := config.LoadFromDB(ctx, sqldb)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if opts.Addr == "" {
		opts.Addr = "0.0.0.0:80"
	}

	if opts.Log == "" {
		logger.Warn("no status log configured; watcher will be disabled. Set via /settings")
	}
	if opts.CertsDir == "" {
		logger.Warn("no certs directory configured; set via /settings")
	}

	// Shared poll cadence for both VPN systems: a missing or malformed setting
	// degrades to the default rather than broken loops (0s interval would spin).
	if opts.PollInterval <= 0 {
		opts.PollInterval = 10 * time.Second
	}

	// WireGuard defaults, following the same degrade-to-default pattern.
	if opts.WGIface == "" {
		opts.WGIface = "wg0"
	}
	if opts.WGHandshakeTimeout <= 0 {
		opts.WGHandshakeTimeout = 180 * time.Second
	}

	// Step 4: determine VPN subnet from OpenVPN server config, fall back to ipp.txt
	var vpnNet *net.IPNet
	if opts.ServerConfig != "" {
		if cidr, err := openvpn.ParseServerSubnet(opts.ServerConfig); err != nil {
			logger.Warn("could not parse subnet from server config", "path", opts.ServerConfig, "err", err)
		} else if _, parsed, err := net.ParseCIDR(cidr); err != nil {
			logger.Warn("invalid subnet parsed from server config", "cidr", cidr, "err", err)
		} else {
			vpnNet = parsed
		}
	}
	if vpnNet == nil && opts.IPPFile != "" {
		vpnToName, _, loadErr := openvpn.LoadIPPFile(opts.IPPFile)
		if loadErr != nil {
			logger.Warn("could not load ipp.txt for subnet detection", "err", loadErr)
		} else {
			for ip := range vpnToName {
				parsed := net.ParseIP(ip)
				if parsed == nil {
					continue
				}
				_, ipNet, parseErr := net.ParseCIDR(parsed.String() + "/24")
				if parseErr != nil {
					continue
				}
				vpnNet = ipNet
				break
			}
			if vpnNet == nil {
				logger.Warn("no IPs found in ipp.txt, client portal disabled")
			}
		}
	}

	detectedSubnet := "<disabled>"
	if vpnNet != nil {
		detectedSubnet = vpnNet.String()
	}

	logger.Info("startup config",
		"db", dbPath,
		"log", opts.Log,
		"addr", opts.Addr,
		"certs_dir", opts.CertsDir,
		"templates_dir", templatesDir,
		"ipp_file", opts.IPPFile,
		"server_config", opts.ServerConfig,
		"vpn_subnet", detectedSubnet,
		"admin_user", opts.AdminUser,
		"session_ttl", opts.SessionTTL,
		"poll_interval", opts.PollInterval,
		"wireguard_conf", opts.WGConf,
		"wireguard_interface", opts.WGIface,
		"wireguard_handshake_timeout", opts.WGHandshakeTimeout,
	)

	tmpl, err := handler.LoadTemplates(templatesDir)
	if err != nil {
		return err
	}

	certList := &openvpn.CertWhitelist{}
	if err := certList.Load(opts.CertsDir); err != nil {
		logger.Warn("Could not load certs directory: " + err.Error())
	}

	// WireGuard peer registry: the wg-side validity source (analogous to
	// certList). Loaded once here so handlers and the poller have data
	// immediately; kept fresh by its RefreshLoop below. A load failure is not
	// fatal — the panel runs with WireGuard monitoring effectively disabled
	// until the conf becomes readable.
	wgReg := &wireguard.Registry{}
	if opts.WGConf == "" {
		// Deliberately disabled: mark the registry healthy-empty so the reaper
		// keeps pruning revoked certificates exactly as the pure-OpenVPN build.
		wgReg.MarkDisabled()
		logger.Warn("wireguard monitoring disabled: no wireguard_conf configured; set via /settings")
	} else if err := wgReg.Load(opts.WGConf); err != nil {
		logger.Warn("Could not load wireguard conf; wireguard monitoring degraded until it loads",
			"path", opts.WGConf, "err", err)
	}

	online := &tracker.OnlineTracker{}   // OpenVPN, fed by the watcher
	wgOnline := &tracker.OnlineTracker{} // WireGuard, fed by the wg poller
	ippSt := &openvpn.IPPStore{}

	sessions := auth.NewSessionStore(opts.SessionTTL)

	cache := sysinfo.NewStatsCache(
		func(ctx context.Context) (uint64, uint64, error) {
			return database.SumAllTraffic(ctx)
		},
		func(ctx context.Context) (int, int, error) {
			// Total = clients known to the DB that are valid in EITHER system:
			// certificate still valid (certList, sourced from pki/index.txt,
			// excludes revoked clients) OR currently a WireGuard peer. Online is
			// the union of both online sets, deduplicated by name — a client on
			// OpenVPN and WireGuard simultaneously counts once. Both sources
			// filter their online sets by the same validity lists, so online
			// stays a subset of total.
			names, err := database.AllClientNames(ctx)
			if err != nil {
				return 0, 0, err
			}
			total := 0
			for _, name := range names {
				if certList.Contains(name) || wgReg.Contains(name) {
					total++
				}
			}
			onlineSet := online.Get()
			for name := range wgOnline.Get() {
				onlineSet[name] = true
			}
			return len(onlineSet), total, nil
		},
	)

	// Reap revoked/removed clients as part of the refresh cycles of BOTH
	// validity sources: after each successful reload of pki/index.txt or of
	// wg0.conf, purge the DB rows of any client that is valid in neither (see
	// reapRevokedClients). Tying it to the reloads — rather than an independent
	// ticker — guarantees it only ever runs right after a freshly read,
	// complete set from the source that triggered it; the guards inside
	// reapRevokedClients protect against the OTHER source being stale or bad.
	reap := func() {
		reapRevokedClients(ctx, database, certList, wgReg, logger)
	}
	go certList.RefreshLoop(ctx, opts.CertsDir, logger, reap)
	go wgReg.RefreshLoop(ctx, opts.WGConf, database, logger, reap)
	go ippSt.RefreshLoop(ctx, opts.IPPFile, database, logger)
	go cache.Run(ctx)
	go purgeVisitedDomainsLoop(ctx, database, logger)

	// WireGuard poller: the wg-side counterpart of the OpenVPN watcher. Safe
	// to start even when WireGuard is absent — dump failures degrade to a
	// closed-sessions/offline state and are retried, so bringing WireGuard up
	// later starts monitoring without a panel restart.
	if opts.WGConf != "" {
		wgPoller := &wireguard.Poller{
			DB:               database,
			Logger:           logger,
			Registry:         wgReg,
			Online:           wgOnline,
			Iface:            opts.WGIface,
			Interval:         opts.PollInterval,
			HandshakeTimeout: opts.WGHandshakeTimeout,
		}
		go wgPoller.Run(ctx)
	}

	// The poller's interface and the sniffer's capture list are separate
	// settings, so a WireGuard deployment on a non-default interface can end up
	// accounted but never sniffed. Surface that at startup — it is otherwise
	// indistinguishable from peers that simply browsed nothing.
	sniffer.CheckWireGuardCapture(logger, opts.WGConf, opts.WGIface, opts.SnifferIfaces)

	// Domain sniffer: runs in-process on the panel's own DB handle, so there is
	// no separate service and no second database path to keep in sync. It shuts
	// down with ctx; snifferDone closes once its final flush has committed.
	snifferDone := sniffer.Start(ctx, sqldb, sniffer.Config{
		Ifaces:  opts.SnifferIfaces,
		IPPFile: opts.IPPFile,
		WGConf:  opts.SnifferWGConf,
		Snaplen: opts.SnifferSnaplen,
		Workers: opts.SnifferWorkers,
		Queue:   opts.SnifferQueue,
		Flush:   opts.SnifferFlush,
		Dedup:   opts.SnifferDedup,
	}, logger)
	waitSnifferDrain := func() {
		cancel() // make sure the sniffer sees shutdown even on an early error return
		select {
		case <-snifferDone:
		case <-time.After(20 * time.Second):
			logger.Warn("sniffer did not finish draining in time")
		}
	}

	mux := http.NewServeMux()
	handler.Register(mux, handler.Deps{
		DB:           database,
		Sessions:     sessions,
		OVPNOnline:   online,
		WGOnline:     wgOnline,
		Certs:        certList,
		WGRegistry:   wgReg,
		IPP:          ippSt,
		Templates:    tmpl,
		VPNNet:       vpnNet,
		SessionTTL:   opts.SessionTTL,
		Logger:       logger,
		TemplatesDir: templatesDir,
		Cache:        cache,
	})

	srv := &http.Server{Addr: opts.Addr, Handler: mux}
	srvErr := make(chan error, 1)
	go func() {
		logger.Info("Listening on: " + opts.Addr)
		srvErr <- srv.ListenAndServe()
	}()
	select {
	case err := <-srvErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server failed to start: %w", err)
		}
	case <-time.After(200 * time.Millisecond):
		// bound successfully
	}

	// Step 5: start log watcher (disabled if log path not configured)
	if opts.Log == "" {
		logger.Warn("watcher disabled: configure openvpn_status_log via /settings and restart")
		<-ctx.Done()
		waitSnifferDrain()
		return ctx.Err()
	}

	w := openvpn.Watcher{DB: database, Logger: logger, Certs: certList, Online: online,
		PollInterval: opts.PollInterval}
	err = w.Watch(ctx, opts.Log)
	waitSnifferDrain()
	return err
}
