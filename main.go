package main

import (
	"bufio"
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
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"ovpnmonitor/auth"
	"ovpnmonitor/cert"
	"ovpnmonitor/config"
	"ovpnmonitor/db"
	"ovpnmonitor/handler"
	"ovpnmonitor/ipp"
	"ovpnmonitor/sniffer"
	"ovpnmonitor/sysinfo"
	"ovpnmonitor/tracker"
	"ovpnmonitor/watcher"
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

	// Step 4: determine VPN subnet from OpenVPN server config, fall back to ipp.txt
	var vpnNet *net.IPNet
	if opts.ServerConfig != "" {
		if cidr, err := parseServerSubnet(opts.ServerConfig); err != nil {
			logger.Warn("could not parse subnet from server config", "path", opts.ServerConfig, "err", err)
		} else if _, parsed, err := net.ParseCIDR(cidr); err != nil {
			logger.Warn("invalid subnet parsed from server config", "cidr", cidr, "err", err)
		} else {
			vpnNet = parsed
		}
	}
	if vpnNet == nil && opts.IPPFile != "" {
		vpnToName, _, loadErr := ipp.LoadIPPFile(opts.IPPFile)
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
	)

	tmpl, err := handler.LoadTemplates(templatesDir)
	if err != nil {
		return err
	}

	certList := &cert.Whitelist{}
	if err := certList.Load(opts.CertsDir); err != nil {
		logger.Warn("Could not load certs directory: " + err.Error())
	}

	online := &tracker.OnlineTracker{}
	ippSt := &ipp.Store{}

	sessions := auth.NewSessionStore(opts.SessionTTL)

	cache := sysinfo.NewStatsCache(
		func(ctx context.Context) (uint64, uint64, error) {
			return database.SumAllTraffic(ctx)
		},
		func(ctx context.Context) (int, int, error) {
			total, err := database.CountClients(ctx)
			if err != nil {
				return 0, 0, err
			}
			onlineSet := online.Get()
			return len(onlineSet), total, nil
		},
	)

	go certList.RefreshLoop(ctx, opts.CertsDir, logger)
	go ippSt.RefreshLoop(ctx, opts.IPPFile, database, logger)
	go cache.Run(ctx)
	go purgeVisitedDomainsLoop(ctx, database, logger)

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
	handler.Register(mux, database, sessions, online, ippSt, tmpl, vpnNet,
		opts.SessionTTL, logger, templatesDir, cache)

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

	w := watcher.Watcher{DB: database, Logger: logger, Certs: certList, Online: online}
	err = w.Watch(ctx, opts.Log)
	waitSnifferDrain()
	return err
}

// visitedDomainRetention is how long aggregated (client, domain) browsing
// records are kept before the daily cleanup job purges them.
const visitedDomainRetention = 90 * 24 * time.Hour

// purgeVisitedDomainsLoop runs an immediate purge on startup and then once a day,
// deleting visited_domains rows whose last_seen is older than the retention
// window so browsing history storage stays bounded.
func purgeVisitedDomainsLoop(ctx context.Context, database *db.DB, logger *slog.Logger) {
	purge := func() {
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		n, err := database.PurgeVisitedDomainsOlderThan(c, visitedDomainRetention)
		if err != nil {
			logger.Warn("visited-domains purge failed", "err", err)
			return
		}
		if n > 0 {
			logger.Info("purged stale visited domains", "rows", n)
		}
	}
	purge()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			purge()
		case <-ctx.Done():
			return
		}
	}
}

// parseServerSubnet reads an OpenVPN server config file and extracts the VPN
// subnet from the "server <ip> <mask>" directive, returning it as a CIDR string.
func parseServerSubnet(configPath string) (string, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "server ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		ipStr := fields[1]
		maskStr := fields[2]

		parsedMask := net.ParseIP(maskStr)
		if parsedMask == nil {
			return "", fmt.Errorf("invalid netmask %q in server config", maskStr)
		}
		m := net.IPMask(parsedMask.To4())
		ones, bits := m.Size()
		if bits == 0 {
			return "", fmt.Errorf("could not determine prefix length from mask %q", maskStr)
		}
		return fmt.Sprintf("%s/%d", ipStr, ones), nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no 'server' directive found in %s", configPath)
}
