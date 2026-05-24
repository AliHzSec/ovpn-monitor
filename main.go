package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
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
	"ovpnmonitor/auth"
	"ovpnmonitor/cert"
	"ovpnmonitor/config"
	"ovpnmonitor/db"
	"ovpnmonitor/handler"
	"ovpnmonitor/ipp"
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
	exe, err := os.Executable()
	if err != nil {
		exe = "."
	}
	exeDir := filepath.Dir(exe)

	flagDB := flag.String("db", "", "path to SQLite database")
	flagLog := flag.String("log", "", "path to OpenVPN status log")
	flagAddr := flag.String("addr", "", "listen address (host:port)")
	flagCertsDir := flag.String("certs-dir", "", "path to OpenVPN issued certs directory")
	flagTemplatesDir := flag.String("templates-dir", "", "path to HTML templates directory")
	flagIPPFile := flag.String("ipp-file", "", "path to OpenVPN ipp.txt file")
	flagClientSubnet := flag.String("client-subnet", "", "VPN client subnet override (CIDR)")
	flagAdminUser := flag.String("admin-user", "", "admin username")
	flagAdminPass := flag.String("admin-pass", "", "admin password")
	flagSessionTTL := flag.String("session-ttl", "", "session TTL (e.g. 24h)")
	flag.Parse()

	resolve := func(flagVal, envKey, def string) string {
		if flagVal != "" {
			return flagVal
		}
		if v := os.Getenv(envKey); v != "" {
			return v
		}
		return def
	}

	sessionTTLStr := resolve(*flagSessionTTL, "SESSION_TTL", "24h")
	sessionTTL, err := time.ParseDuration(sessionTTLStr)
	if err != nil {
		sessionTTL = 24 * time.Hour
	}

	opts := config.Options{
		DB:           resolve(*flagDB, "DB_PATH", filepath.Join(exeDir, "db.sqlite")),
		Log:          resolve(*flagLog, "OPENVPN_STATUS_LOG", ""),
		Addr:         resolve(*flagAddr, "ADDR", "0.0.0.0:8080"),
		CertsDir:     resolve(*flagCertsDir, "OPENVPN_CERT_DIR", ""),
		TemplatesDir: resolve(*flagTemplatesDir, "TEMPLATES_DIR", filepath.Join(exeDir, "templates")),
		IPPFile:      resolve(*flagIPPFile, "OPENVPN_IPP_FILE", ""),
		ClientSubnet: resolve(*flagClientSubnet, "OPENVPN_CLIENT_SUBNET", ""),
		AdminUser:    resolve(*flagAdminUser, "ADMIN_USER", "admin"),
		AdminPass:    resolve(*flagAdminPass, "ADMIN_PASS", "changeme"),
		SessionTTL:   sessionTTL,
	}

	if opts.CertsDir == "" {
		logger.Warn("no certs directory configured; set --certs-dir or OPENVPN_CERT_DIR")
	}
	if opts.Log == "" {
		logger.Warn("no status log configured; set --log or OPENVPN_STATUS_LOG")
	}

	// Determine VPN subnet for client portal access control.
	var vpnNet *net.IPNet
	if opts.ClientSubnet != "" {
		_, vpnNet, err = net.ParseCIDR(opts.ClientSubnet)
		if err != nil {
			logger.Warn("invalid OPENVPN_CLIENT_SUBNET, client portal disabled", "err", err)
			vpnNet = nil
		}
	} else if opts.IPPFile != "" {
		vpnToName, _, loadErr := ipp.LoadIPPFile(opts.IPPFile)
		if loadErr != nil {
			logger.Warn("could not load ipp.txt for subnet detection, client portal disabled", "err", loadErr)
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
	} else {
		logger.Warn("no ipp file configured; client portal disabled")
	}

	detectedSubnet := "<disabled>"
	if vpnNet != nil {
		detectedSubnet = vpnNet.String()
	}

	logger.Info("startup config",
		"db", opts.DB,
		"log", opts.Log,
		"addr", opts.Addr,
		"certs_dir", opts.CertsDir,
		"templates_dir", opts.TemplatesDir,
		"ipp_file", opts.IPPFile,
		"vpn_subnet", detectedSubnet,
		"admin_user", opts.AdminUser,
		"session_ttl", opts.SessionTTL,
	)

	tmpl, err := handler.LoadTemplates(opts.TemplatesDir)
	if err != nil {
		return err
	}

	sqldb, err := sql.Open("sqlite3", opts.DB)
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

	database := db.New(sqldb)
	if err := database.Migrate(ctx); err != nil {
		return err
	}

	certList := &cert.Whitelist{}
	if err := certList.Load(opts.CertsDir); err != nil {
		logger.Warn("Could not load certs directory: " + err.Error())
	}

	online := &tracker.OnlineTracker{}
	ippSt := &ipp.Store{}

	sessions := auth.NewSessionStore(opts.SessionTTL)

	go certList.RefreshLoop(ctx, opts.CertsDir, logger)
	go ippSt.RefreshLoop(ctx, opts.IPPFile, database, logger)

	mux := http.NewServeMux()
	handler.Register(mux, database, sessions, online, ippSt, tmpl, vpnNet,
		opts.AdminUser, opts.AdminPass, opts.SessionTTL, logger)

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

	w := watcher.Watcher{DB: database, Logger: logger, Certs: certList, Online: online}
	return w.Watch(ctx, opts.Log)
}
