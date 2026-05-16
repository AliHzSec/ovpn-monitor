package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	_ "github.com/mattn/go-sqlite3"
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

type options struct {
	db           string
	log          string
	addr         string
	certsDir     string
	templatesDir string
	ippFile      string
	clientSubnet string
	adminUser    string
	adminPass    string
	sessionTTL   time.Duration
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

	dbPath := resolve(*flagDB, "DB_PATH", filepath.Join(exeDir, "db.sqlite"))
	logFile := resolve(*flagLog, "OPENVPN_STATUS_LOG", "")
	addr := resolve(*flagAddr, "ADDR", "0.0.0.0:8080")
	certsDir := resolve(*flagCertsDir, "OPENVPN_CERT_DIR", "")
	templatesDir := resolve(*flagTemplatesDir, "TEMPLATES_DIR", filepath.Join(exeDir, "templates"))
	ippFile := resolve(*flagIPPFile, "OPENVPN_IPP_FILE", "")
	clientSubnet := resolve(*flagClientSubnet, "OPENVPN_CLIENT_SUBNET", "")
	adminUser := resolve(*flagAdminUser, "ADMIN_USER", "admin")
	adminPass := resolve(*flagAdminPass, "ADMIN_PASS", "changeme")
	sessionTTLStr := resolve(*flagSessionTTL, "SESSION_TTL", "24h")

	if certsDir == "" {
		logger.Warn("no certs directory configured; set --certs-dir or OPENVPN_CERT_DIR")
	}
	if logFile == "" {
		logger.Warn("no status log configured; set --log or OPENVPN_STATUS_LOG")
	}

	sessionTTL, err := time.ParseDuration(sessionTTLStr)
	if err != nil {
		sessionTTL = 24 * time.Hour
	}

	opts := options{
		db:           dbPath,
		log:          logFile,
		addr:         addr,
		certsDir:     certsDir,
		templatesDir: templatesDir,
		ippFile:      ippFile,
		clientSubnet: clientSubnet,
		adminUser:    adminUser,
		adminPass:    adminPass,
		sessionTTL:   sessionTTL,
	}

	// Determine VPN subnet for client portal access control.
	var vpnNet *net.IPNet
	if clientSubnet != "" {
		_, vpnNet, err = net.ParseCIDR(clientSubnet)
		if err != nil {
			logger.Warn("invalid OPENVPN_CLIENT_SUBNET, client portal disabled", "err", err)
			vpnNet = nil
		}
	} else if ippFile != "" {
		vpnToName, _, loadErr := loadIPPFile(ippFile)
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
		"db", opts.db,
		"log", opts.log,
		"addr", opts.addr,
		"certs_dir", opts.certsDir,
		"templates_dir", opts.templatesDir,
		"ipp_file", opts.ippFile,
		"vpn_subnet", detectedSubnet,
		"admin_user", opts.adminUser,
		"session_ttl", opts.sessionTTL,
	)

	tmpl, err := loadTemplates(opts.templatesDir)
	if err != nil {
		return err
	}

	sqldb, err := sql.Open("sqlite3", opts.db)
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

	database := &db{db: sqldb}
	if err := database.migrate(ctx); err != nil {
		return err
	}

	certList := &certWhitelist{}
	if err := certList.load(opts.certsDir); err != nil {
		logger.Warn("Could not load certs directory: " + err.Error())
	}

	online := &onlineTracker{}
	ipp := &ippStore{}

	sessions := &sessionStore{
		sessions: make(map[string]time.Time),
		ttl:      opts.sessionTTL,
	}

	go certList.refreshLoop(ctx, opts.certsDir, logger)
	go ipp.refreshLoop(ctx, opts.ippFile, database, logger)

	mux := http.NewServeMux()

	// ── Admin API ────────────────────────────────────────────────────────────
	mux.Handle("/api/clients", authMiddleware(sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("filter")
		clients, err := database.queryClients(r.Context(), filter)
		if err != nil {
			logger.Error("querying clients: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		onlineSet := online.get()
		for i := range clients {
			clients[i].Online = onlineSet[clients[i].CommonName]
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(clients)
	})))

	// ── Client stats API (VPN IP only, no auth) ──────────────────────────────
	mux.HandleFunc("/api/client-stats", func(w http.ResponseWriter, r *http.Request) {
		clientIP, ok := vpnClientIP(r, vpnNet)
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		vpnToName, _ := ipp.get()
		commonName, found := vpnToName[clientIP.String()]
		if !found {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		filter := r.URL.Query().Get("filter")
		c, err := database.clientStatsByName(r.Context(), commonName, cutoffFor(filter))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}
			logger.Error("client stats: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		onlineSet := online.get()
		c.Online = onlineSet[c.CommonName]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	})

	// ── /login → redirect to /panel/login ────────────────────────────────────
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/panel/login", http.StatusMovedPermanently)
	})

	// ── /logout → redirect to /panel/logout ──────────────────────────────────
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/panel/logout", http.StatusMovedPermanently)
	})

	// ── Admin login (GET + POST) ──────────────────────────────────────────────
	mux.HandleFunc("/panel/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			user := r.FormValue("username")
			pass := r.FormValue("password")
			if user == opts.adminUser && pass == opts.adminPass {
				token := generateToken()
				sessions.set(token)
				http.SetCookie(w, &http.Cookie{
					Name:     "session",
					Value:    token,
					Path:     "/",
					HttpOnly: true,
					MaxAge:   int(opts.sessionTTL.Seconds()),
				})
				http.Redirect(w, r, "/panel", http.StatusSeeOther)
				return
			}
			renderTemplate(w, tmpl, "login.html", map[string]interface{}{
				"Error": "Invalid username or password",
			})
			return
		}
		renderTemplate(w, tmpl, "login.html", nil)
	})

	// ── Admin logout ──────────────────────────────────────────────────────────
	mux.HandleFunc("/panel/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil {
			sessions.delete(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/panel/login", http.StatusSeeOther)
	})

	// ── Admin dashboard ───────────────────────────────────────────────────────
	mux.Handle("/panel", authMiddleware(sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, tmpl, "dashboard.html", nil)
	})))

	// ── Client portal (root) ──────────────────────────────────────────────────
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		clientIP, ok := vpnClientIP(r, vpnNet)
		if !ok {
			http.Redirect(w, r, "/panel/login", http.StatusSeeOther)
			return
		}
		vpnToName, _ := ipp.get()
		commonName, found := vpnToName[clientIP.String()]
		if !found {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#070b0f;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center"><p>Your VPN session was not found. Please reconnect.</p></body></html>`)
			return
		}
		data := clientPortalData{
			CommonName: commonName,
			VPNAddress: clientIP.String(),
		}
		c, err := database.clientByVPNAddress(r.Context(), clientIP.String())
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			logger.Error("client portal db: " + err.Error())
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		if c != nil {
			onlineSet := online.get()
			data.Online = onlineSet[c.CommonName]
			data.ConnectedSince = c.ConnectedSince
			data.LastSeen = c.LastSeen
		}
		renderTemplate(w, tmpl, "client.html", data)
	})

	srv := &http.Server{Addr: opts.addr, Handler: mux}
	srvErr := make(chan error, 1)
	go func() {
		logger.Info("Listening on: " + opts.addr)
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

	w := watcher{db: database, logger: logger, certs: certList, online: online}
	return w.watch(ctx, opts.log)
}

// loadTemplates parses all .html files in dir; each is named by its filename.
func loadTemplates(dir string) (*template.Template, error) {
	return template.ParseGlob(filepath.Join(dir, "*.html"))
}

func renderTemplate(w http.ResponseWriter, tmpl *template.Template, name string, data interface{}) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// ── IPP Store ────────────────────────────────────────────────────────────────

type ippStore struct {
	mu        sync.RWMutex
	vpnToName map[string]string // vpn_ip → common_name
	nameToVPN map[string]string // common_name → vpn_ip
}

func (is *ippStore) get() (map[string]string, map[string]string) {
	is.mu.RLock()
	defer is.mu.RUnlock()
	vpnToName := make(map[string]string, len(is.vpnToName))
	for k, v := range is.vpnToName {
		vpnToName[k] = v
	}
	nameToVPN := make(map[string]string, len(is.nameToVPN))
	for k, v := range is.nameToVPN {
		nameToVPN[k] = v
	}
	return vpnToName, nameToVPN
}

func (is *ippStore) refreshLoop(ctx context.Context, ippFile string, database *db, logger *slog.Logger) {
	if ippFile == "" {
		return
	}
	load := func() {
		vpnToName, nameToVPN, err := loadIPPFile(ippFile)
		if err != nil {
			logger.Warn("ipp refresh failed", "err", err)
			return
		}
		is.mu.Lock()
		is.vpnToName = vpnToName
		is.nameToVPN = nameToVPN
		is.mu.Unlock()

		// Sync vpn_address into DB for each known client.
		ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		for name, ip := range nameToVPN {
			if _, err := database.db.ExecContext(ctx2,
				`UPDATE clients SET vpn_address = ? WHERE common_name = ?`, ip, name); err != nil {
				logger.Warn("ipp db update failed", "name", name, "err", err)
			}
		}

		subnet := "<unknown>"
		for ip := range vpnToName {
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			_, ipNet, err := net.ParseCIDR(parsed.String() + "/24")
			if err != nil {
				continue
			}
			subnet = ipNet.String()
			break
		}
		logger.Info("ipp file loaded", "clients", len(vpnToName), "subnet", subnet)
	}
	load()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			load()
		case <-ctx.Done():
			return
		}
	}
}

func loadIPPFile(path string) (map[string]string, map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	vpnToName := make(map[string]string)
	nameToVPN := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		ip := strings.TrimSpace(fields[1])
		if name == "" || ip == "" {
			continue
		}
		vpnToName[ip] = name
		nameToVPN[name] = ip
	}
	return vpnToName, nameToVPN, scanner.Err()
}

// vpnClientIP parses the remote address and checks whether it falls inside vpnNet.
func vpnClientIP(r *http.Request, vpnNet *net.IPNet) (net.IP, bool) {
	if vpnNet == nil {
		return nil, false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, false
	}
	return ip, vpnNet.Contains(ip)
}

// ── Cert Whitelist ──────────────────────────────────────────────────────────

type certWhitelist struct {
	mu    sync.RWMutex
	names map[string]bool
}

func (c *certWhitelist) load(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	names := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		if strings.HasPrefix(name, "server_") {
			continue
		}
		names[name] = true
	}
	c.mu.Lock()
	c.names = names
	c.mu.Unlock()
	return nil
}

func (c *certWhitelist) contains(name string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.names[name]
}

func (c *certWhitelist) all() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]string, 0, len(c.names))
	for name := range c.names {
		result = append(result, name)
	}
	return result
}

func (c *certWhitelist) refreshLoop(ctx context.Context, dir string, logger *slog.Logger) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.load(dir); err != nil {
				logger.Warn("Cert refresh failed: " + err.Error())
			} else {
				logger.Info("Cert whitelist refreshed")
			}
		case <-ctx.Done():
			return
		}
	}
}

// ── Online Tracker ──────────────────────────────────────────────────────────

type onlineTracker struct {
	mu      sync.RWMutex
	clients map[string]bool
}

func (o *onlineTracker) set(clients map[string]bool) {
	o.mu.Lock()
	o.clients = clients
	o.mu.Unlock()
}

func (o *onlineTracker) get() map[string]bool {
	o.mu.RLock()
	defer o.mu.RUnlock()
	result := make(map[string]bool, len(o.clients))
	for k, v := range o.clients {
		result[k] = v
	}
	return result
}

// ── Session Store ───────────────────────────────────────────────────────────

type sessionStore struct {
	mu       sync.RWMutex
	sessions map[string]time.Time
	ttl      time.Duration
}

func (s *sessionStore) set(token string) {
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(s.ttl)
	s.mu.Unlock()
}

func (s *sessionStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func authMiddleware(sessions *sessionStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err != nil || !sessions.valid(c.Value) {
			http.Redirect(w, r, "/panel/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── Database ────────────────────────────────────────────────────────────────

type db struct{ db *sql.DB }

type client struct {
	CommonName            string `json:"common_name"`
	RealAddress           string `json:"real_address"`
	VPNAddress            string `json:"vpn_address"`
	BytesReceived         int64  `json:"bytes_received"`
	BytesSent             int64  `json:"bytes_sent"`
	TotalTraffic          int64  `json:"total_traffic"`
	ConnectedSince        string `json:"connected_since"`
	LastSeen              string `json:"last_seen"`
	BytesReceivedReadable string `json:"bytes_received_readable"`
	BytesSentReadable     string `json:"bytes_sent_readable"`
	TotalTrafficReadable  string `json:"total_traffic_readable"`
	Online                bool   `json:"online"`
}

type clientPortalData struct {
	CommonName     string
	VPNAddress     string
	Online         bool
	ConnectedSince string
	LastSeen       string
}

func (d *db) migrate(ctx context.Context) error {
	const create = `
	CREATE TABLE IF NOT EXISTS clients (
		id                   INTEGER PRIMARY KEY,
		common_name          TEXT NOT NULL UNIQUE,
		real_address         TEXT NOT NULL DEFAULT '',
		bytes_received       INTEGER NOT NULL DEFAULT 0 CHECK (bytes_received >= 0),
		bytes_sent           INTEGER NOT NULL DEFAULT 0 CHECK (bytes_sent >= 0),
		last_bytes_received  INTEGER NOT NULL DEFAULT 0 CHECK (last_bytes_received >= 0),
		last_bytes_sent      INTEGER NOT NULL DEFAULT 0 CHECK (last_bytes_sent >= 0),
		connected_since      TEXT NOT NULL DEFAULT '',
		last_seen            TEXT NOT NULL DEFAULT ''
	);`
	if _, err := d.db.ExecContext(ctx, create); err != nil {
		return err
	}
	// Add vpn_address column if it doesn't exist yet.
	rows, err := d.db.QueryContext(ctx, `PRAGMA table_info(clients)`)
	if err != nil {
		return err
	}
	hasVPNAddr := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "vpn_address" {
			hasVPNAddr = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasVPNAddr {
		_, err = d.db.ExecContext(ctx, `ALTER TABLE clients ADD COLUMN vpn_address TEXT NOT NULL DEFAULT ''`)
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *db) upsertKnownClient(ctx context.Context, name string) error {
	const s = `INSERT OR IGNORE INTO clients (common_name) VALUES (?)`
	_, err := d.db.ExecContext(ctx, s, name)
	return err
}

func (d *db) updateClients(ctx context.Context, clients []client) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, c := range clients {
		var lastReceived, lastSent int64
		const q = `SELECT last_bytes_received, last_bytes_sent FROM clients WHERE common_name = ?`
		err := tx.QueryRowContext(ctx, q, c.CommonName).Scan(&lastReceived, &lastSent)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				const ins = `INSERT INTO clients
					(common_name, real_address, vpn_address, bytes_received, bytes_sent,
					 last_bytes_received, last_bytes_sent, connected_since, last_seen)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
				now := time.Now().Format("2006-01-02 15:04:05")
				_, err = tx.ExecContext(ctx, ins,
					c.CommonName, c.RealAddress, c.VPNAddress,
					c.BytesReceived, c.BytesSent,
					c.BytesReceived, c.BytesSent,
					c.ConnectedSince, now,
				)
				if err != nil {
					return err
				}
				continue
			}
			return err
		}

		recvDiff := diff(c.BytesReceived, lastReceived)
		sentDiff := diff(c.BytesSent, lastSent)
		now := time.Now().Format("2006-01-02 15:04:05")

		const upd = `UPDATE clients SET
			real_address          = ?,
			vpn_address           = ?,
			bytes_received        = bytes_received + ?,
			bytes_sent            = bytes_sent + ?,
			last_bytes_received   = ?,
			last_bytes_sent       = ?,
			connected_since       = ?,
			last_seen             = ?
			WHERE common_name = ?`
		_, err = tx.ExecContext(ctx, upd,
			c.RealAddress, c.VPNAddress,
			recvDiff, sentDiff,
			c.BytesReceived, c.BytesSent,
			c.ConnectedSince,
			now,
			c.CommonName,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func cutoffFor(filter string) string {
	now := time.Now()
	switch filter {
	case "today":
		return now.Format("2006-01-02") + " 00:00:00"
	case "week":
		return now.AddDate(0, 0, -7).Format("2006-01-02 15:04:05")
	case "month":
		return now.AddDate(0, -1, 0).Format("2006-01-02 15:04:05")
	default:
		return ""
	}
}

func (d *db) queryClients(ctx context.Context, filter string) ([]client, error) {
	cutoff := cutoffFor(filter)

	const base = `SELECT
		common_name,
		real_address,
		vpn_address,
		bytes_received,
		bytes_sent,
		(bytes_received + bytes_sent) AS total_traffic,
		connected_since,
		last_seen
		FROM clients`

	var (
		rows *sql.Rows
		err  error
	)
	if cutoff == "" {
		rows, err = d.db.QueryContext(ctx, base+` ORDER BY (bytes_received + bytes_sent) DESC`)
	} else {
		rows, err = d.db.QueryContext(ctx, base+` WHERE last_seen >= ? ORDER BY (bytes_received + bytes_sent) DESC`, cutoff)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []client
	for rows.Next() {
		var c client
		if err := rows.Scan(
			&c.CommonName, &c.RealAddress, &c.VPNAddress,
			&c.BytesReceived, &c.BytesSent,
			&c.TotalTraffic, &c.ConnectedSince, &c.LastSeen,
		); err != nil {
			return nil, err
		}
		c.BytesReceivedReadable = formatBytes(c.BytesReceived)
		c.BytesSentReadable = formatBytes(c.BytesSent)
		c.TotalTrafficReadable = formatBytes(c.TotalTraffic)
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return clients, nil
}

func (d *db) clientByVPNAddress(ctx context.Context, vpnAddr string) (*client, error) {
	const q = `SELECT common_name, vpn_address, bytes_received, bytes_sent,
		(bytes_received + bytes_sent) AS total_traffic, connected_since, last_seen
		FROM clients WHERE vpn_address = ?`
	var c client
	err := d.db.QueryRowContext(ctx, q, vpnAddr).Scan(
		&c.CommonName, &c.VPNAddress,
		&c.BytesReceived, &c.BytesSent,
		&c.TotalTraffic, &c.ConnectedSince, &c.LastSeen,
	)
	if err != nil {
		return nil, err
	}
	c.BytesReceivedReadable = formatBytes(c.BytesReceived)
	c.BytesSentReadable = formatBytes(c.BytesSent)
	c.TotalTrafficReadable = formatBytes(c.TotalTraffic)
	return &c, nil
}

func (d *db) clientStatsByName(ctx context.Context, commonName, cutoff string) (*client, error) {
	const base = `SELECT common_name, vpn_address, bytes_received, bytes_sent,
		(bytes_received + bytes_sent) AS total_traffic, connected_since, last_seen
		FROM clients WHERE common_name = ?`
	var row *sql.Row
	if cutoff != "" {
		row = d.db.QueryRowContext(ctx, base+" AND last_seen >= ?", commonName, cutoff)
	} else {
		row = d.db.QueryRowContext(ctx, base, commonName)
	}
	var c client
	if err := row.Scan(
		&c.CommonName, &c.VPNAddress,
		&c.BytesReceived, &c.BytesSent,
		&c.TotalTraffic, &c.ConnectedSince, &c.LastSeen,
	); err != nil {
		return nil, err
	}
	c.BytesReceivedReadable = formatBytes(c.BytesReceived)
	c.BytesSentReadable = formatBytes(c.BytesSent)
	c.TotalTrafficReadable = formatBytes(c.TotalTraffic)
	return &c, nil
}

func diff(current, previous int64) int64 {
	if current >= previous {
		return current - previous
	}
	return current
}

// ── Watcher ─────────────────────────────────────────────────────────────────

type watcher struct {
	db     *db
	logger *slog.Logger
	certs  *certWhitelist
	online *onlineTracker
}

func (w watcher) watch(ctx context.Context, file string) error {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer fw.Close()

	if err := fw.Add(file); err != nil {
		return err
	}

	w.ensureKnownClients(ctx)
	w.processLog(ctx, file)

	for {
		select {
		case event := <-fw.Events:
			if event.Op&fsnotify.Write == fsnotify.Write {
				w.logger.Info("Log file updated: " + event.Name)
				w.processLog(ctx, file)
			}
		case err := <-fw.Errors:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (w watcher) ensureKnownClients(ctx context.Context) {
	for _, name := range w.certs.all() {
		if err := w.db.upsertKnownClient(ctx, name); err != nil {
			w.logger.Warn("Could not upsert client " + name + ": " + err.Error())
		}
	}
}

func (w watcher) processLog(ctx context.Context, name string) {
	f, err := os.Open(name)
	if err != nil {
		w.logger.Error("Open log: " + err.Error())
		return
	}
	defer f.Close()

	clients, err := parseOpenVPNLog(f, w.certs, w.logger)
	if err != nil {
		w.logger.Error("Parse log: " + err.Error())
		return
	}

	onlineSet := make(map[string]bool, len(clients))
	for _, c := range clients {
		onlineSet[c.CommonName] = true
	}
	w.online.set(onlineSet)

	if err := w.db.updateClients(ctx, clients); err != nil {
		w.logger.Error("Update DB: " + err.Error())
	} else {
		w.logger.Info("Database updated", "online_clients", len(clients))
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func formatBytes(bytes int64) string {
	const (
		KB = 1 << 10
		MB = 1 << 20
		GB = 1 << 30
		TB = 1 << 40
	)
	switch {
	case bytes >= TB:
		return strconv.FormatFloat(float64(bytes)/TB, 'f', 2, 64) + " TB"
	case bytes >= GB:
		return strconv.FormatFloat(float64(bytes)/GB, 'f', 2, 64) + " GB"
	case bytes >= MB:
		return strconv.FormatFloat(float64(bytes)/MB, 'f', 2, 64) + " MB"
	case bytes >= KB:
		return strconv.FormatFloat(float64(bytes)/KB, 'f', 2, 64) + " KB"
	default:
		return strconv.FormatInt(bytes, 10) + " B"
	}
}

func parseOpenVPNLog(f io.Reader, certs *certWhitelist, logger *slog.Logger) ([]client, error) {
	scanner := bufio.NewScanner(f)

	var clients []client
	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "CLIENT_LIST,") {
			continue
		}

		record := strings.Split(line, ",")
		// FORMAT: CLIENT_LIST,CommonName,RealAddress,VirtualAddr,VirtualIPv6,BytesReceived,BytesSent,ConnectedSince,ConnectedSinceT,...
		if len(record) < 8 {
			continue
		}

		name := record[1]
		if name == "UNDEF" || !certs.contains(name) {
			continue
		}

		// record[6]: bytes sent by server TO client = downloaded by client
		bytesReceived, err := strconv.ParseInt(record[6], 10, 64)
		if err != nil {
			logger.Warn("skipping malformed log line", "line", line, "error", err)
			continue
		}
		// record[5]: bytes received by server FROM client = uploaded by client
		bytesSent, err := strconv.ParseInt(record[5], 10, 64)
		if err != nil {
			logger.Warn("skipping malformed log line", "line", line, "error", err)
			continue
		}
		var connectedSince string
		if len(record) > 8 {
			if epoch, err := strconv.ParseInt(record[8], 10, 64); err == nil {
				connectedSince = time.Unix(epoch, 0).UTC().Format("2006-01-02 15:04:05")
			}
		}
		if connectedSince == "" {
			connectedSince = record[7]
		}

		clients = append(clients, client{
			CommonName:     name,
			RealAddress:    record[2],
			VPNAddress:     record[3], // VirtualAddr from status log
			BytesReceived:  bytesReceived,
			BytesSent:      bytesSent,
			ConnectedSince: connectedSince,
		})
	}

	return clients, scanner.Err()
}
