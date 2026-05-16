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

	// Flag definitions — defaults are empty so we can detect "not set".
	flagDB := flag.String("db", "", "path to SQLite database")
	flagLog := flag.String("log", "", "path to OpenVPN status log")
	flagAddr := flag.String("addr", "", "listen address (host:port)")
	flagCertsDir := flag.String("certs-dir", "", "path to OpenVPN issued certs directory")
	flagTemplatesDir := flag.String("templates-dir", "", "path to HTML templates directory")
	flagAdminUser := flag.String("admin-user", "", "admin username")
	flagAdminPass := flag.String("admin-pass", "", "admin password")
	flagSessionTTL := flag.String("session-ttl", "", "session TTL (e.g. 24h)")
	flag.Parse()

	// resolve applies the priority: CLI flag > env var > built-in default.
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
		adminUser:    adminUser,
		adminPass:    adminPass,
		sessionTTL:   sessionTTL,
	}

	logger.Info("startup config",
		"db", opts.db,
		"log", opts.log,
		"addr", opts.addr,
		"certs_dir", opts.certsDir,
		"templates_dir", opts.templatesDir,
		"admin_user", opts.adminUser,
		"session_ttl", opts.sessionTTL,
	)

	// Load HTML templates from disk
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

	sessions := &sessionStore{
		sessions: make(map[string]time.Time),
		ttl:      opts.sessionTTL,
	}

	go certList.refreshLoop(ctx, opts.certsDir, logger)

	mux := http.NewServeMux()

	// JSON API
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

	// Login
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
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
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			renderTemplate(w, tmpl, "login.html", map[string]interface{}{
				"Error": "Invalid username or password",
			})
			return
		}
		renderTemplate(w, tmpl, "login.html", nil)
	})

	// Logout
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil {
			sessions.delete(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	// Dashboard
	mux.Handle("/", authMiddleware(sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, tmpl, "dashboard.html", nil)
	})))

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
			http.Redirect(w, r, "/login", http.StatusSeeOther)
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

func (d *db) migrate(ctx context.Context) error {
	const s = `
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
	_, err := d.db.ExecContext(ctx, s)
	return err
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
					(common_name, real_address, bytes_received, bytes_sent,
					 last_bytes_received, last_bytes_sent, connected_since, last_seen)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
				now := time.Now().Format("2006-01-02 15:04:05")
				_, err = tx.ExecContext(ctx, ins,
					c.CommonName, c.RealAddress,
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
			bytes_received        = bytes_received + ?,
			bytes_sent            = bytes_sent + ?,
			last_bytes_received   = ?,
			last_bytes_sent       = ?,
			connected_since       = ?,
			last_seen             = ?
			WHERE common_name = ?`
		_, err = tx.ExecContext(ctx, upd,
			c.RealAddress,
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
			&c.CommonName, &c.RealAddress,
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
			BytesReceived:  bytesReceived,
			BytesSent:      bytesSent,
			ConnectedSince: connectedSince,
		})
	}

	return clients, scanner.Err()
}
