// Package openvpn groups everything OpenVPN-specific: the status-log watcher
// and parser (watcher.go, parse.go), the active-certificate whitelist sourced
// from easy-rsa's pki/index.txt (cert.go), the ipp.txt persistence-file store
// (ipp.go), and the server.conf subnet parser (serverconf.go). Its WireGuard
// counterpart is the wireguard package; shared infrastructure (db, tracker,
// model) lives beside both.
package openvpn

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"ovpnmonitor/internal/db"
	"ovpnmonitor/internal/tracker"
)

type Watcher struct {
	DB     *db.DB
	Logger *slog.Logger
	Certs  *CertWhitelist
	Online *tracker.OnlineTracker

	// PollInterval is the guaranteed resync cadence (the panel-wide
	// poll_interval setting, shared with the WireGuard poller). fsnotify Write
	// events still trigger an immediate re-read in between ticks — the ticker
	// only bounds how stale the state can get when events are missed. Must be
	// set before Watch (main defaults it, mirroring the WireGuard poller).
	PollInterval time.Duration
}

func (w Watcher) Watch(ctx context.Context, file string) error {
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

	ticker := time.NewTicker(w.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case event := <-fw.Events:
			if event.Op&fsnotify.Write == fsnotify.Write {
				w.Logger.Info("Log file updated: " + event.Name)
				w.processLog(ctx, file)
			}
		case <-ticker.C:
			// If OpenVPN stops writing the status file (crash, service stop),
			// no fsnotify Write events arrive and clients would stay "online"
			// forever. Detect a stale file and close out their sessions.
			//
			// The 3-minute staleness threshold is deliberately NOT derived from
			// PollInterval: PollInterval is OUR read cadence, while the file's
			// mtime advances at OpenVPN's own WRITE cadence (its `status`
			// directive, typically 60s). Scaling the threshold down with a short
			// poll interval (e.g. 10s) would flag OpenVPN as unresponsive in the
			// perfectly normal gap between two of its writes.
			if fi, err := os.Stat(file); err == nil && time.Since(fi.ModTime()) > 3*time.Minute {
				w.Logger.Warn("status log not updated recently; assuming OpenVPN is unresponsive",
					"path", file, "last_modified", fi.ModTime().Format(time.RFC3339))
				if err := w.DB.CloseAllOpenSessions(ctx); err != nil {
					w.Logger.Error("Close stale sessions: " + err.Error())
				}
				w.Online.Set(map[string]bool{})
			} else {
				// File is fresh (or stat failed): resync to catch any missed events.
				w.processLog(ctx, file)
			}
		case err := <-fw.Errors:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (w Watcher) ensureKnownClients(ctx context.Context) {
	for _, name := range w.Certs.All() {
		if err := w.DB.UpsertKnownClient(ctx, name); err != nil {
			w.Logger.Warn("Could not upsert client " + name + ": " + err.Error())
		}
	}
}

func (w Watcher) processLog(ctx context.Context, name string) {
	f, err := os.Open(name)
	if err != nil {
		w.Logger.Error("Open log: " + err.Error())
		return
	}
	defer f.Close()

	entries, err := parseOpenVPNLog(f, w.Certs, w.Logger)
	if err != nil {
		// A partial read (no END marker) is expected when we catch OpenVPN
		// mid-rewrite. Skip it without touching online state or sessions, so a
		// torn snapshot can never falsely disconnect clients.
		if errors.Is(err, ErrIncompleteLog) {
			w.Logger.Warn("skipping partial status log read; sessions left unchanged")
			return
		}
		w.Logger.Error("Parse log: " + err.Error())
		return
	}

	onlineSet := make(map[string]bool, len(entries))
	for _, e := range entries {
		onlineSet[e.CommonName] = true
	}
	w.Online.Set(onlineSet)

	if err := w.DB.ProcessLogEntries(ctx, entries); err != nil {
		w.Logger.Error("Update DB: " + err.Error())
	} else {
		w.Logger.Info("Database updated", "online_clients", len(entries))
	}
}
