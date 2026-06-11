package watcher

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"ovpnmonitor/cert"
	"ovpnmonitor/db"
	"ovpnmonitor/model"
	"ovpnmonitor/tracker"
)

// ErrIncompleteLog signals that the status file was read mid-rewrite (no END
// marker). It is an expected, transient condition — callers must skip the read
// entirely rather than act on a partial snapshot.
var ErrIncompleteLog = errors.New("incomplete status log read: missing END marker")

type Watcher struct {
	DB     *db.DB
	Logger *slog.Logger
	Certs  *cert.Whitelist
	Online *tracker.OnlineTracker
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

	ticker := time.NewTicker(60 * time.Second)
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

func parseOpenVPNLog(f io.Reader, certs *cert.Whitelist, logger *slog.Logger) ([]model.LogEntry, error) {
	scanner := bufio.NewScanner(f)

	var entries []model.LogEntry
	sawEnd := false
	for scanner.Scan() {
		line := scanner.Text()

		// OpenVPN terminates a complete status dump with an "END" line. Its
		// presence means we read the file in full rather than mid-rewrite.
		if line == "END" {
			sawEnd = true
			continue
		}

		if !strings.HasPrefix(line, "CLIENT_LIST,") {
			continue
		}

		record := strings.Split(line, ",")
		// FORMAT: CLIENT_LIST,CommonName,RealAddress,VirtualAddr,VirtualIPv6,BytesReceived,BytesSent,ConnectedSince,ConnectedSinceT,...
		if len(record) < 9 {
			continue
		}

		name := record[1]
		if name == "UNDEF" || !certs.Contains(name) {
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

		epoch, err := strconv.ParseInt(record[8], 10, 64)
		if err != nil {
			logger.Warn("skipping malformed log line", "line", line, "error", err)
			continue
		}
		// Guard against torn/partial reads of status.log yielding a garbage
		// time_t (e.g. an extra digit appended), which would otherwise be
		// stored as an absurd far-future connected-since date.
		const minEpoch = 946684800 // 2000-01-01 UTC
		if epoch < minEpoch || epoch > time.Now().Add(24*time.Hour).Unix() {
			logger.Warn("skipping line with implausible connected-since epoch", "epoch", epoch, "common_name", name)
			continue
		}
		connectedSince := time.Unix(epoch, 0).Local().Format("2006-01-02 15:04:05")

		entries = append(entries, model.LogEntry{
			CommonName:     name,
			RealAddress:    record[2],
			VPNAddress:     record[3],
			Protocol:       protocolOf(record[2]),
			BytesReceived:  bytesReceived,
			BytesSent:      bytesSent,
			ConnectedSince: connectedSince,
			ConnectedEpoch: epoch,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !sawEnd {
		// No END marker: the file was truncated or read mid-rewrite. Returning the
		// sentinel makes the caller skip this read instead of acting on a partial
		// snapshot (which would corrupt byte counts and spuriously disconnect clients).
		return nil, ErrIncompleteLog
	}

	return entries, nil
}

// protocolOf returns the transport prefix of an OpenVPN real-address
// ("tcp4-server", "udp4"), which is stable for the life of a connection —
// unlike the IP:port, which can change under UDP float. It is used as part of
// session identity so the UDP and TCP legs of a protocol switch that happen to
// share a one-second connected_since are not merged into one row.
func protocolOf(realAddr string) string {
	if i := strings.IndexByte(realAddr, ':'); i >= 0 {
		return realAddr[:i]
	}
	return realAddr
}
