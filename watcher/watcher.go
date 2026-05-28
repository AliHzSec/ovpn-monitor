package watcher

import (
	"bufio"
	"context"
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

	for {
		select {
		case event := <-fw.Events:
			if event.Op&fsnotify.Write == fsnotify.Write {
				w.Logger.Info("Log file updated: " + event.Name)
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
	for scanner.Scan() {
		line := scanner.Text()

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
			BytesReceived:  bytesReceived,
			BytesSent:      bytesSent,
			ConnectedSince: connectedSince,
			ConnectedEpoch: epoch,
		})
	}

	return entries, scanner.Err()
}
