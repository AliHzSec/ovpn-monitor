package ipp

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"ovpnmonitor/db"
)

type Store struct {
	mu        sync.RWMutex
	vpnToName map[string]string
	nameToVPN map[string]string
}

func (is *Store) Get() (map[string]string, map[string]string) {
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

func (is *Store) RefreshLoop(ctx context.Context, ippFile string, database *db.DB, logger *slog.Logger) {
	if ippFile == "" {
		return
	}
	load := func() {
		vpnToName, nameToVPN, err := LoadIPPFile(ippFile)
		if err != nil {
			logger.Warn("ipp refresh failed", "err", err)
			return
		}
		is.mu.Lock()
		is.vpnToName = vpnToName
		is.nameToVPN = nameToVPN
		is.mu.Unlock()

		ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		for name, ip := range nameToVPN {
			if err := database.UpdateClientVPNAddress(ctx2, name, ip); err != nil {
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

func LoadIPPFile(path string) (map[string]string, map[string]string, error) {
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
