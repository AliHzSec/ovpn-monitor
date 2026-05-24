package cert

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Whitelist struct {
	mu    sync.RWMutex
	names map[string]bool
}

func (c *Whitelist) Load(dir string) error {
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

func (c *Whitelist) Contains(name string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.names[name]
}

func (c *Whitelist) All() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]string, 0, len(c.names))
	for name := range c.names {
		result = append(result, name)
	}
	return result
}

func (c *Whitelist) RefreshLoop(ctx context.Context, dir string, logger *slog.Logger) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := c.Load(dir); err != nil {
				logger.Warn("Cert refresh failed: " + err.Error())
			} else {
				logger.Info("Cert whitelist refreshed")
			}
		case <-ctx.Done():
			return
		}
	}
}
