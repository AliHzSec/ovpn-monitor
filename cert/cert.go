package cert

import (
	"bufio"
	"context"
	"io"
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

// Load rebuilds the set of active (non-revoked) client common names.
//
// The authoritative source of a certificate's status is easy-rsa's
// pki/index.txt, which marks every entry "V" (valid), "R" (revoked) or "E"
// (expired). Revoking a client with easy-rsa does NOT delete its .crt from
// pki/issued/ — it only flips the index.txt status to "R" and adds the serial
// to crl.pem — so simply listing issued/ keeps counting revoked clients as if
// they were still active. We therefore read index.txt (which lives in the pki
// root, one level above issued/) and keep only "V" entries, excluding the
// server's own certificate.
//
// dir is the configured certificate directory (…/pki/issued). When no index.txt
// is found alongside it (a non-easy-rsa deployment), we fall back to listing dir
// so such setups keep working — but that fallback cannot detect revocation.
func (c *Whitelist) Load(dir string) error {
	names, err := loadValidNames(dir)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.names = names
	c.mu.Unlock()
	return nil
}

func loadValidNames(dir string) (map[string]bool, error) {
	// index.txt sits in the pki root, i.e. the parent of the issued/ directory.
	indexPath := filepath.Join(filepath.Dir(filepath.Clean(dir)), "index.txt")
	f, err := os.Open(indexPath)
	if err != nil {
		if os.IsNotExist(err) {
			return loadFromDir(dir)
		}
		return nil, err
	}
	defer f.Close()
	return parseValidNames(f)
}

// parseValidNames reads an easy-rsa index.txt and returns the set of common
// names whose certificate status is "V" (valid), excluding the server cert.
// Each line is tab-separated:
//
//	V<TAB>expiry<TAB><TAB>serial<TAB>filename<TAB>/CN=<name>
//	R<TAB>expiry<TAB>revoked<TAB>serial<TAB>filename<TAB>/CN=<name>
//
// The distinguished name is always the final field and carries the client's CN.
//
// A scan (I/O) error returns a nil map and the error so the caller keeps the
// previous whitelist rather than replacing it with a half-read one — which would
// spuriously mark still-valid clients as revoked.
func parseValidNames(r io.Reader) (map[string]bool, error) {
	names := make(map[string]bool)
	sc := bufio.NewScanner(r)
	// Lines are short, but guard against a corrupt oversized line crashing the scan.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 2 {
			continue
		}
		if strings.TrimSpace(fields[0]) != "V" {
			continue // skip Revoked ("R"), Expired ("E"), and anything unexpected
		}
		cn := commonNameFromDN(fields[len(fields)-1])
		if cn == "" || strings.HasPrefix(cn, "server_") {
			continue
		}
		names[cn] = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return names, nil
}

// commonNameFromDN extracts the CN value from an OpenSSL distinguished name such
// as "/CN=Alice" or "/C=US/O=Org/CN=Alice". Returns "" when no CN is present.
func commonNameFromDN(dn string) string {
	for part := range strings.SplitSeq(dn, "/") {
		if cn, ok := strings.CutPrefix(part, "CN="); ok {
			return strings.TrimSpace(cn)
		}
	}
	return ""
}

// loadFromDir is the fallback used when no index.txt is present: it treats every
// non-server certificate file in dir as a client. It cannot distinguish revoked
// certs (whose .crt lingers in issued/ after revocation), so it is a best effort
// for non-easy-rsa layouts only.
func loadFromDir(dir string) (map[string]bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
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
	return names, nil
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
