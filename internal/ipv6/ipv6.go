// Package ipv6 toggles IPv6 internet reachability for the managed VPN services
// (WireGuard and OpenVPN) by editing their server config files and restarting
// the corresponding systemd unit.
//
// The config file on disk is the only source of truth: reads parse the live
// file every time, so a hand edit by an admin is reflected in the panel
// immediately rather than masked by a cached value.
//
// Writes are atomic (temp file + fsync + rename, preserving mode and
// ownership), the previous contents are kept in memory and in a timestamped
// .bak next to the file, and a failed service restart rolls the file back to
// the original contents before the error is reported.
//
// Config files may contain private keys (wg0.conf does), so nothing here ever
// logs file contents or command output — only the action, the resulting state
// and sanitized errors.
package ipv6

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// State is the tri-state result of reading a config file: IPv6 markers found
// consistently enabled, consistently disabled, or unknown (markers missing or
// in an inconsistent mix — surfaced to the UI rather than guessed).
type State string

const (
	StateEnabled  State = "enabled"
	StateDisabled State = "disabled"
	StateUnknown  State = "unknown"
)

// systemctlTimeout bounds every systemctl invocation.
const systemctlTimeout = 30 * time.Second

// editor holds the pure content transforms for one service's config format.
type editor struct {
	state func(content []byte) State
	set   func(content []byte, enabled bool) ([]byte, error)
}

// Service toggles IPv6 for one VPN service. The zero-value Restart field
// defaults to a real systemctl restart; tests replace it to simulate
// failures without root.
type Service struct {
	Path   string // server config file, edited in place (atomically)
	Unit   string // systemd unit restarted after a successful write
	Logger *slog.Logger

	// Restart restarts Unit and verifies it came back active. Nil means the
	// real systemctl implementation.
	Restart func(ctx context.Context, unit string) error

	mu     sync.Mutex // guards Set so concurrent toggles cannot interleave writes
	editor editor
}

// NewWireGuard builds the Service for a WireGuard server config. iface is the
// interface name appearing in the ip6tables PostUp/PostDown marker lines.
func NewWireGuard(path, unit, iface string, logger *slog.Logger) *Service {
	if iface == "" {
		iface = "wg0"
	}
	return &Service{
		Path:   path,
		Unit:   unit,
		Logger: logger,
		editor: editor{state: wgState(iface), set: wgSet(iface)},
	}
}

// NewOpenVPN builds the Service for an OpenVPN server config.
func NewOpenVPN(path, unit string, logger *slog.Logger) *Service {
	return &Service{
		Path:   path,
		Unit:   unit,
		Logger: logger,
		editor: editor{state: ovpnState, set: ovpnSet},
	}
}

func (s *Service) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// State parses the live config file and reports the current IPv6 state.
func (s *Service) State() (State, error) {
	content, err := os.ReadFile(s.Path)
	if err != nil {
		return StateUnknown, fmt.Errorf("read config: %w", err)
	}
	return s.editor.state(content), nil
}

// Set rewrites the config file to the requested state and restarts the
// service. On a restart failure the original contents are restored and the
// service restarted again before the error is returned.
func (s *Service) Set(ctx context.Context, enabled bool) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	original, err := os.ReadFile(s.Path)
	if err != nil {
		return StateUnknown, fmt.Errorf("read config: %w", err)
	}
	updated, err := s.editor.set(original, enabled)
	if err != nil {
		return StateUnknown, err
	}

	if err := writeBackup(s.Path, original); err != nil {
		return StateUnknown, fmt.Errorf("backup: %w", err)
	}
	if err := writeFileAtomic(s.Path, updated); err != nil {
		return StateUnknown, fmt.Errorf("write config: %w", err)
	}

	restart := s.Restart
	if restart == nil {
		restart = systemctlRestart
	}
	if err := restart(ctx, s.Unit); err != nil {
		// Roll back: restore the original contents and restart again so the
		// running service matches the file on disk. Both are best-effort —
		// the error below already tells the admin manual attention is needed.
		if rbErr := writeFileAtomic(s.Path, original); rbErr != nil {
			s.log().Error("ipv6 toggle: rollback write failed", "unit", s.Unit, "err", rbErr)
		}
		if rbErr := restart(ctx, s.Unit); rbErr != nil {
			s.log().Error("ipv6 toggle: rollback restart failed", "unit", s.Unit, "err", rbErr)
		}
		s.log().Error("ipv6 toggle: restart failed, config restored", "unit", s.Unit, "err", err)
		return StateUnknown, fmt.Errorf("restarting %s failed after the config change; the original config was restored", s.Unit)
	}

	state := s.editor.state(updated)
	s.log().Info("ipv6 toggled", "unit", s.Unit, "state", state)
	return state, nil
}

// systemctlRestart restarts the unit and then verifies with is-active — a
// zero exit code from restart alone does not prove the service came back up.
func systemctlRestart(ctx context.Context, unit string) error {
	ctx, cancel := context.WithTimeout(ctx, systemctlTimeout)
	defer cancel()
	if _, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart %s: %w", unit, err)
	}
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		return fmt.Errorf("%s did not come back active after restart", unit)
	}
	return nil
}

// writeBackup writes the original contents to a timestamped .bak next to the
// file, keeping the file's mode.
func writeBackup(path string, original []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	bak := path + "." + time.Now().Format("20060102-150405") + ".bak"
	if err := os.WriteFile(bak, original, info.Mode().Perm()); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		chownLike(bak, info)
	}
	return nil
}

// writeFileAtomic writes content to path via a temp file in the same
// directory + fsync + rename, preserving the original file's mode and (when
// running as root) ownership.
func writeFileAtomic(path string, content []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Every exit path except the successful rename removes the temp file.
	defer func() { os.Remove(tmpName) }()

	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		chownLike(tmpName, info)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// fsync the directory so the rename itself is durable.
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// chownLike applies the reference file's ownership to path. Best-effort: a
// chown failure must not abort a config write on systems where the panel runs
// with CAP_CHOWN but odd ownership.
func chownLike(path string, ref os.FileInfo) {
	if st, ok := ref.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(st.Uid), int(st.Gid))
	}
}
