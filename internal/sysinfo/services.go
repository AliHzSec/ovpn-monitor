package sysinfo

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func getServiceUptime(osUptimeSec uint64, serviceName string) (uint64, error) {
	// ActiveEnterTimestampMonotonic alone is not enough: systemd keeps the
	// timestamp of the *last* activation even after a unit is stopped, so the
	// current ActiveState must be checked as well.
	out, err := exec.Command("systemctl", "show", serviceName,
		"--property=ActiveState", "--property=ActiveEnterTimestampMonotonic", "--no-pager").Output()
	if err != nil {
		return 0, err
	}
	props := make(map[string]string, 2)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[k] = strings.TrimSpace(v)
		}
	}
	// oneshot units (e.g. wg-quick@wg0) report "active (exited)"; ActiveState
	// is still "active" for them.
	if props["ActiveState"] != "active" {
		return 0, fmt.Errorf("service %q not active", serviceName)
	}
	microseconds, err := strconv.ParseUint(props["ActiveEnterTimestampMonotonic"], 10, 64)
	if err != nil {
		return 0, err
	}
	if microseconds == 0 {
		return 0, fmt.Errorf("service %q not active", serviceName)
	}
	startedAtSec := microseconds / 1_000_000
	if osUptimeSec < startedAtSec {
		return 0, nil
	}
	return osUptimeSec - startedAtSec, nil
}

// WGUnit is the systemd unit that manages the WireGuard interface.
const WGUnit = "wg-quick@wg0"

// openVPNUnitCandidates are the unit names OpenVPN servers commonly run under,
// in preference order.
var openVPNUnitCandidates = []string{"openvpn-server@server", "openvpn@server"}

func getOVPNUptime(osUptimeSec uint64) uint64 {
	for _, name := range openVPNUnitCandidates {
		if uptime, err := getServiceUptime(osUptimeSec, name); err == nil {
			return uptime
		}
	}
	return 0
}

func getWGUptime(osUptimeSec uint64) uint64 {
	uptime, err := getServiceUptime(osUptimeSec, WGUnit)
	if err != nil {
		return 0
	}
	return uptime
}

// OpenVPNUnit resolves which of the candidate OpenVPN units this host actually
// has, falling back to the primary candidate if none is loaded.
func OpenVPNUnit() string {
	for _, name := range openVPNUnitCandidates {
		out, err := exec.Command("systemctl", "show", name,
			"--property=LoadState", "--no-pager").Output()
		if err == nil && strings.TrimSpace(string(out)) == "LoadState=loaded" {
			return name
		}
	}
	return openVPNUnitCandidates[0]
}

// ServiceActive reports whether the given systemd unit is currently active.
func ServiceActive(unit string) bool {
	out, _ := exec.Command("systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out)) == "active"
}
