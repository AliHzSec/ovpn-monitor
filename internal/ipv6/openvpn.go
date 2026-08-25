package ipv6

import (
	"fmt"
	"strings"
)

// ovpnIPv6Line reports whether a normalized (comment-stripped) config line is
// one of the IPv6 directives the toggle manages. Lines are matched by key,
// never by full string equality, so an admin who changed the IPv6 prefix or
// the DNS servers does not break the feature; whatever value sits on the line
// is preserved when the comment prefix moves.
func ovpnIPv6Line(body string) bool {
	if strings.HasPrefix(body, "server-ipv6 ") || body == "server-ipv6" {
		return true
	}
	// Bare tun-ipv6 (the "push tun-ipv6" form is handled below).
	if body == "tun-ipv6" {
		return true
	}
	if !strings.HasPrefix(body, "push ") {
		return false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(body, "push "))
	rest = strings.Trim(rest, `"`)
	switch {
	case rest == "tun-ipv6":
		return true
	case strings.HasPrefix(rest, "route-ipv6"):
		return true
	case rest == "redirect-gateway ipv6":
		// Only the ipv6 variant; "redirect-gateway def1 bypass-dhcp" is IPv4
		// and must stay untouched.
		return true
	case strings.HasPrefix(rest, "dhcp-option DNS "):
		// IPv6 DNS servers contain a colon; the IPv4 DNS lines don't and are
		// left alone.
		return strings.Contains(strings.TrimPrefix(rest, "dhcp-option DNS "), ":")
	}
	return false
}

// ovpnToggle comments or uncomments one line, preserving everything after the
// comment prefix. Uncommenting strips a leading '#' plus at most one space.
func ovpnToggle(line string, enable bool) string {
	trimmed := strings.TrimLeft(line, " \t")
	indent := line[:len(line)-len(trimmed)]
	if enable {
		if strings.HasPrefix(trimmed, "#") {
			s := strings.TrimPrefix(trimmed, "#")
			s = strings.TrimPrefix(s, " ")
			return indent + s
		}
		return line
	}
	if strings.HasPrefix(trimmed, "#") {
		return line
	}
	return indent + "#" + trimmed
}

// ovpnState reports enabled when every IPv6 directive present is active,
// disabled when every one is commented, and unknown when none exist or the
// file mixes both.
func ovpnState(content []byte) State {
	lines := strings.Split(string(content), "\n")
	found := false
	result := StateUnknown
	for _, line := range lines {
		body, active := uncommentedLine(line)
		if !ovpnIPv6Line(body) {
			continue
		}
		found = true
		lineState := StateDisabled
		if active {
			lineState = StateEnabled
		}
		if result == StateUnknown {
			result = lineState
		} else if result != lineState {
			return StateUnknown
		}
	}
	if !found {
		return StateUnknown
	}
	return result
}

// ovpnSet flips the comment prefix on every IPv6 directive line. A file with
// no IPv6 directives at all is an error rather than a silent no-op.
func ovpnSet(content []byte, enabled bool) ([]byte, error) {
	lines := strings.Split(string(content), "\n")
	found := false
	for i, line := range lines {
		body, _ := uncommentedLine(line)
		if !ovpnIPv6Line(body) {
			continue
		}
		found = true
		lines[i] = ovpnToggle(line, enabled)
	}
	if !found {
		return nil, fmt.Errorf("config contains no IPv6 directives; refusing to guess")
	}
	return []byte(strings.Join(lines, "\n")), nil
}
