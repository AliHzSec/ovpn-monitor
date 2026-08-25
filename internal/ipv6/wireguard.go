package ipv6

import (
	"fmt"
	"strings"
)

// wgMarker identifies one of the two mutually exclusive ip6tables lines of a
// WireGuard [Interface] hook: accept (IPv6 forwarding on) or reject (off).
// Exactly one of each pair is meant to be active; the other is commented out.
type wgMarker int

const (
	wgPostUpAccept wgMarker = iota
	wgPostUpReject
	wgPostDownAccept
	wgPostDownReject
)

// wgBody is the full marker line without any comment prefix.
func wgBody(iface string, m wgMarker) string {
	hook := "PostUp"
	op := "-I"
	if m == wgPostDownAccept || m == wgPostDownReject {
		hook = "PostDown"
		op = "-D"
	}
	action := "ACCEPT"
	if m == wgPostUpReject || m == wgPostDownReject {
		action = "REJECT --reject-with icmp6-adm-prohibited"
	}
	return fmt.Sprintf("%s = ip6tables %s FORWARD -i %s -j %s", hook, op, iface, action)
}

// wgPair groups one hook's accept/reject markers; acceptIndex/rejectIndex are
// positions into the pair array.
type wgPair struct {
	accept, reject wgMarker
}

var wgPairs = []wgPair{
	{wgPostUpAccept, wgPostUpReject},
	{wgPostDownAccept, wgPostDownReject},
}

// uncommentedLine splits a raw config line into its body (comment prefix and
// surrounding whitespace stripped) and whether it is active (uncommented).
func uncommentedLine(line string) (body string, active bool) {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "#") {
		return strings.TrimSpace(strings.TrimPrefix(s, "#")), false
	}
	return s, true
}

// wgFindMarkers locates the first occurrence of each marker body, returning
// line indices (-1 when absent) and whether each occurrence is active.
func wgFindMarkers(iface string, lines []string) (idx map[wgMarker]int, active map[wgMarker]bool) {
	idx = map[wgMarker]int{
		wgPostUpAccept: -1, wgPostUpReject: -1,
		wgPostDownAccept: -1, wgPostDownReject: -1,
	}
	active = map[wgMarker]bool{}
	for i, line := range lines {
		body, on := uncommentedLine(line)
		for _, m := range []wgMarker{wgPostUpAccept, wgPostUpReject, wgPostDownAccept, wgPostDownReject} {
			if idx[m] == -1 && body == wgBody(iface, m) {
				idx[m] = i
				active[m] = on
			}
		}
	}
	return idx, active
}

// wgState derives the read state from the markers present in the file. Each
// hook pair reports enabled (accept active, reject not) or disabled (reject
// active, accept not); anything else — a missing pair, both active, neither
// active — makes that pair unknown, and one unknown pair (or disagreement
// between pairs) makes the whole file unknown.
func wgState(iface string) func(content []byte) State {
	return func(content []byte) State {
		lines := strings.Split(string(content), "\n")
		_, active := wgFindMarkers(iface, lines)
		result := StateUnknown
		for _, pair := range wgPairs {
			var pairState State
			switch {
			case active[pair.accept] && !active[pair.reject]:
				pairState = StateEnabled
			case active[pair.reject] && !active[pair.accept]:
				pairState = StateDisabled
			default:
				// Both active, neither active, or both missing: not a state
				// we can act on blindly.
				return StateUnknown
			}
			if result == StateUnknown {
				result = pairState
			} else if result != pairState {
				return StateUnknown
			}
		}
		return result
	}
}

// wgSet rewrites the marker lines to the requested state. A marker missing
// from the file (e.g. an older config that only ever had the ACCEPT lines) is
// inserted directly beneath its partner, so the first write upgrades the file
// to the two-pair layout instead of silently no-oping. A file with no marker
// of a pair at all cannot be upgraded safely and is an error.
func wgSet(iface string) func(content []byte, enabled bool) ([]byte, error) {
	return func(content []byte, enabled bool) ([]byte, error) {
		lines := strings.Split(string(content), "\n")
		idx, _ := wgFindMarkers(iface, lines)

		// desired maps a marker to its target line (commented or active).
		desired := func(m wgMarker) string {
			body := wgBody(iface, m)
			isAccept := m == wgPostUpAccept || m == wgPostDownAccept
			if isAccept == enabled {
				return body
			}
			return "#" + body
		}

		replace := map[int]string{}     // line index -> new content
		insertAfter := map[int]string{} // partner line index -> inserted line
		for _, pair := range wgPairs {
			for _, m := range []wgMarker{pair.accept, pair.reject} {
				partner := pair.reject
				if m == pair.reject {
					partner = pair.accept
				}
				switch {
				case idx[m] >= 0:
					replace[idx[m]] = desired(m)
				case idx[partner] >= 0:
					insertAfter[idx[partner]] = desired(m)
				default:
					return nil, fmt.Errorf("config contains neither IPv6 %s forwarding line; refusing to guess", hookName(m))
				}
			}
		}

		out := make([]string, 0, len(lines)+4)
		for i, line := range lines {
			if newLine, ok := replace[i]; ok {
				out = append(out, newLine)
			} else {
				out = append(out, line)
			}
			if ins, ok := insertAfter[i]; ok {
				out = append(out, ins)
			}
		}
		return []byte(strings.Join(out, "\n")), nil
	}
}

func hookName(m wgMarker) string {
	if m == wgPostDownAccept || m == wgPostDownReject {
		return "PostDown"
	}
	return "PostUp"
}
