// Package domain owns the panel's ONE definition of what a hostname's "root
// domain" is. Every code path that groups browsing history by site — the live
// sniffer that records visits, the database migration that backfills historic
// rows, and any future consumer — must call Root from here rather than
// re-deriving the answer, so the visited-domains UI can never disagree with
// itself about which rows belong together.
//
// It is deliberately a leaf package (public-suffix table and stdlib only) so
// both the sniffer and the database layer can depend on it without either
// depending on the other.
package domain

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Root reduces a fully-qualified hostname to the root domain its visits should
// be grouped under, e.g.:
//
//	www.youtube.com                     -> youtube.com
//	foo.bar.bbc.co.uk                   -> bbc.co.uk
//	firebaseremoteconfig.googleapis.com -> googleapis.com
//
// It returns ("", false) for empty input, bare IP literals, single-label names,
// implausible hostnames, and names that are nothing but a public suffix
// ("co.uk") and therefore have no root domain to group under.
//
// Root is ORGANIZATIONAL grouping, which is why it is not simply
// publicsuffix.EffectiveTLDPlusOne. The public suffix list has two sections:
// the ICANN section (real registry suffixes such as "com" and "co.uk") and the
// PRIVATE section, where operators register their own delegations —
// "googleapis.com", "appspot.com", "s3.amazonaws.com", "blogspot.com",
// "github.io". EffectiveTLDPlusOne honours both, so it answers
// "firebaseremoteconfig.googleapis.com" for that host: correct for the cookie
// policy the list was written for, but wrong here, where it leaks one row per
// Google API endpoint into a table that is supposed to hold one row per site.
// Root therefore ignores the private section and groups on the ICANN suffix.
func Root(host string) (string, bool) {
	host = Normalize(host)
	if host == "" || !validHost(host) {
		return "", false
	}
	// A raw address is not a domain: an SNI or Host header carrying one has no
	// site to group under.
	if net.ParseIP(host) != nil {
		return "", false
	}
	if !strings.Contains(host, ".") {
		return "", false
	}
	suffix := icannSuffix(host)
	// The root domain is the suffix plus exactly one more label. A host that IS
	// the suffix has no such label, and fails this check.
	if !strings.HasSuffix(host, "."+suffix) {
		return "", false
	}
	rest := strings.TrimSuffix(host, "."+suffix)
	if i := strings.LastIndexByte(rest, '.'); i >= 0 {
		rest = rest[i+1:]
	}
	if rest == "" {
		return "", false
	}
	return rest + "." + suffix, true
}

// Normalize puts a hostname into the canonical form the panel stores and
// compares: lowercase, no surrounding whitespace, no IPv6 brackets, and no
// trailing root dot ("GOOGLE.COM." and "google.com" are one site, not two).
// It is idempotent, so callers may apply it before calling Root without
// changing the result.
func Normalize(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	return strings.Trim(host, "[]")
}

// icannSuffix returns host's public suffix as measured against the ICANN
// section of the list only. publicsuffix.PublicSuffix reports whether the
// suffix it found is ICANN-managed; when it is not, the match came from the
// private section, so the suffix is widened one label at a time until an
// ICANN-managed one is reached ("googleapis.com" -> "com",
// "s3.amazonaws.com" -> "com"). Each step strictly shortens the suffix, so the
// loop always terminates. A name that matches nothing at all (an invented TLD,
// "foo.localhost") keeps its final single label as the suffix, which mirrors
// the list's own default rule.
func icannSuffix(host string) string {
	suffix, icann := publicsuffix.PublicSuffix(host)
	for !icann {
		i := strings.IndexByte(suffix, '.')
		if i < 0 {
			break // single label left; nothing further to widen to
		}
		suffix, icann = publicsuffix.PublicSuffix(suffix[i+1:])
	}
	return suffix
}

// validHost rejects strings that cannot be hostnames before they reach the
// public-suffix lookup, so malformed capture data ("a..b", a value with a port
// or a path still attached) is dropped rather than stored as a bogus site.
// Bytes >= 0x80 are allowed so an internationalised name in raw UTF-8 survives
// alongside its punycode ("xn--") form.
func validHost(host string) bool {
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return false // leading, trailing or doubled dot
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			case c == '-' || c == '_':
			case c >= 0x80:
			default:
				return false
			}
		}
	}
	return true
}
