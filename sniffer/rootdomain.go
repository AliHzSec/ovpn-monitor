package sniffer

import (
	"net"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// rootDomain reduces a fully-qualified hostname to its registrable root domain
// using the public suffix list, e.g.:
//
//	www.youtube.com      -> youtube.com
//	i.ytimg.com          -> ytimg.com
//	foo.bar.bbc.co.uk    -> bbc.co.uk
//
// This collapses CDN/subdomain noise so the aggregated table stays small
// (one row per (client, registrable domain) instead of per hostname).
// It returns ("", false) for empty input, bare IP literals, or hostnames with
// no valid registrable domain.
func rootDomain(host string) (string, bool) {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", false
	}
	// Ignore IP literals — an SNI/Host of a raw address is not a domain.
	if net.ParseIP(host) != nil {
		return "", false
	}
	// Must contain a dot and only plausible hostname characters.
	if !strings.Contains(host, ".") {
		return "", false
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || etld1 == "" {
		return "", false
	}
	return etld1, true
}
