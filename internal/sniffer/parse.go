package sniffer

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// parseTLSServerName extracts the SNI host name from the first bytes of a TLS
// ClientHello. It reads ONLY the plaintext server_name extension — no
// decryption, no handshake completion — and is defensive against truncated or
// malformed input (returns "", false rather than panicking on a short buffer).
func parseTLSServerName(b []byte) (string, bool) {
	// TLS record: content_type(1)=0x16 handshake, version(2), length(2)
	if len(b) < 5 || b[0] != 0x16 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	rec := b[5:]
	if recLen < len(rec) {
		rec = rec[:recLen]
	}
	// Handshake: msg_type(1)=0x01 ClientHello, length(3)
	if len(rec) < 4 || rec[0] != 0x01 {
		return "", false
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	hs := rec[4:]
	if hsLen < len(hs) {
		hs = hs[:hsLen]
	}
	// client_version(2) + random(32)
	if len(hs) < 34 {
		return "", false
	}
	p := 34
	// session_id
	if p+1 > len(hs) {
		return "", false
	}
	p += 1 + int(hs[p])
	// cipher_suites
	if p+2 > len(hs) {
		return "", false
	}
	p += 2 + int(binary.BigEndian.Uint16(hs[p:]))
	// compression_methods
	if p+1 > len(hs) {
		return "", false
	}
	p += 1 + int(hs[p])
	// extensions
	if p+2 > len(hs) {
		return "", false
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(hs[p:]))
	p += 2
	if extEnd > len(hs) {
		extEnd = len(hs)
	}
	for p+4 <= extEnd {
		etype := binary.BigEndian.Uint16(hs[p:])
		elen := int(binary.BigEndian.Uint16(hs[p+2:]))
		p += 4
		if p+elen > extEnd {
			break
		}
		if etype == 0x0000 { // server_name
			return parseSNIExtension(hs[p : p+elen])
		}
		p += elen
	}
	return "", false
}

// parseSNIExtension reads a host_name entry out of a server_name extension body.
func parseSNIExtension(ext []byte) (string, bool) {
	// server_name_list length(2)
	if len(ext) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(ext))
	sn := ext[2:]
	if listLen < len(sn) {
		sn = sn[:listLen]
	}
	// entry: name_type(1) + name_length(2) + name
	if len(sn) < 3 || sn[0] != 0x00 { // 0x00 = host_name
		return "", false
	}
	nameLen := int(binary.BigEndian.Uint16(sn[1:]))
	if 3+nameLen > len(sn) {
		return "", false
	}
	host := strings.ToLower(strings.TrimSpace(string(sn[3 : 3+nameLen])))
	if host == "" {
		return "", false
	}
	return host, true
}

// httpMethods are the request-line prefixes accepted as a plausible HTTP
// request, so arbitrary port-80 traffic isn't mistaken for a Host header.
var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
}

// parseHTTPHost extracts the Host header from the first bytes of a plaintext
// HTTP/1.x request. It only inspects the request head (up to the blank line)
// and never reads the body.
func parseHTTPHost(b []byte) (string, bool) {
	looksHTTP := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, m) {
			looksHTTP = true
			break
		}
	}
	if !looksHTTP {
		return "", false
	}
	// Only scan the header block (before the terminating CRLFCRLF).
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		b = b[:i]
	}
	lines := bytes.Split(b, []byte("\r\n"))
	for _, ln := range lines[1:] { // skip the request line
		if len(ln) < 5 || !bytes.EqualFold(ln[:5], []byte("Host:")) {
			continue
		}
		host := strings.TrimSpace(string(ln[5:]))
		if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i:], "]") {
			host = host[:i] // strip :port (but keep IPv6 in brackets intact)
		}
		host = strings.ToLower(strings.Trim(host, "[]"))
		if host == "" {
			return "", false
		}
		return host, true
	}
	return "", false
}
