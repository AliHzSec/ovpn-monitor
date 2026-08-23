package sniffer

import (
	"encoding/binary"
	"testing"
)

// buildClientHello constructs a minimal but structurally valid TLS ClientHello
// record carrying a single server_name (host_name) extension, so the SNI parser
// is exercised against real wire layout rather than a hand-typed hex blob.
func buildClientHello(host string) []byte {
	// server_name extension body
	name := []byte(host)
	entry := append([]byte{0x00}, u16(len(name))...) // name_type=host_name, name_len
	entry = append(entry, name...)
	list := append(u16(len(entry)), entry...) // server_name_list
	ext := append(u16(0x0000), u16(len(list))...)
	ext = append(ext, list...)

	var body []byte
	body = append(body, 0x03, 0x03)          // client_version TLS 1.2
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id length 0
	body = append(body, u16(2)...)           // cipher_suites length
	body = append(body, 0x00, 0x2f)          // one cipher suite
	body = append(body, 0x01, 0x00)          // compression: len 1, null
	body = append(body, u16(len(ext))...)    // extensions length
	body = append(body, ext...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, u16(len(hs))...)
	rec = append(rec, hs...)
	return rec
}

func u16(v int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(v))
	return b
}

func TestParseTLSServerName(t *testing.T) {
	cases := []string{"www.example.com", "youtube.com", "a.b.c.d.example.co.uk"}
	for _, want := range cases {
		got, ok := parseTLSServerName(buildClientHello(want))
		if !ok || got != want {
			t.Errorf("parseTLSServerName(%q) = %q,%v", want, got, ok)
		}
	}
	// Truncated input must not panic and must fail cleanly.
	full := buildClientHello("example.com")
	for i := 0; i < len(full); i++ {
		if _, ok := parseTLSServerName(full[:i]); ok && i < 5 {
			t.Errorf("expected failure on truncated len=%d", i)
		}
	}
	if _, ok := parseTLSServerName([]byte("not tls")); ok {
		t.Error("non-TLS input should fail")
	}
}

func TestParseHTTPHost(t *testing.T) {
	cases := map[string]string{
		"GET / HTTP/1.1\r\nHost: www.Example.com\r\n\r\n":            "www.example.com",
		"POST /x HTTP/1.1\r\nHost: api.foo.com:8080\r\nA: b\r\n\r\n": "api.foo.com",
		"GET / HTTP/1.1\r\nUser-Agent: z\r\nHost: bar.org\r\n\r\n":   "bar.org",
	}
	for req, want := range cases {
		got, ok := parseHTTPHost([]byte(req))
		if !ok || got != want {
			t.Errorf("parseHTTPHost(%q) = %q,%v want %q", req, got, ok, want)
		}
	}
	if _, ok := parseHTTPHost([]byte("\x16\x03\x01 binary junk")); ok {
		t.Error("non-HTTP input should fail")
	}
}
