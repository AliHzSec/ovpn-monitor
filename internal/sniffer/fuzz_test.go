package sniffer

import "testing"

// These fuzz targets assert the one property the merged-in sniffer must hold
// now that parsing runs inside the panel process: no input — however
// truncated, malformed, or adversarial — may panic. Any output is fine.

func FuzzParseTLSServerName(f *testing.F) {
	f.Add(buildClientHello("example.com"))
	f.Add([]byte{})
	f.Add([]byte{0x16})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a.b\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseTLSServerName(b)
	})
}

func FuzzParseHTTPHost(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"))
	f.Add([]byte{})
	f.Add([]byte("POST "))
	f.Add(buildClientHello("example.com"))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseHTTPHost(b)
	})
}

func FuzzRootDomain(f *testing.F) {
	f.Add("www.youtube.com")
	f.Add("")
	f.Add("..")
	f.Add("xn--%00.\xff\xfe")
	f.Fuzz(func(t *testing.T, s string) {
		rootDomain(s)
	})
}
