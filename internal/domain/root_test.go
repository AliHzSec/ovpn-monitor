package domain

import "testing"

func TestRoot(t *testing.T) {
	cases := map[string]struct {
		want string
		ok   bool
	}{
		// The bug this function exists for: "googleapis.com" is a PRIVATE-section
		// public-suffix entry, so the registrable domain of any Google API host is
		// the host itself. Grouping must ignore the private section.
		"firebaseremoteconfig.googleapis.com": {"googleapis.com", true},
		"www.googleapis.com":                  {"googleapis.com", true},
		"googleapis.com":                      {"googleapis.com", true},
		// Other private-section suffixes that leaked the same way.
		"my-project.appspot.com":  {"appspot.com", true},
		"bucket.s3.amazonaws.com": {"amazonaws.com", true},
		"someone.blogspot.com":    {"blogspot.com", true},
		"someone.github.io":       {"github.io", true},

		// Multi-part ICANN suffixes must not be mistaken for the root domain.
		"something.co.uk":     {"something.co.uk", true},
		"foo.bar.bbc.co.uk":   {"bbc.co.uk", true},
		"example.com.br":      {"example.com.br", true},
		"www.example.com.br":  {"example.com.br", true},
		"shop.example.com.au": {"example.com.au", true},

		// Already a root domain, no subdomain to strip.
		"google.ru":   {"google.ru", true},
		"youtube.com": {"youtube.com", true},

		// Ordinary subdomains.
		"www.youtube.com": {"youtube.com", true},
		"i.ytimg.com":     {"ytimg.com", true},

		// Normalisation: case and the trailing root dot.
		"GOOGLE.COM.":      {"google.com", true},
		"  WWW.BBC.CO.UK ": {"bbc.co.uk", true},

		// Raw IP literals are addresses, not sites.
		"10.0.0.1":        {"", false},
		"192.168.1.254":   {"", false},
		"255.255.255.255": {"", false},
		"::1":             {"", false},
		"[::1]":           {"", false},
		"2001:db8::1":     {"", false},

		// Nothing to group under.
		"":          {"", false},
		"localhost": {"", false},
		"com":       {"", false},
		"co.uk":     {"", false},

		// Malformed input must be dropped, not stored as a bogus site.
		"..":               {"", false},
		"a..b":             {"", false},
		".example.com":     {"", false},
		"example.com:443":  {"", false},
		"example.com/path": {"", false},
		"exa mple.com":     {"", false},
	}
	for host, exp := range cases {
		got, ok := Root(host)
		if got != exp.want || ok != exp.ok {
			t.Errorf("Root(%q) = %q,%v want %q,%v", host, got, ok, exp.want, exp.ok)
		}
	}
}

// A root domain must be its own root: grouping a set of hosts and then grouping
// the resulting roots again has to produce the same answer, otherwise the
// top-level list and the per-root detail list could disagree.
func TestRootIsIdempotent(t *testing.T) {
	for _, host := range []string{
		"firebaseremoteconfig.googleapis.com", "foo.bar.bbc.co.uk",
		"bucket.s3.amazonaws.com", "www.example.com.br", "i.ytimg.com",
	} {
		root, ok := Root(host)
		if !ok {
			t.Fatalf("Root(%q) failed", host)
		}
		again, ok := Root(root)
		if !ok || again != root {
			t.Errorf("Root(Root(%q)) = %q,%v want %q,true", host, again, ok, root)
		}
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	for _, host := range []string{" WWW.Example.COM. ", "[::1]", "example.com", ""} {
		once := Normalize(host)
		if twice := Normalize(once); twice != once {
			t.Errorf("Normalize(%q) = %q then %q; want stable", host, once, twice)
		}
	}
}

// Root must never panic, whatever a hostile SNI or Host header contains.
func FuzzRoot(f *testing.F) {
	f.Add("www.youtube.com")
	f.Add("firebaseremoteconfig.googleapis.com")
	f.Add("")
	f.Add("..")
	f.Add("xn--%00.\xff\xfe")
	f.Add(".....................")
	f.Fuzz(func(t *testing.T, s string) {
		if root, ok := Root(s); ok {
			// A successful result must itself be a valid, stable root domain.
			if again, ok2 := Root(root); !ok2 || again != root {
				t.Errorf("Root(%q) = %q, but Root(%q) = %q,%v", s, root, root, again, ok2)
			}
		}
	})
}
