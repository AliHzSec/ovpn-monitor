package web

import (
	"bytes"
	"encoding/json"
	"html"
	"io/fs"
	"net/http"

	"ovpnmonitor/internal/model"
)

// csrfMetaPlaceholder is the empty CSRF meta tag the Vite entries ship with.
// It is replaced in place at serve time when the caller supplies a CSRF
// token, and left empty for pages that make no mutating requests (portal).
const csrfMetaPlaceholder = `<meta name="csrf-token" content="" />`

var headClose = []byte("</head>")

// ServePage serves one embedded HTML entry (e.g. "index.html", "login.html")
// with csrf injected into the csrf-token meta. An empty csrf leaves the
// placeholder untouched: no token is exposed. No cookie is set here — the
// session cookie (set by the login page / login POST handlers) is the only
// cookie this panel uses.
func ServePage(w http.ResponseWriter, name, csrf string) {
	servePage(Dist, w, name, nil, csrf)
}

// ServePortal serves portal.html with the window.OVPN_PORTAL bootstrap —
// the JSON-encoded ClientPortalData — injected before </head>, replacing the
// old server-rendered client.html template. The portal is IP-gated and
// sessionless and makes no mutating requests, so the CSRF meta stays empty.
func ServePortal(w http.ResponseWriter, data model.ClientPortalData) {
	servePage(Dist, w, "portal.html", data, "")
}

// servePage reads name out of fsys (rooted at the embed parent, so the path
// is "dist/"+name), injects the CSRF meta when csrf is non-empty — and for
// portal.html the bootstrap script — and writes the page no-cache. A dist
// holding only the .gitkeep placeholder yields a clear 500 instead of a
// broken page.
func servePage(fsys fs.FS, w http.ResponseWriter, name string, portal any, csrf string) {
	body, err := fs.ReadFile(fsys, "dist/"+name)
	if err != nil {
		NotBuilt(w)
		return
	}

	if csrf != "" {
		meta := []byte(`<meta name="csrf-token" content="` + html.EscapeString(csrf) + `" />`)
		if bytes.Contains(body, []byte(csrfMetaPlaceholder)) {
			body = bytes.Replace(body, []byte(csrfMetaPlaceholder), meta, 1)
		} else {
			body = injectBeforeHead(body, meta)
		}
	}

	if portal != nil {
		// encoding/json escapes <, > and & by default, so the payload is safe
		// to drop into an inline <script> verbatim.
		if payload, err := json.Marshal(portal); err == nil {
			script := make([]byte, 0, len(payload)+40)
			script = append(script, []byte(`<script>window.OVPN_PORTAL = `)...)
			script = append(script, payload...)
			script = append(script, []byte(`</script>`)...)
			body = injectBeforeHead(body, script)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write(body)
}

func injectBeforeHead(body, inject []byte) []byte {
	out := make([]byte, 0, len(body)+len(inject))
	if i := bytes.Index(body, headClose); i >= 0 {
		out = append(out, body[:i]...)
		out = append(out, inject...)
		out = append(out, body[i:]...)
		return out
	}
	return append(out, body...)
}
