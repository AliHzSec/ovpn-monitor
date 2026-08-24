package web

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"

	"ovpnmonitor/internal/model"
)

var headClose = []byte("</head>")

// ServePage serves one embedded HTML entry (e.g. "index.html", "login.html").
// No cookie is set here — the session cookie (set by the login POST handler)
// is the only cookie this panel uses.
func ServePage(w http.ResponseWriter, name string) {
	servePage(Dist, w, name, nil)
}

// ServePortal serves portal.html with the window.OVPN_PORTAL bootstrap —
// the JSON-encoded ClientPortalData — injected before </head>, replacing the
// old server-rendered client.html template. The portal is IP-gated and
// sessionless.
func ServePortal(w http.ResponseWriter, data model.ClientPortalData) {
	servePage(Dist, w, "portal.html", data)
}

// servePage reads name out of fsys (rooted at the embed parent, so the path
// is "dist/"+name), injects the portal bootstrap for portal.html, and writes
// the page no-cache. A dist holding only the .gitkeep placeholder yields a
// clear 500 instead of a broken page.
func servePage(fsys fs.FS, w http.ResponseWriter, name string, portal any) {
	body, err := fs.ReadFile(fsys, "dist/"+name)
	if err != nil {
		NotBuilt(w)
		return
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
