// Package web embeds the Vite-built React frontend (dist/) into the Go
// binary and serves it: fingerprinted bundles under /assets/, the favicons,
// and the three HTML entries (index/login/portal) with per-request injection
// (see pages.go). Pattern adapted from 3x-ui's internal/web, reworked for
// stdlib net/http — no gin.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var Dist embed.FS

// notBuiltMsg is served when dist/ holds only the .gitkeep placeholder, i.e.
// the Go binary was built without running the frontend build first.
const notBuiltMsg = "frontend not built — run ./build.sh"

// NotBuilt answers any frontend route when the embedded dist has no real
// build in it.
func NotBuilt(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write([]byte(notBuiltMsg + "\n"))
}

// RegisterAssets mounts the static half of the frontend onto mux: the
// fingerprinted JS/CSS bundles under /assets/ (immutable, year-long cache)
// and the favicons the HTML entries reference.
func RegisterAssets(mux *http.ServeMux) {
	if assets, err := fs.Sub(Dist, "dist/assets"); err == nil {
		mux.Handle("/assets/", immutable(http.StripPrefix("/assets", http.FileServerFS(assets))))
	}
	mux.HandleFunc("GET /favicon.svg", serveEmbedded("dist/favicon.svg", "image/svg+xml"))
	mux.HandleFunc("GET /favicon-512.png", serveEmbedded("dist/favicon-512.png", "image/png"))
}

// immutable marks fingerprinted assets (content hash in the filename) as
// cacheable forever; a new build ships new filenames, so staleness is
// impossible.
func immutable(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		next.ServeHTTP(w, r)
	})
}

func serveEmbedded(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(Dist, name)
		if err != nil {
			NotBuilt(w)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	}
}
