package handler

import (
	"encoding/json"
	"net/http"

	"ovpnmonitor/internal/auth"
	"ovpnmonitor/internal/ipv6"
)

// registerIPv6 mounts the IPv6 toggle endpoints. They live under
// /api/settings/{service}/ipv6 — a more specific pattern than the section
// settings route, so the stdlib mux routes them here. Like every other
// privileged, state-changing endpoint they sit behind the admin API auth
// middleware.
func registerIPv6(mux *http.ServeMux, d Deps) {
	services := map[string]*ipv6.Service{
		"wireguard": d.IPv6WG,
		"openvpn":   d.IPv6OVPN,
	}
	resolve := func(w http.ResponseWriter, r *http.Request) *ipv6.Service {
		svc, known := services[r.PathValue("service")]
		if !known || svc == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "IPv6 toggle is not configured for this service",
			})
			return nil
		}
		return svc
	}

	mux.Handle("GET /api/settings/{service}/ipv6", auth.APIAuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc := resolve(w, r)
		if svc == nil {
			return
		}
		state, err := svc.State()
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			d.Logger.Error("ipv6: read state", "err", err)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Could not read the server config"})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"state": string(state)})
	})))

	mux.Handle("PUT /api/settings/{service}/ipv6", auth.APIAuthMiddleware(d.Sessions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc := resolve(w, r)
		if svc == nil {
			return
		}
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		state, err := svc.Set(r.Context(), *body.Enabled)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    true,
			"state": string(state),
		})
	})))
}
