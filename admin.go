package main

import (
	_ "embed"
	"encoding/json"
	"net"
	"net/http"
	"strings"
)

//go:embed status.html
var statusPage string

// Local, read-only diagnostics. No remote management or write APIs yet.
func adminHandler(c Config, s *Stats) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "loopback Host required", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "read-only API", http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(statusPage))
		case "/api/status":
			w.Header().Set("Content-Type", "application/json")
			status := s.snapshot(c.Mode)
			status["max_connections"] = c.MaxConnections
			status["idle_seconds"] = c.IdleSeconds
			json.NewEncoder(w).Encode(status)
		case "/healthz":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"process":"running","note":"not an end-to-end tunnel health check"}`))
		default:
			http.NotFound(w, r)
		}
	})
}
