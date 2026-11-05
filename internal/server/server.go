// Package server exposes the tools as a small JSON API and serves the UI.
package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"email-test-tools/internal/netcheck"
	"email-test-tools/internal/report"
	"email-test-tools/internal/smtpcheck"
)

type Options struct {
	Static  fs.FS
	Version string
	// AllowRemote disables the localhost-only Host check (for --addr 0.0.0.0).
	AllowRemote bool
}

func New(o Options) http.Handler {
	mux := http.NewServeMux()
	sem := make(chan struct{}, 8) // limit concurrent tests

	handle := func(path string, fn func(context.Context, json.RawMessage) (*report.Report, error)) {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if ct != "application/json" {
				http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
			var raw json.RawMessage
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&raw); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-r.Context().Done():
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
			defer cancel()
			t := time.Now()
			rep, err := fn(ctx, raw)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			slog.Info("test finished", "tool", rep.Tool, "status", rep.Status, "took", time.Since(t).Round(time.Millisecond))
			writeJSON(w, rep)
		})
	}

	handle("/api/smtp", func(ctx context.Context, b json.RawMessage) (*report.Report, error) {
		var req smtpcheck.Request
		if err := json.Unmarshal(b, &req); err != nil {
			return nil, err
		}
		return smtpcheck.Run(ctx, req), nil
	})
	handle("/api/ports", func(ctx context.Context, b json.RawMessage) (*report.Report, error) {
		var req netcheck.PortRequest
		if err := json.Unmarshal(b, &req); err != nil {
			return nil, err
		}
		return netcheck.CheckPorts(ctx, req), nil
	})
	handle("/api/dns", func(ctx context.Context, b json.RawMessage) (*report.Report, error) {
		var req netcheck.DNSRequest
		if err := json.Unmarshal(b, &req); err != nil {
			return nil, err
		}
		return netcheck.LookupDNS(ctx, req), nil
	})
	handle("/api/domain", func(ctx context.Context, b json.RawMessage) (*report.Report, error) {
		var req netcheck.DomainRequest
		if err := json.Unmarshal(b, &req); err != nil {
			return nil, err
		}
		return netcheck.CheckDomain(ctx, req), nil
	})
	handle("/api/tls", func(ctx context.Context, b json.RawMessage) (*report.Report, error) {
		var req netcheck.TLSRequest
		if err := json.Unmarshal(b, &req); err != nil {
			return nil, err
		}
		return netcheck.CheckTLS(ctx, req), nil
	})
	mux.HandleFunc("GET /api/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"version": o.Version, "ports": netcheck.PortInfo})
	})
	mux.Handle("GET /", http.FileServerFS(o.Static))

	return guard(mux, o.AllowRemote)
}

// guard blocks DNS-rebinding and cross-site requests: a random website must
// not be able to use this local tool to probe the user's network.
func guard(next http.Handler, allowRemote bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowRemote && !isLoopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && r.Method != http.MethodGet {
			if !strings.HasSuffix(origin, "//"+r.Host) {
				http.Error(w, "cross-origin request blocked", http.StatusForbidden)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func isLoopbackHost(hostport string) bool {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		h = hostport
	}
	h = strings.Trim(h, "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
