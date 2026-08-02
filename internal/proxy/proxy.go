// Package proxy is the Spidercob data plane (design doc §6):
// authN -> policy -> sanitize -> route -> DLP-scan response -> audit.
// Phase 1 scope: node routing, buffered scanning, JSON-RPC-aware logging,
// Prometheus metrics. Phase 2 adds token validation; phase 3 adds real
// policy + streaming scan.
package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/metrics"
	"github.com/sumeetgp/spidercob-gateway/internal/policy"
	"github.com/sumeetgp/spidercob-gateway/internal/scan"
)

const maxBodyBytes = 10 << 20 // 10 MiB cap, part of the inbound sanitization story

type Gateway struct {
	nodes    map[string]*httputil.ReverseProxy
	policy   policy.Engine
	scanners *scan.Chain
}

func New(cfg *config.Config) (*Gateway, error) {
	g := &Gateway{
		nodes:    make(map[string]*httputil.ReverseProxy),
		policy:   policy.AllowAll{}, // replaced in phase 3
		scanners: scan.Default(),
	}
	for _, n := range cfg.Nodes {
		u, err := url.Parse(n.UpstreamURL)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", n.Name, err)
		}
		name := n.Name
		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(u)
				pr.SetXForwarded()
				// Keep upstream responses uncompressed so they stay scannable.
				pr.Out.Header.Del("Accept-Encoding")
			},
			ModifyResponse: g.scanResponse(name),
		}
		g.nodes[name] = rp
	}
	return g, nil
}

// statusRecorder captures the response code for metrics and passes Flush
// through so SSE/streaming responses keep working.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ServeHTTP routes /mcp/{node}/... to the registered upstream.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rest := strings.TrimPrefix(r.URL.Path, "/mcp/")
	parts := strings.SplitN(rest, "/", 2)
	node := parts[0]
	rpcMethod := "?"
	sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		metrics.Requests.Inc(node, rpcMethod, strconv.Itoa(sr.status))
		metrics.UpstreamDuration.Observe(time.Since(start).Seconds(), node)
	}()

	rp, ok := g.nodes[node]
	if !ok {
		http.Error(sr, "unknown MCP node", http.StatusNotFound)
		return
	}

	// TODO(phase 2): validate bearer token here — signature, exp, aud == this
	// node's canonical URI (RFC 8707), jti not revoked. On 401, return
	// WWW-Authenticate pointing at RFC 9728 protected-resource metadata.

	if !g.policy.Allow(node, r) {
		http.Error(sr, "forbidden", http.StatusForbidden)
		return
	}

	// Inbound scan (buffered; streaming-safe scanning is a phase-3 item).
	if r.Body != nil && r.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			http.Error(sr, "bad request", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		rpcMethod = jsonRPCMethod(body)
		for _, v := range g.scanners.ScanRequest(body) {
			metrics.ScanVerdicts.Inc(v.Scanner, v.Action.String(), "request", node)
			slog.Warn("scan verdict",
				"scanner", v.Scanner, "action", v.Action.String(),
				"direction", "request", "node", node,
				"rpc_method", rpcMethod, "detail", v.Detail)
			if v.Action == scan.Block {
				writeJSONRPCError(sr, body, "request blocked by spidercob sanitization")
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	if len(parts) == 2 {
		r.URL.Path = "/" + parts[1]
	} else {
		r.URL.Path = "/"
	}
	rp.ServeHTTP(sr, r)
}

// scanResponse runs the outbound (DLP) chain on JSON responses.
// SSE/streaming responses pass through untouched in phase 1 — windowed
// streaming redaction is a phase-3 item (design doc §6 step 6).
func (g *Gateway) scanResponse(node string) func(*http.Response) error {
	return func(resp *http.Response) error {
		if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		clean, verdicts := g.scanners.ScanResponse(body)
		for _, v := range verdicts {
			metrics.ScanVerdicts.Inc(v.Scanner, v.Action.String(), "response", node)
			slog.Warn("scan verdict",
				"scanner", v.Scanner, "action", v.Action.String(),
				"direction", "response", "node", node, "detail", v.Detail)
		}
		resp.Body = io.NopCloser(bytes.NewReader(clean))
		resp.ContentLength = int64(len(clean))
		resp.Header.Set("Content-Length", fmt.Sprint(len(clean)))
		return nil
	}
}

func jsonRPCMethod(body []byte) string {
	var m struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return "?"
	}
	return m.Method
}

func writeJSONRPCError(w http.ResponseWriter, req []byte, msg string) {
	var m struct {
		ID any `json:"id"`
	}
	_ = json.Unmarshal(req, &m)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      m.ID,
		"error":   map[string]any{"code": -32001, "message": msg},
	})
}
