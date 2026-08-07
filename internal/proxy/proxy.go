// Package proxy is the Spidercob data plane (design doc §6):
// authN -> policy -> sanitize -> route -> DLP-scan response -> audit.
//
// The gateway owns MCP session identity end-to-end: it mints its own
// client-facing session ID at `initialize`, never passing through
// whatever the real upstream (or spawned stdio process) uses internally.
// A local mapping (session.go) translates the gateway's ID to the real
// upstream resource, and killing a session -- explicitly via DELETE, or
// via idle timeout -- tears both down together.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/metrics"
	"github.com/sumeetgp/spidercob-gateway/internal/policy"
	"github.com/sumeetgp/spidercob-gateway/internal/proxy/stdioadapter"
	"github.com/sumeetgp/spidercob-gateway/internal/scan"
)

const maxBodyBytes = 10 << 20 // 10 MiB cap, part of the inbound sanitization story

const idleReapInterval = 30 * time.Second

// nodeConfig describes a registered node -- not a live connection. A
// connection (an httpUpstreamSession or a spawned stdioUpstreamSession) is
// created fresh per client session, not shared across them, so tearing
// down one session never affects another using the same node.
type nodeConfig struct {
	name        string
	transport   string
	upstreamURL *url.URL
	command     string
	args        []string
}

// AuthClaims is the subset of a validated access token's claims the proxy
// itself needs -- just enough to stash into the request context for
// Phase 3's policy engine (issue #3, story 22), without the proxy package
// needing to import internal/authserver's full Claims type.
type AuthClaims struct {
	Subject string // sub: "user:<username>" or "agent:<client_id>"
	Act     string // act: the calling agent's client_id, when a human uses one (RFC 8693 shape; unpopulated until Phase 2b)
}

// TokenValidator is what the proxy needs from an authserver: given the
// node being called and a bearer token, either a validated identity or an
// error. Defined here, not in internal/authserver, so this package's
// dependency surface stays minimal -- main.go is the only place that needs
// to know an *authserver.AuthServer actually implements this.
type TokenValidator interface {
	ValidateAccessToken(node, token string) (AuthClaims, error)
}

// authCtxKey is the context key AuthClaims are stored under after a
// request's bearer token validates -- Phase 3's policy engine reads this
// instead of re-parsing the token.
type authCtxKey struct{}

// AuthClaimsFromContext returns the AuthClaims stashed by a successful
// bearer-token validation, if any.
func AuthClaimsFromContext(ctx context.Context) (AuthClaims, bool) {
	c, ok := ctx.Value(authCtxKey{}).(AuthClaims)
	return c, ok
}

type Gateway struct {
	nodes    map[string]*nodeConfig
	sessions *sessionManager
	policy   policy.Engine
	scanners *scan.Chain
	client   *http.Client
	authn    TokenValidator
	issuer   string

	nodeHealthMu sync.Mutex
	nodeHealth   map[string]*nodeHealth

	stopReaper chan struct{}
	reaperDone chan struct{}
}

// New builds a Gateway. authn validates every request's bearer token
// (issue #3) -- there is no way to construct a Gateway that skips this;
// the TODO(phase 2) placeholder this replaces is gone, not made optional.
func New(cfg *config.Config, authn TokenValidator) (*Gateway, error) {
	if authn == nil {
		return nil, fmt.Errorf("proxy: a TokenValidator is required")
	}
	var initialPolicy policy.Engine = policy.DenyAll{} // phase 2: nothing is allowed until Phase 3's real evaluator lands (MASTER_PLAN.md §6, 2026-08-04)
	if cfg.DevAllowAllPolicy {
		slog.Warn("DevAllowAllPolicy is enabled -- every authenticated caller can reach every tool on every node; never set this in production")
		initialPolicy = policy.AllowAll{}
	}
	g := &Gateway{
		nodes:      make(map[string]*nodeConfig),
		sessions:   newSessionManager(time.Duration(cfg.IdleSessionTimeoutSeconds) * time.Second),
		policy:     initialPolicy,
		scanners:   scan.Default(),
		client:     &http.Client{Timeout: 30 * time.Second},
		authn:      authn,
		issuer:     strings.TrimRight(cfg.Issuer, "/"),
		nodeHealth: make(map[string]*nodeHealth),
		stopReaper: make(chan struct{}),
		reaperDone: make(chan struct{}),
	}
	for _, n := range cfg.Nodes {
		nc := &nodeConfig{name: n.Name, transport: n.Transport, command: n.Command, args: n.Args}
		if n.Transport == config.TransportStreamableHTTP {
			u, err := url.Parse(n.UpstreamURL)
			if err != nil {
				return nil, fmt.Errorf("node %s: %w", n.Name, err)
			}
			nc.upstreamURL = u
		}
		g.nodes[n.Name] = nc
	}

	go g.reapLoop()
	return g, nil
}

func (g *Gateway) reapLoop() {
	defer close(g.reaperDone)
	t := time.NewTicker(idleReapInterval)
	defer t.Stop()
	for {
		select {
		case <-g.stopReaper:
			return
		case <-t.C:
			g.sessions.reapIdle(context.Background())
		}
	}
}

// Close stops the idle-session reaper and tears down every live session's
// upstream resource -- notably, every spawned stdio child process.
func (g *Gateway) Close() error {
	close(g.stopReaper)
	<-g.reaperDone

	var errs []string
	for _, id := range g.sessions.allIDs() {
		if err := g.sessions.end(context.Background(), id); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(errs, "; "))
}

// statusRecorder captures the response code for metrics.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// ServeHTTP routes /mcp/{node}/... to the registered upstream, through the
// gateway's own session lifecycle.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rest := strings.TrimPrefix(r.URL.Path, "/mcp/")
	parts := strings.SplitN(rest, "/", 2)
	nodeName := parts[0]
	rpcMethod := "?"
	sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		metrics.Requests.Inc(nodeName, rpcMethod, strconv.Itoa(sr.status))
		metrics.UpstreamDuration.Observe(time.Since(start).Seconds(), nodeName)
	}()

	nc, ok := g.nodes[nodeName]
	if !ok {
		http.Error(sr, "unknown MCP node", http.StatusNotFound)
		return
	}

	// Validate bearer token: signature, exp, aud == this node's canonical
	// URI (RFC 8707), jti not revoked. Missing or invalid -> 401 with
	// WWW-Authenticate pointing at this node's RFC 9728 protected-resource
	// metadata, so a spec-compliant client knows how to obtain a valid one.
	claims, ok := g.authenticate(sr, r, nodeName)
	if !ok {
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), authCtxKey{}, claims))

	if !g.policy.Allow(nodeName, r) {
		http.Error(sr, "forbidden", http.StatusForbidden)
		return
	}

	if len(parts) == 2 {
		r.URL.Path = "/" + parts[1]
	} else {
		r.URL.Path = "/"
	}

	sessionID := r.Header.Get("Mcp-Session-Id")

	if r.Method == http.MethodDelete {
		g.handleDelete(sr, r.Context(), nodeName, sessionID)
		return
	}

	var body []byte
	if r.Body != nil && r.Method == http.MethodPost {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			http.Error(sr, "bad request", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		body = b
		rpcMethod = jsonRPCMethod(body)
		for _, v := range g.scanners.ScanRequest(body) {
			metrics.ScanVerdicts.Inc(v.Scanner, v.Action.String(), "request", nodeName)
			slog.Warn("scan verdict",
				"scanner", v.Scanner, "action", v.Action.String(),
				"direction", "request", "node", nodeName,
				"rpc_method", rpcMethod, "detail", v.Detail)
			if v.Action == scan.Block {
				writeJSONRPCError(sr, body, "request blocked by spidercob sanitization")
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	if sessionID == "" {
		if rpcMethod != "initialize" {
			http.Error(sr, "missing Mcp-Session-Id", http.StatusBadRequest)
			return
		}
		g.handleNewSession(sr, r, nc)
		return
	}

	sess, ok := g.sessions.get(sessionID)
	if !ok || sess.node != nodeName {
		http.Error(sr, "session not found", http.StatusNotFound)
		return
	}
	if !sess.upstream.alive() {
		// The process crashed on its own since the session was
		// established -- self-heal by dropping the now-useless mapping,
		// and fail this request cleanly rather than let the caller hang
		// or silently spawn a replacement under the old session ID.
		_ = g.sessions.end(r.Context(), sessionID)
		slog.Warn("session upstream died unexpectedly", "node", nodeName, "session", sessionID)
		writeJSONRPCError(sr, body, "session's upstream connection is no longer available; re-initialize")
		return
	}
	sess.touch()
	g.forward(sr, r, sess, false)
}

// authenticate validates the request's bearer token against nodeName. On
// failure it writes the 401 response itself (with a WWW-Authenticate
// header pointing at this node's RFC 9728 metadata) and returns ok=false;
// the caller should return immediately without writing anything else.
func (g *Gateway) authenticate(w http.ResponseWriter, r *http.Request, nodeName string) (AuthClaims, bool) {
	wwwAuthenticate := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/%s"`, g.issuer, nodeName)

	authz := r.Header.Get("Authorization")
	token, hasBearer := strings.CutPrefix(authz, "Bearer ")
	if !hasBearer || token == "" {
		w.Header().Set("WWW-Authenticate", wwwAuthenticate)
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return AuthClaims{}, false
	}

	claims, err := g.authn.ValidateAccessToken(nodeName, token)
	if err != nil {
		slog.Warn("bearer token rejected", "node", nodeName, "err", err)
		w.Header().Set("WWW-Authenticate", wwwAuthenticate)
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
		return AuthClaims{}, false
	}
	return claims, true
}

func (g *Gateway) handleNewSession(w http.ResponseWriter, r *http.Request, nc *nodeConfig) {
	upstream, err := g.newUpstream(r.Context(), nc)
	if err != nil {
		switch {
		case errors.Is(err, errNodeQuarantined):
			http.Error(w, "node quarantined after repeated failures", http.StatusServiceUnavailable)
		case errors.Is(err, errNodeBackoff):
			http.Error(w, "node temporarily unavailable, try again shortly", http.StatusServiceUnavailable)
		default:
			http.Error(w, "failed to reach upstream", http.StatusBadGateway)
		}
		return
	}
	sess, err := g.sessions.create(nc.name, upstream)
	if err != nil {
		_ = upstream.teardown(r.Context())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	g.forward(w, r, sess, true)
}

func (g *Gateway) handleDelete(w http.ResponseWriter, ctx context.Context, nodeName, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing Mcp-Session-Id", http.StatusBadRequest)
		return
	}
	sess, ok := g.sessions.get(sessionID)
	if !ok || sess.node != nodeName {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	if err := g.sessions.end(ctx, sessionID); err != nil {
		http.Error(w, "failed to end session", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var (
	errNodeQuarantined = errors.New("node quarantined after repeated failures")
	errNodeBackoff     = errors.New("node in backoff after a recent failure")
)

func (g *Gateway) healthFor(node string) *nodeHealth {
	g.nodeHealthMu.Lock()
	defer g.nodeHealthMu.Unlock()
	h, ok := g.nodeHealth[node]
	if !ok {
		h = newNodeHealth()
		g.nodeHealth[node] = h
	}
	return h
}

func (g *Gateway) newUpstream(ctx context.Context, nc *nodeConfig) (sessionUpstream, error) {
	if nc.transport != config.TransportStdio {
		return &httpUpstreamSession{client: g.client, upstreamURL: nc.upstreamURL}, nil
	}

	health := g.healthFor(nc.name)
	switch health.decide(time.Now()) {
	case spawnQuarantined:
		return nil, errNodeQuarantined
	case spawnBackoff:
		return nil, errNodeBackoff
	}

	node, err := stdioadapter.New(ctx, nc.name, nc.command, nc.args)
	if err != nil {
		health.recordFailure(time.Now())
		return nil, err
	}
	return &stdioUpstreamSession{node: node}, nil
}

// forward dispatches one request through a session's upstream, runs the
// outbound DLP chain over the buffered response, and -- for a newly
// established session -- stamps the gateway-minted session ID onto both
// the Mcp-Session-Id header and a mirrored cookie before anything is
// written to the real client.
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, sess *mcpSession, newSession bool) {
	buf := newBufferedResponseWriter()
	sess.upstream.ServeHTTP(buf, r)

	clean, verdicts := g.scanners.ScanResponse(buf.body.Bytes())
	for _, v := range verdicts {
		metrics.ScanVerdicts.Inc(v.Scanner, v.Action.String(), "response", sess.node)
		slog.Warn("scan verdict",
			"scanner", v.Scanner, "action", v.Action.String(),
			"direction", "response", "node", sess.node, "detail", v.Detail)
	}

	for k, vv := range buf.header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	if newSession {
		w.Header().Set("Mcp-Session-Id", sess.id)
		http.SetCookie(w, &http.Cookie{
			Name: sessionCookieName, Value: sess.id,
			Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(clean)))
	w.WriteHeader(buf.status)
	_, _ = w.Write(clean)
}

// bufferedResponseWriter buffers a response in memory so it can be
// rewritten (DLP-scanned, session headers added) before being flushed to
// the real client.
type bufferedResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header), status: http.StatusOK}
}

func (b *bufferedResponseWriter) Header() http.Header         { return b.header }
func (b *bufferedResponseWriter) WriteHeader(code int)        { b.status = code }
func (b *bufferedResponseWriter) Write(p []byte) (int, error) { return b.body.Write(p) }

// httpUpstreamSession is a streamable_http node's per-session upstream.
// Each request is forwarded with the real upstream's own session ID
// substituted in for the gateway's -- the gateway's minted ID never
// reaches the upstream, and the upstream's raw session ID never reaches
// the client.
type httpUpstreamSession struct {
	client      *http.Client
	upstreamURL *url.URL

	mu                sync.Mutex
	upstreamSessionID string
}

func (u *httpUpstreamSession) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	outURL := *u.upstreamURL
	outURL.Path = singleJoiningSlash(u.upstreamURL.Path, r.URL.Path)

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	outReq.Header = r.Header.Clone()
	outReq.Header.Del("Accept-Encoding") // keep responses uncompressed so they stay scannable
	outReq.ContentLength = r.ContentLength

	u.mu.Lock()
	id := u.upstreamSessionID
	u.mu.Unlock()
	if id != "" {
		outReq.Header.Set("Mcp-Session-Id", id)
	} else {
		outReq.Header.Del("Mcp-Session-Id") // never forward the gateway's own minted ID upstream
	}

	resp, err := u.client.Do(outReq)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer resp.Body.Close()

	if upstreamID := resp.Header.Get("Mcp-Session-Id"); upstreamID != "" {
		u.mu.Lock()
		u.upstreamSessionID = upstreamID
		u.mu.Unlock()
	}

	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Mcp-Session-Id") {
			continue // never leak the upstream's own session id to the client
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (u *httpUpstreamSession) teardown(ctx context.Context) error {
	u.mu.Lock()
	id := u.upstreamSessionID
	u.mu.Unlock()
	if id == "" {
		return nil // upstream never actually established a session of its own
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.upstreamURL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Mcp-Session-Id", id)
	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// alive is always true for streamable_http upstreams -- there's no
// persistent process on our side to die; each request is its own round
// trip to whatever's currently running upstream.
func (u *httpUpstreamSession) alive() bool { return true }

func writeUpstreamError(w http.ResponseWriter, err error) {
	http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// stdioUpstreamSession is a stdio node's per-session upstream: a child
// process spawned exclusively for this one session, so ending the session
// only ever affects this process, never any other agent's session against
// the same node.
type stdioUpstreamSession struct {
	node *stdioadapter.Node
}

func (u *stdioUpstreamSession) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.node.ServeHTTP(w, r)
}

func (u *stdioUpstreamSession) teardown(ctx context.Context) error {
	return u.node.Close()
}

func (u *stdioUpstreamSession) alive() bool { return u.node.Alive() }

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
