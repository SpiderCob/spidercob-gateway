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

	"github.com/sumeetgp/spidercob-gateway/internal/audit"
	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/metrics"
	"github.com/sumeetgp/spidercob-gateway/internal/pin"
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

	// inProcessHandler, when non-nil, makes this node an in-process one
	// (issue #59: spidercob-admin) -- routed via inProcessUpstreamSession
	// instead of the ordinary stdio/streamable_http dispatch, regardless
	// of transport (which stays empty/unused for this kind of node).
	// There is no config.Node shape that can set this field -- it's only
	// ever populated by Gateway.registerInProcessNode, called directly by
	// the composition root, deliberately unreachable through the admin
	// API's node-registration path.
	inProcessHandler http.Handler
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
	// nodesMu guards nodes -- unguarded before issue #57, when it was
	// only ever written once, during New, before ServeHTTP could
	// possibly run. AddNode/RemoveNode (node_registry.go) can now mutate
	// it concurrently with routing reads on other goroutines.
	nodesMu sync.RWMutex
	nodes   map[string]*nodeConfig

	sessions *sessionManager
	policy   policy.Engine
	pins     *pin.Registry
	scanners *scan.Chain
	client   *http.Client
	authn    TokenValidator
	issuer   string

	nodeHealthMu sync.Mutex
	nodeHealth   map[string]*nodeHealth

	stopReaper chan struct{}
	reaperDone chan struct{}

	// auditRecorder is nil until SetAuditRecorder is called -- see its
	// doc comment (audit.go) for why that's a legitimate, permanent
	// steady state, not just a startup window.
	auditRecorder   AuditRecorder
	auditQueue      chan audit.Record
	stopAuditWorker chan struct{}
	auditWorkerDone chan struct{}

	// maxStreamBytes bounds a single streamed response (issue #55) --
	// defaults to defaultMaxStreamBytes in New(); overridable only by
	// this package's own tests, which need a small cap to exercise
	// truncation without writing megabytes, the same "exported default,
	// test-only override" shape setAuditRecorder's capacity parameter
	// already established for audit queue sizing.
	maxStreamBytes int

	// maxBufferedResponseBytes bounds a single buffered (non-SSE)
	// response held in memory (security review finding #5) -- defaults
	// to defaultMaxBufferedResponseBytes in New(); overridable only by
	// this package's own tests, same shape as maxStreamBytes.
	maxBufferedResponseBytes int
}

// New builds a Gateway. authn validates every request's bearer token
// (issue #3) -- there is no way to construct a Gateway that skips this;
// the TODO(phase 2) placeholder this replaces is gone, not made optional.
// Starts with policy.DenyAll{} (or, if cfg.DevAllowAllPolicy is set,
// policy.AllowAll{}) -- the composition root (cmd/spidercob) wires in the
// real, store-backed evaluator afterward via SetPolicy, once it has a
// store to back it with. DevAllowAllPolicy always wins over that: it's a
// blunt, explicit dev/CI-only escape hatch (automation/run-e2e.sh), not
// meant to be quietly overridden by whatever real policy config happens
// to also be present.
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
		nodes:          make(map[string]*nodeConfig),
		sessions:       newSessionManager(time.Duration(cfg.IdleSessionTimeoutSeconds) * time.Second),
		policy:         initialPolicy,
		scanners:       scan.DefaultWithPII(scan.PIIConfig{DetectEmail: cfg.ScanDetectEmail, DetectPhone: cfg.ScanDetectPhone}),
		client:         &http.Client{Timeout: 30 * time.Second},
		authn:          authn,
		issuer:         strings.TrimRight(cfg.Issuer, "/"),
		nodeHealth:     make(map[string]*nodeHealth),
		stopReaper:     make(chan struct{}),
		reaperDone:     make(chan struct{}),
		maxStreamBytes: defaultMaxStreamBytes,

		maxBufferedResponseBytes: defaultMaxBufferedResponseBytes,
	}
	for _, n := range cfg.Nodes {
		nc, err := buildNodeConfig(n)
		if err != nil {
			return nil, err
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

// SetPolicy replaces the Gateway's policy engine -- the composition root
// (cmd/spidercob) calls this once, right after New, to swap in the real,
// store-backed evaluator (issue #7) now that a store exists to back it
// with. Exported (rather than the unexported field tests in this package
// assign directly) because main.go is a different package.
func (g *Gateway) SetPolicy(p policy.Engine) {
	g.policy = p
}

// SetPinRegistry wires in the tool-pinning (rug-pull defense) registry --
// the composition root (cmd/spidercob) calls this once, right after
// SetPolicy, now that a store exists to back it with. A Gateway with no
// registry set (nil, the zero value) runs with pinning disabled
// entirely: every tools/call passes the quarantine check and tools/list
// is never further filtered by it -- the same "start permissive, the
// composition root opts a real backend in once its dependencies exist"
// posture SetPolicy already takes, so existing tests and call sites that
// don't care about pinning don't need to construct a store for it.
func (g *Gateway) SetPinRegistry(r *pin.Registry) {
	g.pins = r
}

// Close stops the idle-session reaper and tears down every live session's
// upstream resource -- notably, every spawned stdio child process.
func (g *Gateway) Close() error {
	close(g.stopReaper)
	<-g.reaperDone

	// The audit worker only exists once SetAuditRecorder has actually
	// been called (audit.go) -- most unit tests in this package never
	// call it, so stopAuditWorker stays nil and there's nothing to stop.
	if g.stopAuditWorker != nil {
		close(g.stopAuditWorker)
		<-g.auditWorkerDone
	}

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

// Flush makes *statusRecorder itself satisfy http.Flusher whenever the
// real underlying ResponseWriter does -- embedding http.ResponseWriter as
// an interface field only promotes the methods that interface itself
// declares (Header/Write/WriteHeader), never Flush, so without this a
// streamed response forwarded through a statusRecorder (every request
// except a session's very first initialize -- see ServeHTTP's sr vs w
// split) would silently never flush incrementally, defeating issue #55's
// entire point on every request after the first one in a session. A safe
// no-op when the underlying writer doesn't support it (e.g. in tests
// using a plain httptest.ResponseRecorder without a Flusher).
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
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

	g.nodesMu.RLock()
	nc, nodeExists := g.nodes[nodeName]
	g.nodesMu.RUnlock()

	// A node that isn't currently registered is still reachable if a
	// request carries a session ID that's already live on it (issue #57
	// story 5: RemoveNode doesn't kill sessions already in flight -- only
	// new ones). Read Mcp-Session-Id early, before authentication, just
	// for this check; the normal read further down still governs actual
	// dispatch. Any other unknown-node request (no session at all, or a
	// session ID that doesn't map to this node) is rejected exactly as
	// before, before authentication even runs -- not revealing anything
	// beyond "this node was never valid."
	if !nodeExists {
		earlySessionID := r.Header.Get("Mcp-Session-Id")
		sess, liveOnThisNode := g.sessions.get(earlySessionID)
		if earlySessionID == "" || !liveOnThisNode || sess.node != nodeName {
			http.Error(sr, "unknown MCP node", http.StatusNotFound)
			return
		}
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

	if len(parts) == 2 {
		r.URL.Path = "/" + parts[1]
	} else {
		r.URL.Path = "/"
	}

	sessionID := r.Header.Get("Mcp-Session-Id")

	if r.Method == http.MethodDelete {
		// Ending a session is lifecycle management, not a tool/resource
		// access -- it isn't policy-gated the way tools/call or
		// resources/read are. A caller who authenticated against this
		// node may always end their own session.
		g.handleDelete(sr, r.Context(), nodeName, sessionID)
		return
	}

	// Policy needs the JSON-RPC method (and, for tools/call, the tool
	// name) to make a method/tool-level decision -- both only exist once
	// the body is parsed, so body-reading now happens before the policy
	// check, not after it as it did back when policy was only ever a
	// coarse node-level bool.
	var body []byte
	var toolName string
	if r.Body != nil && r.Method == http.MethodPost {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			http.Error(sr, "bad request", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		body = b
		rpcMethod = jsonRPCMethod(body)
		if rpcMethod == "tools/call" {
			toolName = jsonRPCToolName(body)
		}
	}

	decision := g.policy.Decide(r.Context(), claims.Subject, nodeName, rpcMethod, toolName)
	if decision.RateLimited {
		g.enqueueAudit(claims, rpcMethod+":rate_limited", auditResource(nodeName, toolName))
		http.Error(sr, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	if !decision.Allowed {
		g.enqueueAudit(claims, rpcMethod+":denied_policy", auditResource(nodeName, toolName))
		http.Error(sr, "forbidden", http.StatusForbidden)
		return
	}

	// A tool that passed policy can still be quarantined: policy answers
	// "is this principal allowed to call this tool," pinning separately
	// answers "is this still the tool definition everyone agreed to" --
	// two independent gates, both must pass. No re-approval mechanism
	// exists yet (Phase 4), so this stays a hard block, not a warning.
	if rpcMethod == "tools/call" && g.pins != nil && g.pins.IsQuarantined(r.Context(), nodeName, toolName) {
		g.enqueueAudit(claims, rpcMethod+":quarantined", auditResource(nodeName, toolName))
		http.Error(sr, "tool quarantined: its definition changed since it was first observed", http.StatusForbidden)
		return
	}

	// Schema enforcement (issue #11): a third, independent gate -- policy
	// answers "is this principal allowed," pinning's quarantine check
	// answers "is this still the tool everyone agreed to," and this
	// answers "does this specific call's arguments match what was agreed
	// to." No pin yet, or a pin with no inputSchema, both mean "nothing to
	// validate against" -- skip, don't block (stories 2 and 23).
	if rpcMethod == "tools/call" && g.pins != nil {
		schema, exists, err := g.pins.PinnedSchema(r.Context(), nodeName, toolName)
		if err != nil {
			slog.Error("pin: failed to fetch pinned schema", "node", nodeName, "tool", toolName, "err", err)
			http.Error(sr, "internal error checking tool schema", http.StatusInternalServerError)
			return
		}
		if exists && schema != nil {
			if err := pin.ValidateArguments(schema, jsonRPCToolArguments(body)); err != nil {
				// err.Error() already self-describes its specific failure
				// mode (e.g. "arguments do not match pinned schema: ...",
				// or a schema parse/resolve failure) -- don't prepend
				// another "...pinned schema" wrapper on top of it.
				g.enqueueAudit(claims, rpcMethod+":schema_rejected", auditResource(nodeName, toolName))
				writeJSONRPCError(sr, body, "tool call rejected: "+err.Error())
				return
			}
		}
	}

	if body != nil {
		for _, v := range g.scanners.ScanRequest(body) {
			metrics.ScanVerdicts.Inc(v.Scanner, v.Action.String(), "request", nodeName)
			slog.Warn("scan verdict",
				"scanner", v.Scanner, "action", v.Action.String(),
				"direction", "request", "node", nodeName,
				"rpc_method", rpcMethod, "detail", v.Detail)
			// A matched ALLOW rule can request block-on-scan-flag
			// (issue #7): escalate any non-clean verdict for this
			// specific call from "log only" to "block," on top of the
			// scan chain's own unconditional Block action (e.g. secrets
			// outbound, already blocked regardless of policy).
			if v.Action == scan.Block || (decision.BlockOnScanFlag && v.Action != scan.Allow) {
				g.enqueueAudit(claims, rpcMethod+":blocked_scan", auditResource(nodeName, toolName))
				writeJSONRPCError(sr, body, "request blocked by spidercob sanitization")
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	// Three *failure* paths below -- missing session id (non-initialize),
	// unknown/mismatched session, dead upstream -- all fail a request
	// that already passed every policy/pin/schema/scan gate above.
	// They're session-lifecycle or infrastructure failures on an
	// already-authorized call, not a new authorization decision, so none
	// of them call enqueueAudit. This is a deliberate exclusion (issue
	// #45 spec), same category as the auth-failure/unknown-node returns
	// earlier in this function -- named explicitly here since, unlike
	// those two, these three happen *after* policy.Decide already
	// returned Allowed, which is otherwise this function's one consistent
	// signal for "this is audit-worthy." (Doesn't cover the sessionID==""
	// block's own success sub-case just below -- a fresh "initialize"
	// still calls enqueueAudit like every other allowed request; only its
	// sibling "missing session id on a non-initialize call" branch is one
	// of the three exclusions this comment describes.)
	// (Flagged by Copilot's review on PR #46, after merge -- documented
	// here as a direct follow-up; wording corrected per Copilot's review
	// on PR #47, also after merge.)
	if sessionID == "" {
		if rpcMethod != "initialize" {
			http.Error(sr, "missing Mcp-Session-Id", http.StatusBadRequest)
			return
		}
		g.enqueueAudit(claims, rpcMethod+":allowed", auditResource(nodeName, toolName))
		g.handleNewSession(sr, r, nc, body, decision.BlockOnScanFlag)
		return
	}

	sess, ok := g.sessions.get(sessionID)
	if !ok || sess.node != nodeName || sess.principal != claims.Subject {
		// Same 404 whether the session doesn't exist, belongs to a
		// different node, or belongs to a different principal -- a
		// caller who authenticated for this node must never learn
		// "that session exists, it's just not yours" (session hijack:
		// without this check, any principal valid for nodeName could
		// reuse another principal's live session just by obtaining its
		// ID, since node+liveness were the only things checked here).
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
	g.enqueueAudit(claims, rpcMethod+":allowed", auditResource(nodeName, toolName))
	g.forward(sr, r, sess, false, rpcMethod, toolName, body, decision.BlockOnScanFlag)
}

// authenticate validates the request's bearer token against nodeName. On
// failure it writes the 401 response itself (with a WWW-Authenticate
// header pointing at this node's RFC 9728 metadata) and returns ok=false;
// the caller should return immediately without writing anything else.
func (g *Gateway) authenticate(w http.ResponseWriter, r *http.Request, nodeName string) (AuthClaims, bool) {
	wwwAuthenticate := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/%s"`, g.issuer, nodeName)

	token, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
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

// bearerToken extracts the token from an Authorization header value,
// tolerating what RFC 7235 §2.1/RFC 6750 actually allow and a naive
// exact-match against "Bearer " didn't: the auth-scheme is
// case-insensitive ("bearer", "BEARER", ... all valid), and RFC 7230's
// OWS permits more than one space (or a tab) between the scheme and
// the token, plus surrounding whitespace around the token itself.
// Still requires an actual separator between the scheme and the token
// -- "Bearerxyz" is not a valid Bearer header, just a token that
// happens to start with the same letters. internal/adminapi has an
// independent, intentionally-parallel implementation of this same
// logic for its own Authorization header (a different trust boundary,
// no shared import between the two packages) -- keep both in sync if
// this logic ever needs to change.
func bearerToken(authz string) (string, bool) {
	const scheme = "bearer"
	if len(authz) <= len(scheme) || !strings.EqualFold(authz[:len(scheme)], scheme) {
		return "", false
	}
	switch authz[len(scheme)] {
	case ' ', '\t':
	default:
		return "", false
	}
	token := strings.TrimSpace(authz[len(scheme)+1:])
	if token == "" {
		return "", false
	}
	return token, true
}

func (g *Gateway) handleNewSession(w http.ResponseWriter, r *http.Request, nc *nodeConfig, body []byte, blockOnScanFlag bool) {
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
	claims, _ := AuthClaimsFromContext(r.Context()) // always present -- authenticate() already ran before this is reached
	sess, err := g.sessions.create(nc.name, claims.Subject, upstream)
	if err != nil {
		_ = upstream.teardown(r.Context())
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	g.forward(w, r, sess, true, "initialize", "", body, blockOnScanFlag) // handleNewSession is only ever reached when rpcMethod == "initialize"
}

func (g *Gateway) handleDelete(w http.ResponseWriter, ctx context.Context, nodeName, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing Mcp-Session-Id", http.StatusBadRequest)
		return
	}
	claims, _ := AuthClaimsFromContext(ctx) // always present -- authenticate() already ran before this is reached
	sess, ok := g.sessions.get(sessionID)
	if !ok || sess.node != nodeName || sess.principal != claims.Subject {
		// Same hijack/DoS concern as the main dispatch path's session
		// lookup: "a caller who authenticated against this node may
		// always end their own session" (comment above ServeHTTP's
		// DELETE branch) was never actually enforced -- any principal
		// valid for nodeName could end *any* session on it. Same 404
		// for not-found/wrong-node/wrong-principal, for the same
		// non-disclosure reason.
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
	if nc.inProcessHandler != nil {
		return &inProcessUpstreamSession{handler: nc.inProcessHandler}, nil
	}
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

// forward dispatches one request through a session's upstream. Most
// responses (tools/call, tools/list, initialize against a non-streaming
// upstream) go through today's fully-buffered path: the whole body is
// read, DLP-scanned in one pass, and written once. A response the
// upstream marks Content-Type: text/event-stream instead goes through
// forwardStreaming (issue #55) -- a real incremental copy-scan-flush
// loop, only available for upstreams that implement streamingRoundTripper
// (HTTP-transport nodes; stdio nodes fall back to the buffered path
// unconditionally, since they have no HTTP-level streaming signal at
// all). tools/list always takes the buffered path regardless of
// Content-Type: filterToolsListResponse needs the complete, parsed JSON
// body to strip unauthorized/quarantined tools out before it ever
// reaches the client (story 14), and forwardStreaming has no equivalent
// -- an upstream that happened to answer tools/list via SSE would
// otherwise stream every tool straight through with only secret/PII
// redaction applied, silently reopening exactly what that filtering
// exists to close.
func (g *Gateway) forward(w http.ResponseWriter, r *http.Request, sess *mcpSession, newSession bool, rpcMethod, toolName string, body []byte, blockOnScanFlag bool) {
	streamer, ok := sess.upstream.(streamingRoundTripper)
	if !ok {
		buf := newBufferedResponseWriter(g.maxBufferedResponseBytes)
		sess.upstream.ServeHTTP(buf, r)
		g.finishBufferedForward(w, r, sess, newSession, rpcMethod, toolName, buf, body, blockOnScanFlag)
		return
	}

	resp, err := streamer.roundTrip(r)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer resp.Body.Close()

	if rpcMethod == "tools/list" || !isSSEResponse(resp) {
		buf := newBufferedResponseWriter(g.maxBufferedResponseBytes)
		writeUpstreamResponse(buf, resp)
		g.finishBufferedForward(w, r, sess, newSession, rpcMethod, toolName, buf, body, blockOnScanFlag)
		return
	}

	g.forwardStreaming(w, r, sess, newSession, rpcMethod, toolName, resp, body, blockOnScanFlag)
}

// finishBufferedForward is today's original forward() body -- DLP-scan
// the whole buffered response, filter tools/list, stamp session headers,
// write once. Both of forward()'s non-streaming branches funnel into
// this so buffered behavior stays byte-for-byte identical to before
// issue #55, regardless of which one produced buf, with one addition:
// tools/list is now *always* routed here regardless of the upstream's
// Content-Type (forward()'s doc comment explains why), so a tools/list
// response an upstream chose to answer via SSE anyway (legal under the
// MCP streamable_http transport) still needs its JSON-RPC payload pulled
// out of that framing before filterToolsListResponse can do anything
// with it -- otherwise filtering would silently no-op against
// unparseable "data: {...}" bytes and the unfiltered tool list would
// reach the client after all, just through a different door than the
// one already closed.
func (g *Gateway) finishBufferedForward(w http.ResponseWriter, r *http.Request, sess *mcpSession, newSession bool, rpcMethod, toolName string, buf *bufferedResponseWriter, body []byte, blockOnScanFlag bool) {
	if buf.overflow {
		slog.Warn("buffered response exceeded size cap, rejecting",
			"node", sess.node, "rpc_method", rpcMethod, "cap_bytes", buf.limit)
		if claims, ok := AuthClaimsFromContext(r.Context()); ok {
			g.enqueueAudit(claims, rpcMethod+":response_too_large", auditResource(sess.node, toolName))
		}
		writeJSONRPCError(w, body, "response exceeded spidercob size limit")
		return
	}
	clean, verdicts := g.scanners.ScanResponse(buf.body.Bytes())
	for _, v := range verdicts {
		metrics.ScanVerdicts.Inc(v.Scanner, v.Action.String(), "response", sess.node)
		slog.Warn("scan verdict",
			"scanner", v.Scanner, "action", v.Action.String(),
			"direction", "response", "node", sess.node, "detail", v.Detail)
	}

	// Response-direction counterpart of the request-side block check
	// (ServeHTTP, just before scanning the request body): the scan
	// chain's own unconditional Block action, or any non-Allow verdict
	// escalated by the matched ALLOW rule's block-on-scan-flag, must stop
	// the response here -- before any of it (the whole buffered body is
	// already in memory, nothing's been written to w yet) reaches the
	// client. Previously this loop only logged/metriced verdicts and
	// always delivered buf regardless of Action, so neither a hard Block
	// nor block-on-scan-flag ever had any effect on a response -- the
	// request-side gate's "escalate any non-Allow scan verdict on this
	// specific call" (policy.Decision.BlockOnScanFlag's own doc comment)
	// was silently one-directional.
	for _, v := range verdicts {
		if v.Action == scan.Block || (blockOnScanFlag && v.Action != scan.Allow) {
			if claims, ok := AuthClaimsFromContext(r.Context()); ok {
				g.enqueueAudit(claims, rpcMethod+":response_blocked_scan", auditResource(sess.node, toolName))
			}
			writeJSONRPCError(w, body, "response blocked by spidercob sanitization")
			return
		}
	}

	// tools/list itself is gated by the same method-level policy check
	// every other method already went through -- reaching this response
	// stage at all means it was authorized; filtering here further
	// restricts the *contents* of that permitted response to only the
	// tools the caller is separately authorized to invoke via tools/call
	// (story 14: unauthorized tools become invisible, not just blocked).
	sseWrapped := isSSEContentType(buf.header.Get("Content-Type"))
	if rpcMethod == "tools/list" {
		if claims, ok := AuthClaimsFromContext(r.Context()); ok {
			listBody := clean
			if sseWrapped {
				listBody = sseEventData(listBody)
			}
			clean = g.filterToolsListResponse(r.Context(), claims.Subject, sess.node, listBody)
			if sseWrapped {
				// Normalized to plain JSON: tools/list is a synchronous,
				// non-streaming-by-nature method, so there's no reason
				// to round-trip back through SSE framing just because
				// the upstream happened to choose it -- simpler for the
				// client, and sidesteps re-encoding a second event
				// correctly.
				buf.header.Set("Content-Type", "application/json")
			}
		}
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

// isSSEResponse is the streaming-detection trigger (issue #55 spec): an
// upstream response is treated as a real stream only when it says so
// itself via Content-Type. Everything else -- the large majority of
// traffic -- takes the buffered path unchanged.
func isSSEResponse(resp *http.Response) bool {
	return isSSEContentType(resp.Header.Get("Content-Type"))
}

func isSSEContentType(ct string) bool {
	return strings.HasPrefix(strings.TrimSpace(ct), "text/event-stream")
}

// sseEventData extracts the JSON-RPC payload from a body the gateway
// buffered from an upstream that answered a synchronous,
// non-streaming-by-nature request (tools/list) via SSE framing anyway --
// legal under the MCP streamable_http transport, but not something
// filterToolsListResponse's plain json.Unmarshal can parse as-is. MCP's
// SSE encoding for a single request/response pair is one event: one or
// more "data:" lines, joined per the SSE spec (strip the "data:" prefix
// and at most one following space, join what's left with "\n"),
// terminated by a blank line -- exactly what this reconstructs. If body
// contains no "data:" line at all, it's returned unchanged: either it
// was never SSE-framed, or there's nothing to extract either way.
func sseEventData(body []byte) []byte {
	if !bytes.Contains(body, []byte("data:")) {
		return body
	}
	var lines []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		rest, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		lines = append(lines, strings.TrimPrefix(rest, " "))
	}
	if len(lines) == 0 {
		return body
	}
	return []byte(strings.Join(lines, "\n"))
}

// defaultMaxStreamBytes bounds how much of a single streamed response the
// gateway will hold in flight, mirroring maxBodyBytes' existing
// request-side precedent -- closing the response side's equivalent gap
// (issue #55 spec). A stream that exceeds it is terminated, not silently
// truncated-and-called-success: see forwardStreaming's truncated handling.
const defaultMaxStreamBytes = 10 << 20 // 10 MiB

// defaultMaxBufferedResponseBytes is the buffered (non-SSE) response
// path's equivalent of defaultMaxStreamBytes (security review finding
// #5): before it, that path copied an upstream body into memory with no
// bound, so one bad node returning a multi-GB response could exhaust the
// gateway's memory for every session. Over the cap, the response is
// replaced by a JSON-RPC error and audited, never delivered truncated.
const defaultMaxBufferedResponseBytes = 10 << 20 // 10 MiB

// streamCopyChunkSize is how much is read from the upstream body per
// Read call -- small enough that redacted content still reaches the
// client promptly, large enough not to make regex matching per chunk
// needlessly granular.
const streamCopyChunkSize = 32 * 1024

// forwardStreaming relays resp's body to the client incrementally,
// scanning through a windowed ResponseWindow so a secret/PII match
// spanning a chunk boundary is still caught before anything unsafe is
// released (issue #55). If no configured scanner implements
// StreamScanner, it falls back to the safe pre-existing default --
// buffer the whole thing and scan it in one pass -- rather than ever
// forwarding streamed bytes with no scanning applied at all.
func (g *Gateway) forwardStreaming(w http.ResponseWriter, r *http.Request, sess *mcpSession, newSession bool, rpcMethod, toolName string, resp *http.Response, body []byte, blockOnScanFlag bool) {
	window, ok := g.scanners.NewResponseWindow()
	if !ok {
		buf := newBufferedResponseWriter(g.maxBufferedResponseBytes)
		writeUpstreamResponse(buf, resp)
		g.finishBufferedForward(w, r, sess, newSession, rpcMethod, toolName, buf, body, blockOnScanFlag)
		return
	}

	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Mcp-Session-Id") || strings.EqualFold(k, "Content-Length") {
			// Mcp-Session-Id: never leak the upstream's own session id to
			// the client, same as the buffered path. Content-Length:
			// redaction can change the total byte count, and this
			// response is chunked-transfer-encoded, not length-declared --
			// carrying the upstream's original value through would be
			// actively wrong.
			continue
		}
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
	w.WriteHeader(resp.StatusCode)
	flusher, canFlush := w.(http.Flusher)
	if canFlush {
		flusher.Flush()
	}

	metrics.StreamedResponses.Inc(sess.node)

	writeAndFlush := func(b []byte) {
		if len(b) == 0 {
			return
		}
		_, _ = w.Write(b)
		if canFlush {
			flusher.Flush()
		}
	}

	// blockedByVerdict reports whether any verdict in vs requires stopping
	// the stream here -- the same hard-Block-or-escalated-flag rule
	// finishBufferedForward applies to a fully buffered response. Unlike
	// the buffered path, this can only ever stop bytes *not yet
	// written* -- the response's status line and headers are already
	// committed to w by the time any scanning happens (streaming has to
	// commit them before the body exists to scan at all), so a streamed
	// response that trips this can't be turned into a clean 403 the way
	// a buffered one can. The achievable guarantee here is narrower but
	// still real: the flagged/blocked content itself is never flushed to
	// the client, same as the size-cap truncation path just below
	// already accepts "cut off early" as the right trade-off over
	// "deliver all of it anyway."
	blockedByVerdict := func(vs []scan.Verdict) bool {
		for _, v := range vs {
			if v.Action == scan.Block || (blockOnScanFlag && v.Action != scan.Allow) {
				return true
			}
		}
		return false
	}

	var allVerdicts []scan.Verdict
	var total int
	truncated := false
	blockedScan := false
	buf := make([]byte, streamCopyChunkSize)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			total += n
			if total > g.maxStreamBytes {
				truncated = true
				metrics.StreamCapExceeded.Inc(sess.node)
				slog.Warn("streamed response exceeded size cap, terminating",
					"node", sess.node, "cap_bytes", g.maxStreamBytes)
				break
			}
			flushed, verdicts := window.Feed(buf[:n])
			allVerdicts = append(allVerdicts, verdicts...)
			if blockedByVerdict(verdicts) {
				blockedScan = true
				slog.Warn("streamed response blocked by scanning, terminating",
					"node", sess.node, "rpc_method", rpcMethod)
				break
			}
			writeAndFlush(flushed)
		}
		if readErr != nil {
			break // EOF (normal end of stream) or a real read error -- either way, nothing more is coming.
		}
	}
	if !truncated && !blockedScan {
		flushed, verdicts := window.Flush()
		allVerdicts = append(allVerdicts, verdicts...)
		if blockedByVerdict(verdicts) {
			blockedScan = true
			slog.Warn("streamed response blocked by scanning, terminating",
				"node", sess.node, "rpc_method", rpcMethod)
		} else {
			writeAndFlush(flushed)
		}
	}

	for _, v := range allVerdicts {
		metrics.ScanVerdicts.Inc(v.Scanner, v.Action.String(), "response", sess.node)
		slog.Warn("scan verdict",
			"scanner", v.Scanner, "action", v.Action.String(),
			"direction", "response", "node", sess.node, "detail", v.Detail)
	}

	if truncated {
		if claims, ok := AuthClaimsFromContext(r.Context()); ok {
			g.enqueueAudit(claims, rpcMethod+":stream_truncated", auditResource(sess.node, toolName))
		}
	}
	if blockedScan {
		if claims, ok := AuthClaimsFromContext(r.Context()); ok {
			g.enqueueAudit(claims, rpcMethod+":response_blocked_scan", auditResource(sess.node, toolName))
		}
	}
}

// bufferedResponseWriter buffers a response in memory so it can be
// rewritten (DLP-scanned, session headers added) before being flushed to
// the real client. limit > 0 caps how much it will hold (security review
// finding #5): a Write that would go past it is refused with
// errResponseTooLarge and sets overflow, which stops io.Copy from reading
// any more of the upstream body.
type bufferedResponseWriter struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	limit    int
	overflow bool
}

// errResponseTooLarge is what a capped bufferedResponseWriter returns
// once a response would exceed its limit.
var errResponseTooLarge = errors.New("proxy: upstream response exceeds size limit")

func newBufferedResponseWriter(limit int) *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header), status: http.StatusOK, limit: limit}
}

func (b *bufferedResponseWriter) Header() http.Header  { return b.header }
func (b *bufferedResponseWriter) WriteHeader(code int) { b.status = code }
func (b *bufferedResponseWriter) Write(p []byte) (int, error) {
	if b.overflow || (b.limit > 0 && b.body.Len()+len(p) > b.limit) {
		b.overflow = true
		return 0, errResponseTooLarge
	}
	return b.body.Write(p)
}

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

// streamingRoundTripper is an optional capability a sessionUpstream may
// implement: a real round trip to the upstream, returning its response
// headers before the body is consumed, so forward() can inspect
// Content-Type and pick a buffered or windowed-streaming copy strategy
// before committing to either (issue #55). Only httpUpstreamSession
// implements this -- stdio nodes have no HTTP-level streaming signal to
// detect. A sessionUpstream that doesn't implement it makes forward()
// fall back to today's ServeHTTP(buf, r) full-buffer path unchanged,
// the same "optional interface, absence means fall back to existing
// behavior" pattern this package already uses for SetPolicy/
// SetPinRegistry/SetAuditRecorder.
type streamingRoundTripper interface {
	roundTrip(r *http.Request) (*http.Response, error)
}

// roundTrip builds the outbound request (upstream session-ID
// substitution, header hygiene) and performs it, returning the real
// *http.Response with its body not yet consumed -- shared by both
// ServeHTTP (which then copies the body itself) and forward()'s
// streaming-capable path (which inspects headers first).
func (u *httpUpstreamSession) roundTrip(r *http.Request) (*http.Response, error) {
	outURL := *u.upstreamURL
	outURL.Path = singleJoiningSlash(u.upstreamURL.Path, r.URL.Path)

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL.String(), r.Body)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	if upstreamID := resp.Header.Get("Mcp-Session-Id"); upstreamID != "" {
		u.mu.Lock()
		u.upstreamSessionID = upstreamID
		u.mu.Unlock()
	}
	return resp, nil
}

// writeUpstreamResponse copies resp's headers (minus Mcp-Session-Id,
// never leaked to the client), status, and full body into w -- the
// shared tail end of both ServeHTTP and forward()'s non-streaming,
// already-round-tripped path.
func writeUpstreamResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Mcp-Session-Id") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (u *httpUpstreamSession) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := u.roundTrip(r)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	writeUpstreamResponse(w, resp)
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

// jsonRPCToolName extracts params.name from a tools/call request body --
// the tool name policy decisions need for tool-level rules.
func jsonRPCToolName(body []byte) string {
	var m struct {
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	return m.Params.Name
}

// jsonRPCToolArguments extracts params.arguments from a tools/call
// request body -- the raw JSON schema enforcement (issue #11) validates
// against a tool's pinned inputSchema. Returns nil (not an error) on a
// malformed body; the caller treats that the same as "no arguments,"
// consistent with jsonRPCToolName's own best-effort-extraction posture.
func jsonRPCToolArguments(body []byte) json.RawMessage {
	var m struct {
		Params struct {
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	return m.Params.Arguments
}

// filterToolsListResponse rewrites a tools/list JSON-RPC response's tools
// array down to only what policy.FilterTools authorizes and, of those,
// only what isn't currently pin-quarantined (issue #9 story 9: a
// quarantined tool becomes invisible via tools/list, the same "not just
// blocked" treatment story 14 already established for policy-denied
// tools) -- preserving every other field (including the upstream's
// pagination cursor) completely unmodified. If the response isn't a
// well-formed tools/list result (e.g. the upstream returned a JSON-RPC
// error instead), body is returned unchanged -- there's no tools array to
// leak in that case.
func (g *Gateway) filterToolsListResponse(ctx context.Context, principal, node string, body []byte) []byte {
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  *struct {
			Tools      []json.RawMessage `json:"tools"`
			NextCursor string            `json:"nextCursor,omitempty"`
		} `json:"result"`
		Error json.RawMessage `json:"error,omitempty"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Result == nil {
		return body
	}

	var names []string
	byName := make(map[string]json.RawMessage, len(resp.Result.Tools))
	for _, raw := range resp.Result.Tools {
		var t struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &t); err != nil || t.Name == "" {
			continue // malformed tool entry from upstream -- drop rather than risk a policy check on a wrong/empty name
		}
		names = append(names, t.Name)
		byName[t.Name] = raw
	}

	allowed := g.policy.FilterTools(ctx, principal, node, names)
	if g.pins != nil {
		allowed = g.pins.NonQuarantined(ctx, node, allowed)
	}
	filtered := make([]json.RawMessage, 0, len(allowed))
	for _, name := range allowed {
		if raw, ok := byName[name]; ok {
			filtered = append(filtered, raw)
		}
	}
	resp.Result.Tools = filtered

	out, err := json.Marshal(resp)
	if err != nil {
		slog.Error("failed to re-marshal filtered tools/list response", "node", node, "err", err)
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error filtering tools/list"}}`)
	}
	return out
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
