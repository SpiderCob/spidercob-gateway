package connect

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// defaultRefreshCheckInterval is how often the background loop checks
// every held token's due-ness. Deliberately short relative to even the
// gateway's default 120s NHI token TTL (internal/config's
// DefaultNHITokenTTLSeconds) -- an internal implementation constant, not
// something issue #52's spec exposes as a flag.
const defaultRefreshCheckInterval = 2 * time.Second

// Minter is what Proxy needs to obtain a fresh, node-scoped access token
// -- a minimal interface so this package never needs to know how the
// real gateway's /token endpoint works. cmd/spidercob's httpMinter is
// the real implementation, hitting the real gateway's client_credentials
// grant; tests in this package use a fake.
type Minter interface {
	Mint(ctx context.Context, node string) (token string, expiresAt time.Time, err error)
}

// nodeToken is one node's currently-cached token. Every field access
// goes through its own mutex rather than Proxy's -- a background refresh
// swapping in a new token for node A must never contend with a request
// forwarding traffic for node B.
type nodeToken struct {
	mu        sync.RWMutex
	token     string
	issuedAt  time.Time
	expiresAt time.Time
}

// Proxy is the "spidercob connect" sidecar itself: an http.Handler that
// forwards /mcp/<node>/... requests to the real gateway with a
// currently-valid, node-scoped Authorization header attached, and a
// background loop that keeps every configured node's token fresh
// without the caller ever noticing.
type Proxy struct {
	gatewayURL *url.URL
	minter     Minter
	rp         *httputil.ReverseProxy

	now                  func() time.Time
	refreshFraction      float64
	refreshCheckInterval time.Duration

	mu     sync.RWMutex
	tokens map[string]*nodeToken

	stopCh chan struct{}
	doneCh chan struct{}
}

// New builds a Proxy for the given nodes against gatewayURL. It does not
// mint anything or start the background loop yet -- call Start for that,
// once you're ready to begin serving (issue #52 spec: fail loudly at
// startup if any node's credential doesn't work, not silently once the
// first request arrives).
func New(gatewayURL *url.URL, nodes []string, minter Minter) *Proxy {
	p := &Proxy{
		gatewayURL:           gatewayURL,
		minter:               minter,
		now:                  time.Now,
		refreshFraction:      DefaultRefreshFraction,
		refreshCheckInterval: defaultRefreshCheckInterval,
		tokens:               make(map[string]*nodeToken, len(nodes)),
	}
	for _, n := range nodes {
		p.tokens[n] = &nodeToken{}
	}
	p.rp = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = gatewayURL.Scheme
			req.URL.Host = gatewayURL.Host
			req.Host = gatewayURL.Host
		},
	}
	return p
}

// Start mints an initial token for every configured node -- synchronous
// and fail-loud, so a bad credential is caught at startup, not silently
// degraded into "every request 502s" later -- then launches the
// background refresh loop.
func (p *Proxy) Start(ctx context.Context) error {
	p.mu.RLock()
	nodes := make([]string, 0, len(p.tokens))
	for n := range p.tokens {
		nodes = append(nodes, n)
	}
	p.mu.RUnlock()

	for _, node := range nodes {
		if _, err := p.mint(ctx, node); err != nil {
			return fmt.Errorf("connect: initial token mint for node %q failed: %w", node, err)
		}
	}

	p.stopCh = make(chan struct{})
	p.doneCh = make(chan struct{})
	go p.refreshLoop()
	return nil
}

// Close stops the background refresh loop and waits for it to actually
// exit -- mirrors internal/proxy.Gateway's own stopReaper/reaperDone
// shutdown shape.
func (p *Proxy) Close() error {
	if p.stopCh != nil {
		close(p.stopCh)
		<-p.doneCh
	}
	return nil
}

func (p *Proxy) refreshLoop() {
	defer close(p.doneCh)
	t := time.NewTicker(p.refreshCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-t.C:
			p.refreshDueTokens()
		}
	}
}

// refreshDueTokens checks every configured node's due-ness (the pure
// dueForRefresh decision) and attempts a mint for any that are due. A
// failed attempt is logged and the existing token is left completely
// untouched -- a transient mint failure must never drop a still-valid
// token early.
func (p *Proxy) refreshDueTokens() {
	p.mu.RLock()
	nodes := make([]string, 0, len(p.tokens))
	for n := range p.tokens {
		nodes = append(nodes, n)
	}
	p.mu.RUnlock()

	for _, node := range nodes {
		p.mu.RLock()
		nt := p.tokens[node]
		p.mu.RUnlock()

		nt.mu.RLock()
		due := dueForRefresh(p.now(), nt.issuedAt, nt.expiresAt, p.refreshFraction)
		nt.mu.RUnlock()
		if !due {
			continue
		}
		if _, err := p.mint(context.Background(), node); err != nil {
			slog.Warn("connect: background token refresh failed, keeping last-known-good token in service", "node", node, "err", err)
		}
	}
}

// mint calls the real minter for node and, on success, stores the
// result. Shared by Start's initial mint, the background refresh loop,
// and tokenFor's on-demand fallback -- one call site, one place that
// updates a nodeToken.
func (p *Proxy) mint(ctx context.Context, node string) (string, error) {
	p.mu.RLock()
	nt, ok := p.tokens[node]
	p.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("node %q not configured", node)
	}
	token, expiresAt, err := p.minter.Mint(ctx, node)
	if err != nil {
		return "", err
	}
	nt.mu.Lock()
	nt.token = token
	nt.issuedAt = p.now()
	nt.expiresAt = expiresAt
	nt.mu.Unlock()
	return token, nil
}

// tokenFor returns node's currently-cached token if it's still valid, or
// synchronously mints a fresh one on the spot -- the fallback for a
// request that arrives against an already-stale token (proactive
// refresh failed repeatedly, or the process just started and Start
// hasn't been called in this exact code path, e.g. in tests exercising
// ServeHTTP directly).
func (p *Proxy) tokenFor(ctx context.Context, node string) (string, error) {
	p.mu.RLock()
	nt, ok := p.tokens[node]
	p.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("node %q not configured", node)
	}

	nt.mu.RLock()
	token, expiresAt := nt.token, nt.expiresAt
	nt.mu.RUnlock()
	if token != "" && p.now().Before(expiresAt) {
		return token, nil
	}
	return p.mint(ctx, node)
}

func (p *Proxy) hasNode(node string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.tokens[node]
	return ok
}

// ServeHTTP forwards a /mcp/<node>/... request to the real gateway with
// a currently-valid Authorization header attached. An unconfigured node
// gets a clear 404 from the proxy itself (never a confusing pass-through
// to the real gateway), and a token that can't be obtained at all (mint
// failure, on-demand or otherwise) gets a 502 naming the real cause --
// never a silently-forwarded stale or missing credential.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	node, ok := nodeFromPath(r.URL.Path)
	if !ok {
		http.Error(w, "connect: expected a path like /mcp/<node>/...", http.StatusNotFound)
		return
	}
	if !p.hasNode(node) {
		http.Error(w, fmt.Sprintf("connect: not configured for node %q", node), http.StatusNotFound)
		return
	}
	token, err := p.tokenFor(r.Context(), node)
	if err != nil {
		http.Error(w, fmt.Sprintf("connect: could not obtain a token for node %q: %v", node, err), http.StatusBadGateway)
		return
	}
	r.Header.Set("Authorization", "Bearer "+token)
	p.rp.ServeHTTP(w, r)
}

// nodeFromPath mirrors internal/proxy.Gateway.ServeHTTP's own
// "/mcp/<node>/..." parsing exactly, so the URL shape a client points at
// this local proxy is identical to the real gateway's.
func nodeFromPath(path string) (string, bool) {
	rest := strings.TrimPrefix(path, "/mcp/")
	if rest == path {
		return "", false // no "/mcp/" prefix at all
	}
	parts := strings.SplitN(rest, "/", 2)
	if parts[0] == "" {
		return "", false
	}
	return parts[0], true
}
