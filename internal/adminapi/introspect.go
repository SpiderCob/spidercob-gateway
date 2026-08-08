package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IntrospectionResult is what a successful introspection reveals about
// the human behind an admin API request.
type IntrospectionResult struct {
	Username string
	Role     string
}

// SpiderSnoopIntrospector confirms a human session token is currently
// valid and reports its role -- the live half of the admin API's dual
// trust check (issue #13). Behind an interface deliberately: unit tests
// substitute a fake with no real HTTP; it's also the one seam a future
// swap (a different spider-snoop deployment, or eventually a standalone
// shared login/tenant service) would need to change, not a gateway
// rewrite.
type SpiderSnoopIntrospector interface {
	Introspect(ctx context.Context, humanToken string) (IntrospectionResult, error)
}

// HTTPIntrospector is the real implementation: GET {BaseURL}/api/users/me
// with the human's own bearer token -- the exact call spider-snoop's own
// frontend already makes to validate a session (useAuth.js), so this
// asks spider-snoop the same question it already asks itself, rather
// than independently verifying spider-snoop's JWT signature (which would
// require sharing its HS256 secret -- a deliberately rejected design,
// see MASTER_PLAN.md §6, 2026-08-08).
type HTTPIntrospector struct {
	baseURL string
	client  *http.Client
}

// NewHTTPIntrospector builds an HTTPIntrospector against baseURL (spider-
// snoop's own address), bounding every introspection call to timeout so
// a hung spider-snoop can't hang an admin request indefinitely (fail
// closed, not open, on a timeout -- Introspect returns an error, and the
// caller's Gate denies on any error).
func NewHTTPIntrospector(baseURL string, timeout time.Duration) *HTTPIntrospector {
	return &HTTPIntrospector{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (h *HTTPIntrospector) Introspect(ctx context.Context, humanToken string) (IntrospectionResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.baseURL+"/api/users/me", nil)
	if err != nil {
		return IntrospectionResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+humanToken)

	resp, err := h.client.Do(req)
	if err != nil {
		return IntrospectionResult{}, fmt.Errorf("adminapi: introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return IntrospectionResult{}, fmt.Errorf("adminapi: introspection returned status %d", resp.StatusCode)
	}

	var body struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return IntrospectionResult{}, fmt.Errorf("adminapi: parse introspection response: %w", err)
	}
	return IntrospectionResult{Username: body.Username, Role: body.Role}, nil
}

// CachingIntrospector wraps another SpiderSnoopIntrospector with a short,
// explicit-TTL in-memory cache keyed by the human token itself -- the
// same "in-memory, per-process, defense-in-depth is fine for v1" posture
// already established for internal/policy's rate limiter, applied here
// to bound (not eliminate) introspection staleness: a burst of admin
// requests from the same session doesn't cost a live network call each,
// but a spider-snoop logout is still respected within one TTL window,
// not indefinitely. Errors are never cached -- a transient spider-snoop
// blip must not keep denying access for the whole TTL once spider-snoop
// recovers; the very next request retries live.
type CachingIntrospector struct {
	inner SpiderSnoopIntrospector
	ttl   time.Duration
	clock func() time.Time

	mu    sync.Mutex
	cache map[string]cachedIntrospection
}

type cachedIntrospection struct {
	result   IntrospectionResult
	cachedAt time.Time
}

// NewCachingIntrospector wraps inner with a real wall-clock cache of ttl.
func NewCachingIntrospector(inner SpiderSnoopIntrospector, ttl time.Duration) *CachingIntrospector {
	return newCachingIntrospectorWithClock(inner, ttl, time.Now)
}

// newCachingIntrospectorWithClock is the injectable-clock constructor
// tests use to control cache-expiry timing without a real wait.
func newCachingIntrospectorWithClock(inner SpiderSnoopIntrospector, ttl time.Duration, clock func() time.Time) *CachingIntrospector {
	return &CachingIntrospector{
		inner: inner,
		ttl:   ttl,
		clock: clock,
		cache: make(map[string]cachedIntrospection),
	}
}

func (c *CachingIntrospector) Introspect(ctx context.Context, humanToken string) (IntrospectionResult, error) {
	now := c.clock()

	c.mu.Lock()
	cached, ok := c.cache[humanToken]
	c.mu.Unlock()
	if ok && now.Sub(cached.cachedAt) < c.ttl {
		return cached.result, nil
	}

	result, err := c.inner.Introspect(ctx, humanToken)
	if err != nil {
		return IntrospectionResult{}, err
	}

	c.mu.Lock()
	c.cache[humanToken] = cachedIntrospection{result: result, cachedAt: now}
	c.mu.Unlock()

	return result, nil
}
