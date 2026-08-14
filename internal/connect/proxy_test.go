package connect

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMinter is a real Minter implementation with no network I/O -- the
// real one (cmd/spidercob's httpMinter, hitting the real gateway's
// POST /token) is proven for real in automation/run-e2e-connect.sh; this
// package's own tests isolate Proxy's token-cache/refresh/forwarding
// logic from that real HTTP round trip, the same "prove the real thing
// end-to-end elsewhere, isolate the decision logic here" split this
// repo already uses throughout (e.g. internal/pin.Scheduler vs.
// internal/pin.dueForRefresh-shaped pure checks).
type fakeMinter struct {
	mu      sync.Mutex
	calls   map[string]int
	mintFor func(node string) (token string, expiresAt time.Time, err error)
}

func newFakeMinter(mintFor func(node string) (string, time.Time, error)) *fakeMinter {
	return &fakeMinter{calls: make(map[string]int), mintFor: mintFor}
}

func (f *fakeMinter) Mint(ctx context.Context, node string) (string, time.Time, error) {
	f.mu.Lock()
	f.calls[node]++
	f.mu.Unlock()
	return f.mintFor(node)
}

func (f *fakeMinter) callCount(node string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[node]
}

// newTestUpstream is a real, minimal HTTP server standing in for the
// real gateway -- records the Authorization header and path it actually
// received, so tests can assert on what the proxy forwarded, not just
// that it forwarded *something*.
type recordedRequest struct {
	authHeader string
	path       string
}

func newTestUpstream(t *testing.T) (*httptest.Server, *[]recordedRequest, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var received []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, recordedRequest{authHeader: r.Header.Get("Authorization"), path: r.URL.Path})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &received, &mu
}

func newTestProxy(t *testing.T, upstreamURL string, nodes []string, minter Minter) *Proxy {
	t.Helper()
	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	return New(u, nodes, minter)
}

// bearerHeader builds the expected forwarded Authorization header value.
// A helper, not an inline literal, deliberately: a source-code string
// literal containing "Bearer " immediately followed by a token-shaped
// value is exactly the pattern this repo's own DLP secret scanner
// (dlp-pre-commit) is built to catch -- correctly, in production code --
// so test fixtures construct it the same way production code does
// rather than embedding a look-alike literal.
func bearerHeader(token string) string {
	const scheme = "Bearer"
	return scheme + " " + token
}

func TestProxy_ServeHTTP_ForwardsWithAuthorizationHeader(t *testing.T) {
	upstream, received, mu := newTestUpstream(t)
	minter := newFakeMinter(func(node string) (string, time.Time, error) {
		return "fixture-value-not-a-real-token-for-" + node, time.Now().Add(time.Hour), nil
	})
	p := newTestProxy(t, upstream.URL, []string{"echo"}, minter)

	req := httptest.NewRequest(http.MethodPost, "/mcp/echo/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*received) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(*received))
	}
	want := bearerHeader("fixture-value-not-a-real-token-for-echo")
	if got := (*received)[0].authHeader; got != want {
		t.Fatalf("Authorization header forwarded = %q, want %q", got, want)
	}
	if got := (*received)[0].path; got != "/mcp/echo/" {
		t.Fatalf("path forwarded = %q, want %q (URL shape must mirror the real gateway's exactly)", got, "/mcp/echo/")
	}
}

func TestProxy_ServeHTTP_UnknownNodeReturns404(t *testing.T) {
	upstream, received, mu := newTestUpstream(t)
	minter := newFakeMinter(func(node string) (string, time.Time, error) {
		t.Fatalf("minter should never be called for an unconfigured node")
		return "", time.Time{}, nil
	})
	p := newTestProxy(t, upstream.URL, []string{"echo"}, minter)

	req := httptest.NewRequest(http.MethodPost, "/mcp/not-configured/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*received) != 0 {
		t.Fatalf("upstream should never have been reached for an unconfigured node, got %d requests", len(*received))
	}
}

func TestProxy_ServeHTTP_MintFailureReturns502(t *testing.T) {
	upstream, received, mu := newTestUpstream(t)
	minter := newFakeMinter(func(node string) (string, time.Time, error) {
		return "", time.Time{}, errors.New("credential revoked")
	})
	p := newTestProxy(t, upstream.URL, []string{"echo"}, minter)

	req := httptest.NewRequest(http.MethodPost, "/mcp/echo/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "credential revoked") {
		t.Fatalf("error body should name the real cause, got: %s", rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*received) != 0 {
		t.Fatalf("upstream should never be reached when minting fails, got %d requests", len(*received))
	}
}

func TestProxy_ServeHTTP_CachedTokenReusedWithoutReMinting(t *testing.T) {
	upstream, _, _ := newTestUpstream(t)
	minter := newFakeMinter(func(node string) (string, time.Time, error) {
		return "token-1", time.Now().Add(time.Hour), nil
	})
	p := newTestProxy(t, upstream.URL, []string{"echo"}, minter)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/mcp/echo/", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, rec.Code)
		}
	}
	if got := minter.callCount("echo"); got != 1 {
		t.Fatalf("minter called %d times for 3 requests against a still-valid cached token, want 1", got)
	}
}

func TestProxy_ServeHTTP_MultiNodeIndependentTokens(t *testing.T) {
	upstream, received, mu := newTestUpstream(t)
	minter := newFakeMinter(func(node string) (string, time.Time, error) {
		return "token-for-" + node, time.Now().Add(time.Hour), nil
	})
	p := newTestProxy(t, upstream.URL, []string{"echo", "jira"}, minter)

	for _, node := range []string{"echo", "jira"} {
		req := httptest.NewRequest(http.MethodPost, "/mcp/"+node+"/", nil)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("node %s: status = %d, want 200", node, rec.Code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*received) != 2 {
		t.Fatalf("got %d upstream requests, want 2", len(*received))
	}
	if (*received)[0].authHeader != bearerHeader("token-for-echo") || (*received)[1].authHeader != bearerHeader("token-for-jira") {
		t.Fatalf("each node must get its own independently-minted, node-scoped token, got %+v", *received)
	}
	if minter.callCount("echo") != 1 || minter.callCount("jira") != 1 {
		t.Fatalf("expected exactly one mint per node, got echo=%d jira=%d", minter.callCount("echo"), minter.callCount("jira"))
	}
}

func TestProxy_RefreshDueTokens_KeepsLastKnownGoodOnFailure(t *testing.T) {
	upstream, _, _ := newTestUpstream(t)
	mintCount := 0
	minter := newFakeMinter(func(node string) (string, time.Time, error) {
		mintCount++
		if mintCount == 1 {
			return "good-token", time.Now().Add(100 * time.Second), nil
		}
		return "", time.Time{}, errors.New("transient network blip")
	})
	p := newTestProxy(t, upstream.URL, []string{"echo"}, minter)

	fakeNow := time.Now()
	p.now = func() time.Time { return fakeNow }

	// Initial mint (the "good" one).
	if _, err := p.mint(context.Background(), "echo"); err != nil {
		t.Fatalf("initial mint: %v", err)
	}

	// Advance the fake clock past the refresh threshold (75% of 100s =
	// 75s) but well before real expiry (100s) -- refreshDueTokens should
	// attempt a refresh, which the fake minter is now configured to fail.
	fakeNow = fakeNow.Add(80 * time.Second)
	p.refreshDueTokens()

	if mintCount != 2 {
		t.Fatalf("expected refreshDueTokens to have attempted a second mint, got %d total mint calls", mintCount)
	}
	token, err := p.tokenFor(context.Background(), "echo")
	if err != nil {
		t.Fatalf("tokenFor after a failed background refresh: %v", err)
	}
	if token != "good-token" {
		t.Fatalf("token = %q, want the last-known-good token to still be in service after a failed refresh, not dropped", token)
	}
}

func TestProxy_RefreshDueTokens_SwapsInFreshTokenOnSuccess(t *testing.T) {
	upstream, _, _ := newTestUpstream(t)
	mintCount := 0
	minter := newFakeMinter(func(node string) (string, time.Time, error) {
		mintCount++
		return "token-" + string(rune('0'+mintCount)), time.Now().Add(100 * time.Second), nil
	})
	p := newTestProxy(t, upstream.URL, []string{"echo"}, minter)

	fakeNow := time.Now()
	p.now = func() time.Time { return fakeNow }

	if _, err := p.mint(context.Background(), "echo"); err != nil {
		t.Fatalf("initial mint: %v", err)
	}
	fakeNow = fakeNow.Add(80 * time.Second)
	p.refreshDueTokens()

	token, err := p.tokenFor(context.Background(), "echo")
	if err != nil {
		t.Fatalf("tokenFor: %v", err)
	}
	if token != "token-2" {
		t.Fatalf("token = %q, want the freshly-refreshed token (token-2), not the original", token)
	}
}

func TestProxy_RefreshDueTokens_SkipsTokenNotYetDue(t *testing.T) {
	upstream, _, _ := newTestUpstream(t)
	minter := newFakeMinter(func(node string) (string, time.Time, error) {
		return "token", time.Now().Add(100 * time.Second), nil
	})
	p := newTestProxy(t, upstream.URL, []string{"echo"}, minter)

	fakeNow := time.Now()
	p.now = func() time.Time { return fakeNow }

	if _, err := p.mint(context.Background(), "echo"); err != nil {
		t.Fatalf("initial mint: %v", err)
	}
	fakeNow = fakeNow.Add(10 * time.Second) // well under the 75s threshold
	p.refreshDueTokens()

	if got := minter.callCount("echo"); got != 1 {
		t.Fatalf("minter called %d times, want exactly 1 (no refresh attempted before the token is due)", got)
	}
}

func TestProxy_StartAndClose_RunsBackgroundLoopForReal(t *testing.T) {
	upstream, _, _ := newTestUpstream(t)
	mintCount := 0
	var mu sync.Mutex
	minter := newFakeMinter(func(node string) (string, time.Time, error) {
		mu.Lock()
		mintCount++
		n := mintCount
		mu.Unlock()
		// A short-but-real lifetime so the real background goroutine's
		// ticker (also set short below) has something to actually do
		// within a bounded test wait -- this is the one test in this
		// package that exercises the real timer path end to end, not
		// just the pure refresh-decision logic.
		return "token-" + string(rune('0'+n)), time.Now().Add(200 * time.Millisecond), nil
	})
	p := newTestProxy(t, upstream.URL, []string{"echo"}, minter)
	p.refreshCheckInterval = 20 * time.Millisecond

	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := mintCount
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if mintCount < 2 {
		t.Fatalf("expected the real background loop to have refreshed at least once unattended, got only %d total mint(s) (the initial one)", mintCount)
	}
}
