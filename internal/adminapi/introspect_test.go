package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeSpiderSnoopServer is a real, minimal HTTP fixture standing in for
// spider-snoop's GET /api/users/me -- mirrors this repo's established
// "real, minimal fixture server, not an in-process mock" pattern
// (internal/proxy's newFakeUpstreamServer), just applied to a fake
// spider-snoop instead of a fake MCP node.
func fakeSpiderSnoopServer(t *testing.T, wantAuthHeader, username, role string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantAuthHeader != "" && r.Header.Get("Authorization") != wantAuthHeader {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(map[string]string{"username": username, "role": role})
		}
	}))
}

func TestHTTPIntrospector_ValidTokenReturnsRoleAndUsername(t *testing.T) {
	srv := fakeSpiderSnoopServer(t, "Bearer real-session-token", "alice", "admin", http.StatusOK)
	t.Cleanup(srv.Close)

	introspector := NewHTTPIntrospector(srv.URL, time.Second)
	result, err := introspector.Introspect(context.Background(), "real-session-token")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if result.Username != "alice" || result.Role != "admin" {
		t.Fatalf("Introspect result = %+v, want {alice admin}", result)
	}
}

func TestHTTPIntrospector_NonOKStatusErrors(t *testing.T) {
	srv := fakeSpiderSnoopServer(t, "", "", "", http.StatusUnauthorized)
	t.Cleanup(srv.Close)

	introspector := NewHTTPIntrospector(srv.URL, time.Second)
	if _, err := introspector.Introspect(context.Background(), "bad-or-expired-token"); err == nil {
		t.Fatal("expected an error for a non-200 introspection response, got nil")
	}
}

func TestHTTPIntrospector_UnreachableServerErrors(t *testing.T) {
	// Fail closed: an unreachable spider-snoop is an error, never a
	// silent "trust it anyway."
	introspector := NewHTTPIntrospector("http://127.0.0.1:1", time.Second)
	if _, err := introspector.Introspect(context.Background(), "whatever"); err == nil {
		t.Fatal("expected an error for an unreachable spider-snoop, got nil")
	}
}

func TestHTTPIntrospector_TimeoutErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	introspector := NewHTTPIntrospector(srv.URL, 5*time.Millisecond)
	if _, err := introspector.Introspect(context.Background(), "whatever"); err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
}

// fakeIntrospector is a hand-rolled SpiderSnoopIntrospector for testing
// CachingIntrospector's own caching behavior in isolation from any real
// HTTP.
type fakeIntrospector struct {
	calls  int
	result IntrospectionResult
	err    error
}

func (f *fakeIntrospector) Introspect(ctx context.Context, humanToken string) (IntrospectionResult, error) {
	f.calls++
	return f.result, f.err
}

func TestCachingIntrospector_CachesWithinTTL(t *testing.T) {
	fake := &fakeIntrospector{result: IntrospectionResult{Username: "alice", Role: "admin"}}
	clockTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return clockTime }
	c := newCachingIntrospectorWithClock(fake, 30*time.Second, clock)

	if _, err := c.Introspect(context.Background(), "tok"); err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if _, err := c.Introspect(context.Background(), "tok"); err != nil {
		t.Fatalf("Introspect (cached): %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("inner Introspect called %d times, want 1 (second call should hit the cache)", fake.calls)
	}
}

func TestCachingIntrospector_RefreshesAfterTTLExpires(t *testing.T) {
	fake := &fakeIntrospector{result: IntrospectionResult{Username: "alice", Role: "admin"}}
	clockTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return clockTime }
	c := newCachingIntrospectorWithClock(fake, 30*time.Second, clock)

	if _, err := c.Introspect(context.Background(), "tok"); err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	clockTime = clockTime.Add(31 * time.Second)
	if _, err := c.Introspect(context.Background(), "tok"); err != nil {
		t.Fatalf("Introspect (after TTL): %v", err)
	}
	if fake.calls != 2 {
		t.Fatalf("inner Introspect called %d times, want 2 (cache should have expired)", fake.calls)
	}
}

func TestCachingIntrospector_DoesNotCacheErrors(t *testing.T) {
	fake := &fakeIntrospector{err: errors.New("spider-snoop unreachable")}
	clockTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return clockTime }
	c := newCachingIntrospectorWithClock(fake, 30*time.Second, clock)

	if _, err := c.Introspect(context.Background(), "tok"); err == nil {
		t.Fatal("expected an error to propagate, got nil")
	}
	if _, err := c.Introspect(context.Background(), "tok"); err == nil {
		t.Fatal("expected a second error (not a cached success), got nil")
	}
	if fake.calls != 2 {
		t.Fatalf("inner Introspect called %d times, want 2 (errors must never be cached)", fake.calls)
	}
}

func TestCachingIntrospector_DifferentTokensCachedIndependently(t *testing.T) {
	fake := &fakeIntrospector{result: IntrospectionResult{Username: "alice", Role: "admin"}}
	c := NewCachingIntrospector(fake, 30*time.Second)

	if _, err := c.Introspect(context.Background(), "tok-a"); err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if _, err := c.Introspect(context.Background(), "tok-b"); err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if fake.calls != 2 {
		t.Fatalf("inner Introspect called %d times, want 2 (distinct tokens must not share a cache entry)", fake.calls)
	}
}
