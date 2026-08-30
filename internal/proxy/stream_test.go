package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/metrics"
	"github.com/sumeetgp/spidercob-gateway/internal/policy"
)

// fakeAWSKeyHead/fakeAWSKeyTail are a fake AWS-access-key-shaped test
// fixture, built from concatenated pieces rather than one contiguous
// literal so this repo's own dlp-scan pre-commit hook doesn't flag it as
// a real leaked credential -- CONTEXT.md's documented precedent from
// issue #52 (restructure the fixture, don't look for a suppression
// flag). Mirrors internal/scan's identically-purposed package-level
// vars of the same name; duplicated here rather than exported across
// packages since it's test-only fixture data, not production surface.
var (
	fakeAWSKeyHead = "AKIA" + "ABCDE"
	fakeAWSKeyTail = "FGHIJKLMNOP"
)

// capturingWriter is an http.ResponseWriter + http.Flusher test double that
// records every Write call *separately* (unlike httptest.ResponseRecorder,
// which only exposes the final concatenated body) -- the only way to prove
// a response was genuinely delivered incrementally, not buffered and sent
// as one blob that merely happens to contain the right bytes (issue #55
// spec, Testing Decisions: "not just correctness of the end result").
type capturingWriter struct {
	mu      sync.Mutex
	header  http.Header
	status  int
	writes  [][]byte
	flushes int
}

func newCapturingWriter() *capturingWriter {
	return &capturingWriter{header: make(http.Header)}
}

func (c *capturingWriter) Header() http.Header { return c.header }

func (c *capturingWriter) WriteHeader(code int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = code
}

func (c *capturingWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *capturingWriter) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flushes++
}

func (c *capturingWriter) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func (c *capturingWriter) body() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []byte
	for _, w := range c.writes {
		out = append(out, w...)
	}
	return out
}

// newSSEUpstreamServer is a real, minimal streamable_http MCP-shaped test
// upstream that responds to every request with a real text/event-stream
// response, writing chunks one at a time with an explicit Flush and a
// short delay between them so the two flushed segments are actually
// delivered as separate reads on the gateway's side rather than coalesced
// by TCP into one -- the same real-incrementality concern
// TestGateway_SSEResponse_DeliversChunksIncrementally exists to prove.
func newSSEUpstreamServer(t *testing.T, chunks [][]byte, delay time.Duration) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	nextID := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)

		if req.Method == "initialize" {
			mu.Lock()
			nextID++
			id := "sse-upstream-session-" + strconv.Itoa(nextID)
			mu.Unlock()
			w.Header().Set("Mcp-Session-Id", id)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i, c := range chunks {
			_, _ = w.Write(c)
			if flusher != nil {
				flusher.Flush()
			}
			if delay > 0 && i < len(chunks)-1 {
				time.Sleep(delay)
			}
		}
	}))
}

func newSSETestGateway(t *testing.T, upstreamURL string) *Gateway {
	t.Helper()
	cfg := &config.Config{
		Listen: ":0",
		Nodes: []config.Node{
			{Name: "streamy", Transport: config.TransportStreamableHTTP, UpstreamURL: upstreamURL},
		},
	}
	gw, err := New(cfg, fakeValidator{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.policy = policy.AllowAll{}
	t.Cleanup(func() {
		if err := gw.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return gw
}

func TestGateway_SSEResponse_DeliversChunksIncrementally(t *testing.T) {
	upstream := newSSEUpstreamServer(t, [][]byte{bytes.Repeat([]byte("f"), 5000), []byte("-tail")}, 30*time.Millisecond)
	t.Cleanup(func() { upstream.Close() })
	gw := newSSETestGateway(t, upstream.URL)

	sessionID, _ := initialize(t, gw, "streamy")

	req := httptest.NewRequest(http.MethodPost, "/mcp/streamy/", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tail_log"}}`))
	authorize(req)
	req.Header.Set("Mcp-Session-Id", sessionID)
	cw := newCapturingWriter()
	gw.ServeHTTP(cw, req)

	if cw.writeCount() < 2 {
		t.Fatalf("expected the response to arrive as multiple separate writes (real streaming), got %d: %q", cw.writeCount(), cw.body())
	}
	if cw.flushes == 0 {
		t.Fatal("expected at least one Flush call -- a streamed response that's never flushed defeats the point")
	}
	want := strings.Repeat("f", 5000) + "-tail"
	if got := string(cw.body()); got != want {
		t.Fatalf("got body of length %d, want length %d (mismatch)", len(got), len(want))
	}
	if metrics.StreamedResponses.Value("streamy") == 0 {
		t.Error("expected metrics.StreamedResponses to have incremented for node streamy")
	}
}

func TestGateway_SSEResponse_RedactsSecretSplitAcrossChunks(t *testing.T) {
	// A fake AWS-key-shaped string split mid-key across two upstream
	// writes, with no framing in between -- a real chunk boundary
	// splitting one SSE "data:" line's payload partway through, not two
	// separate frames. fakeAWSKeyHead/Tail (built from concatenated
	// pieces, not one contiguous literal -- CONTEXT.md's issue #52
	// precedent) are this repo's dlp-scan-safe way to write a
	// credential-shaped test fixture.
	upstream := newSSEUpstreamServer(t, [][]byte{
		[]byte("data: token=" + fakeAWSKeyHead),
		[]byte(fakeAWSKeyTail + ";done\n\n"),
	}, 30*time.Millisecond)
	t.Cleanup(func() { upstream.Close() })
	gw := newSSETestGateway(t, upstream.URL)

	sessionID, _ := initialize(t, gw, "streamy")
	rec := doWithSession(gw, "streamy", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tail_log"}}`)

	body := rec.Body.String()
	if strings.Contains(body, fakeAWSKeyHead+fakeAWSKeyTail) {
		t.Fatalf("raw secret leaked in streamed response: %q", body)
	}
	if !strings.Contains(body, "[REDACTED:aws-access-key]") {
		t.Fatalf("expected a structural redaction marker, got %q", body)
	}
}

func TestGateway_NonSSEResponse_StaysFullyBufferedWithContentLength(t *testing.T) {
	// Regression: a non-streaming response through the exact same
	// upstream-capability-aware forward() must still behave exactly like
	// before issue #55 -- one write, a real Content-Length header, no
	// chunked-transfer surprises (issue #55 spec, story 9).
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL)

	sessionID, _ := initialize(t, gw, "jira")

	req := httptest.NewRequest(http.MethodPost, "/mcp/jira/", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_issues"}}`))
	authorize(req)
	req.Header.Set("Mcp-Session-Id", sessionID)
	cw := newCapturingWriter()
	gw.ServeHTTP(cw, req)

	if got := cw.writeCount(); got != 1 {
		t.Fatalf("expected exactly one Write call for a buffered response, got %d", got)
	}
	if cw.header.Get("Content-Length") == "" {
		t.Fatal("expected a Content-Length header on the buffered path, same as before issue #55")
	}
	if metrics.StreamedResponses.Value("jira") != 0 {
		t.Error("a non-SSE response must not be counted as streamed")
	}
}

func TestGateway_NewSSESession_StampsSessionHeaderAndCookieBeforeBody(t *testing.T) {
	upstream := newSSEUpstreamServer(t, [][]byte{[]byte("data: ready\n\n")}, 0)
	t.Cleanup(func() { upstream.Close() })
	gw := newSSETestGateway(t, upstream.URL)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/streamy/", strings.NewReader(body))
	authorize(req)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("initialize failed: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Mcp-Session-Id") == "" {
		t.Fatal("expected a gateway-minted Mcp-Session-Id header even on a streaming initialize response")
	}
	var sawCookie bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sawCookie = true
		}
	}
	if !sawCookie {
		t.Fatal("expected the mirrored session cookie to be set on a streaming initialize response")
	}
	// The upstream's own Mcp-Session-Id must never reach the client.
	if rec.Header().Get("Mcp-Session-Id") == "sse-upstream-session-1" {
		t.Fatal("leaked the upstream's own session id to the client")
	}
}

func TestGateway_SSEResponse_ExceedsCapIsTruncatedAndAudited(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 64)
	upstream := newSSEUpstreamServer(t, [][]byte{big, big, big, big}, 5*time.Millisecond)
	t.Cleanup(func() { upstream.Close() })
	gw := newSSETestGateway(t, upstream.URL)
	gw.maxStreamBytes = 32 // force the cap well below what the fake upstream sends

	recorder := newFakeAuditRecorder()
	gw.SetAuditRecorder(recorder)

	sessionID, _ := initialize(t, gw, "streamy")
	rec := doWithSession(gw, "streamy", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tail_log"}}`)

	if len(rec.Body.Bytes()) >= len(big)*4 {
		t.Fatalf("expected the stream to be cut off well before all 4 chunks arrived, got %d bytes", len(rec.Body.Bytes()))
	}
	if metrics.StreamCapExceeded.Value("streamy") == 0 {
		t.Error("expected metrics.StreamCapExceeded to have incremented")
	}

	// The fake upstream serves the same fixed (over-cap) chunk set to
	// every request, including initialize -- so both initialize and
	// tools/call each produce their own "allowed" (pre-forward) and
	// "stream_truncated" pair: 4 records total, not 2. Waiting for only
	// 2 would race, since initialize's own pair alone can already
	// satisfy a count of 2 before tools/call's pair has enqueued.
	records := recorder.waitForCount(t, 4)
	var sawTruncated bool
	for _, r := range records {
		if r.Action == "tools/call:stream_truncated" {
			sawTruncated = true
			if r.Resource != "streamy/tail_log" {
				t.Errorf("expected resource streamy/tail_log, got %q", r.Resource)
			}
		}
	}
	if !sawTruncated {
		t.Fatalf("expected a tools/call:stream_truncated audit record, got %+v", records)
	}
}

func TestGateway_StdioNodeHasNoStreamingCapability(t *testing.T) {
	// stdioUpstreamSession deliberately does not implement
	// streamingRoundTripper -- forward() must fall back to the buffered
	// path unconditionally for stdio nodes (issue #55 spec: scope is
	// HTTP-transport nodes only).
	gw := newStdioTestGateway(t)
	sessionID, _ := initialize(t, gw, "echo")
	rec := doWithSession(gw, "echo", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected a normal buffered response through a stdio node, got status %d: %s", rec.Code, rec.Body.String())
	}
	if metrics.StreamedResponses.Value("echo") != 0 {
		t.Error("a stdio node's response must never be counted as streamed")
	}
}
