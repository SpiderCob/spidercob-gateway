package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Security review finding #5: the buffered (non-SSE) response path copied
// an upstream body into memory with no size cap, so one bad MCP node
// returning a huge response could exhaust the gateway's memory and take
// down every other session. It now has the same cap as the request and
// streaming paths.

// newJSONUpstreamServer answers initialize normally and every other call
// with a plain application/json result whose text field is payloadSize
// bytes long -- the buffered path, not SSE.
func newJSONUpstreamServer(t *testing.T, payloadSize int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		w.Header().Set("Content-Type", "application/json")
		id, _ := json.Marshal(req.ID)
		if req.Method == "initialize" {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, id)
			return
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"text":"%s"}}`, id, strings.Repeat("A", payloadSize))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGateway_BufferedResponseOverCapIsRejectedNotDelivered(t *testing.T) {
	upstream := newJSONUpstreamServer(t, 4096)
	gw := newSSETestGateway(t, upstream.URL)
	gw.maxBufferedResponseBytes = 1024

	recorder := newFakeAuditRecorder()
	gw.SetAuditRecorder(recorder)

	sessionID, _ := initialize(t, gw, "streamy")
	rec := doWithSession(gw, "streamy", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dump"}}`)

	if strings.Contains(rec.Body.String(), strings.Repeat("A", 1024)) {
		t.Fatalf("over-cap upstream response was delivered to the client (%d bytes)", rec.Body.Len())
	}
	var resp struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Error == nil {
		t.Fatalf("expected a JSON-RPC error, got status %d body %q", rec.Code, rec.Body.String())
	}

	var sawTooLarge bool
	for _, r := range recorder.waitForCount(t, 3) {
		if r.Action == "tools/call:response_too_large" {
			sawTooLarge = true
		}
	}
	if !sawTooLarge {
		t.Fatal("expected a tools/call:response_too_large audit record")
	}
}

func TestGateway_BufferedResponseUnderCapIsDeliveredUnchanged(t *testing.T) {
	upstream := newJSONUpstreamServer(t, 512)
	gw := newSSETestGateway(t, upstream.URL)
	gw.maxBufferedResponseBytes = 1024

	sessionID, _ := initialize(t, gw, "streamy")
	rec := doWithSession(gw, "streamy", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dump"}}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), strings.Repeat("A", 512)) {
		t.Fatalf("under-cap response not delivered intact: status %d, %d bytes", rec.Code, rec.Body.Len())
	}
}

func TestBufferedResponseWriter_StopsAcceptingPastLimit(t *testing.T) {
	buf := newBufferedResponseWriter(10)
	if _, err := buf.Write([]byte("0123456789")); err != nil {
		t.Fatalf("write up to the limit: %v", err)
	}
	if _, err := buf.Write([]byte("x")); err == nil {
		t.Fatal("expected an error writing past the limit")
	}
	if !buf.overflow || buf.body.Len() > 10 {
		t.Fatalf("overflow=%v len=%d, want overflow and len <= 10", buf.overflow, buf.body.Len())
	}
}
