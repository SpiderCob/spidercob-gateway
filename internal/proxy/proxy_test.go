package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
)

func newStdioTestGateway(t *testing.T) *Gateway {
	t.Helper()
	cfg := &config.Config{
		Listen: ":0",
		Nodes: []config.Node{
			{
				Name:      "echo",
				Transport: config.TransportStdio,
				Command:   "go",
				Args:      []string{"run", "./stdioadapter/testdata/echoserver"},
			},
		},
	}
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := gw.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return gw
}

// TestGateway_StdioNodeRoutesLikeHTTPNode is the Phase 1 DoD for the
// stdio adapter: a real stdio MCP server (the echoserver fixture, spawned
// as a real child process) must be reachable through the exact same
// request path -- /mcp/<node>/... -- as an HTTP-backed node.
func TestGateway_StdioNodeRoutesLikeHTTPNode(t *testing.T) {
	gw := newStdioTestGateway(t)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/echo/", strings.NewReader(body))
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v, body: %s", err, rec.Body.String())
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in response: %v", resp)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("expected one content item, got: %v", result["content"])
	}
	item, _ := content[0].(map[string]any)
	if item["text"] != "hi" {
		t.Fatalf("echo mismatch, got %v", item["text"])
	}
}

// TestGateway_StdioNodeResponseIsScanned proves stdio nodes don't bypass
// the outbound DLP chain -- a real gap if left unscanned, since content
// inspection is a core part of what the gateway is for, not an HTTP-only
// nicety.
func TestGateway_StdioNodeResponseIsScanned(t *testing.T) {
	gw := newStdioTestGateway(t)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"key AKIAABCDEFGHIJKLMNOP leaked"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp/echo/", strings.NewReader(body))
	rec := httptest.NewRecorder()

	gw.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "AKIA") {
		t.Fatalf("secret leaked through an unscanned stdio response: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "[REDACTED:aws-access-key]") {
		t.Fatalf("expected a structural redaction marker, got: %s", rec.Body.String())
	}
}
