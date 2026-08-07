package stdioadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestNode spawns the real echoserver fixture (internal/proxy/stdioadapter
// /testdata/echoserver) as a child process via `go run` -- a real stdio MCP
// server, not a mock -- per the repo's end-to-end validation rule.
func newTestNode(t *testing.T) *Node {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	n, err := New(ctx, "echo", "go", []string{"run", "./testdata/echoserver"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := n.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return n
}

func doRPC(t *testing.T, n *Node, method string, params any) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()

	n.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response %q: %v", rec.Body.String(), err)
	}
	return resp
}

func TestNode_Initialize(t *testing.T) {
	n := newTestNode(t)

	resp := doRPC(t, n, "initialize", nil)
	if _, ok := resp["error"]; ok {
		t.Fatalf("initialize returned an error: %v", resp["error"])
	}
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("result missing or wrong shape: %v", resp)
	}
	if _, ok := result["serverInfo"]; !ok {
		t.Fatalf("initialize result missing serverInfo: %v", result)
	}
}

func TestNode_ToolsList(t *testing.T) {
	n := newTestNode(t)

	resp := doRPC(t, n, "tools/list", map[string]any{})
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("result missing or wrong shape: %v", resp)
	}
	tools, ok := result["tools"].([]any)
	if !ok || len(tools) != 1 {
		t.Fatalf("expected exactly one tool, got: %v", result["tools"])
	}
	tool, _ := tools[0].(map[string]any)
	if tool["name"] != "echo" {
		t.Fatalf("expected tool named 'echo', got: %v", tool["name"])
	}
}

func TestNode_ToolsCall(t *testing.T) {
	n := newTestNode(t)

	resp := doRPC(t, n, "tools/call", map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"text": "hello from the gateway"},
	})
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("result missing or wrong shape: %v", resp)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("expected exactly one content item, got: %v", result["content"])
	}
	item, _ := content[0].(map[string]any)
	if item["text"] != "hello from the gateway" {
		t.Fatalf("echo mismatch, got: %v", item["text"])
	}
}

// TestNode_AliveBecomesFalseOnUnexpectedCrash uses the real crashserver
// fixture, which completes initialize normally then exits on its own
// shortly after -- proving Alive() detects a real, unexpected process
// death, not just an orderly Close().
func TestNode_AliveBecomesFalseOnUnexpectedCrash(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	n, err := New(ctx, "crash", "go", []string{"run", "./testdata/crashserver"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer n.Close()

	if !n.Alive() {
		t.Fatal("expected the node to be alive immediately after a successful connect")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !n.Alive() {
			return // success: crash was detected
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expected Alive() to become false after the fixture's unexpected exit")
}

func TestNode_UnknownMethod(t *testing.T) {
	n := newTestNode(t)

	resp := doRPC(t, n, "resources/list", map[string]any{})
	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected a JSON-RPC error for an unsupported method, got: %v", resp)
	}
	if code, _ := errObj["code"].(float64); code != -32601 {
		t.Fatalf("expected method-not-found code -32601, got: %v", errObj["code"])
	}
}
