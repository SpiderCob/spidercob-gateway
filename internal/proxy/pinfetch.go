package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sumeetgp/spidercob-gateway/internal/pin"
)

// FetchToolsForPin implements pin.Fetcher against this Gateway's own node
// registry -- the composition root passes it to pin.NewScheduler as the
// real, non-fake Fetch. It opens a short-lived upstream connection
// (never registered in the Gateway's session table: invisible to the
// idle-session reaper and to any session-count limit, and always torn
// down before returning, since this exists purely for the background
// pin-refresh scheduler, not a client), issues initialize then
// tools/list, and translates the result into pin.ToolDef values. Returns
// an error for an unknown node name -- config.Nodes at composition time
// is the single source of truth for what gets pinned, same as every
// other per-node feature in this codebase.
func (g *Gateway) FetchToolsForPin(ctx context.Context, node string) ([]pin.ToolDef, error) {
	nc, ok := g.nodes[node]
	if !ok {
		return nil, fmt.Errorf("proxy: unknown node %q", node)
	}

	upstream, err := g.newUpstream(ctx, nc)
	if err != nil {
		return nil, fmt.Errorf("proxy: connect to %s: %w", node, err)
	}
	defer func() { _ = upstream.teardown(ctx) }()

	if _, err := pinRPCCall(ctx, upstream, initializeRequestForPin()); err != nil {
		return nil, fmt.Errorf("proxy: initialize %s: %w", node, err)
	}

	respBody, err := pinRPCCall(ctx, upstream, toolsListRequestForPin())
	if err != nil {
		return nil, fmt.Errorf("proxy: tools/list %s: %w", node, err)
	}

	return parseToolsListForPin(respBody)
}

func initializeRequestForPin() []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"spidercob-pin-refresh","version":"1"}}}`)
}

func toolsListRequestForPin() []byte {
	return []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
}

// pinRPCCall drives one JSON-RPC request through upstream via the same
// transport-agnostic sessionUpstream.ServeHTTP seam the client-facing
// path uses (session.go) -- reusing bufferedResponseWriter (forward's own
// in-memory http.ResponseWriter) rather than any test-only recorder type,
// since this runs in production, not a test. None of the gateway's own
// session bookkeeping, auth, policy, or DLP-scan layers apply to this
// internal, gateway-initiated call.
func pinRPCCall(ctx context.Context, upstream sessionUpstream, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	buf := newBufferedResponseWriter()
	upstream.ServeHTTP(buf, req)
	if buf.status >= 300 {
		return nil, fmt.Errorf("upstream returned status %d: %s", buf.status, buf.body.String())
	}
	return buf.body.Bytes(), nil
}

// parseToolsListForPin extracts name/description/inputSchema from a raw
// tools/list JSON-RPC response -- the same three fields
// filterToolsListResponse already treats as a tool's identity for policy
// purposes, just translated into pin.ToolDef instead of a plain name.
func parseToolsListForPin(body []byte) ([]pin.ToolDef, error) {
	var resp struct {
		Result *struct {
			Tools []struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse tools/list response: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("tools/list returned an error: %s", resp.Error.Message)
	}
	if resp.Result == nil {
		return nil, fmt.Errorf("tools/list response missing result")
	}

	out := make([]pin.ToolDef, 0, len(resp.Result.Tools))
	for _, t := range resp.Result.Tools {
		if t.Name == "" {
			continue // malformed tool entry from upstream -- same drop-rather-than-risk posture filterToolsListResponse takes
		}
		out = append(out, pin.ToolDef{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return out, nil
}
