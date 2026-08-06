// Package stdioadapter exposes a local stdio-speaking MCP server as an
// http.Handler, so the gateway can route to it through the same request
// path as an HTTP-backed node (design doc §6).
//
// Phase 1 scope: a single persistent upstream connection per node, shared
// by every incoming request -- no per-agent session mapping (that's layered
// on top of this in a later task, for both transports together) and no
// crash supervision (also a later task). This mirrors today's HTTP-node
// behavior, which is also a single stateless shared proxy with no session
// awareness yet.
package stdioadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Node spawns a local stdio MCP server and exposes it as an http.Handler.
type Node struct {
	name    string
	session *mcp.ClientSession

	dead atomic.Bool
}

// New spawns command as a stdio MCP server and connects to it. The child
// process and connection are kept alive for the lifetime of the Node --
// call Close to terminate it.
//
// A background watcher detects the connection ending for any reason
// (orderly Close, or the child process crashing on its own) and flips
// Alive() to false -- letting callers distinguish "in-flight session
// whose process just died" from a live one, rather than only finding out
// the hard way on the next failed call.
func New(ctx context.Context, name, command string, args []string) (*Node, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "spidercob-gateway", Version: "0.1.0"}, nil)
	transport := &mcp.CommandTransport{Command: exec.Command(command, args...)}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("stdioadapter %s: connect: %w", name, err)
	}
	n := &Node{name: name, session: session}
	go func() {
		_ = session.Wait() // returns once the connection ends, for any reason
		n.dead.Store(true)
	}()
	return n, nil
}

// Alive reports whether the underlying process/connection is still active.
// Becomes false once the process exits, whether via an orderly Close or an
// unexpected crash.
func (n *Node) Alive() bool { return !n.dead.Load() }

// Close terminates the underlying child process.
func (n *Node) Close() error { return n.session.Close() }

type rpcRequest struct {
	ID     any             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// ServeHTTP handles one JSON-RPC request against the spawned server,
// translating it to a typed call on the underlying ClientSession.
func (n *Node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, nil, -32700, "parse error")
		return
	}

	var result any
	var err error
	switch req.Method {
	case "initialize":
		// The child was already initialized once, when this Node was
		// created -- re-initializing per agent request would spawn
		// redundant handshakes against a process that's already ready.
		result = n.session.InitializeResult()
	case "tools/list":
		var params mcp.ListToolsParams
		if len(req.Params) > 0 {
			if uerr := json.Unmarshal(req.Params, &params); uerr != nil {
				writeError(w, req.ID, -32602, "invalid params")
				return
			}
		}
		result, err = n.session.ListTools(r.Context(), &params)
	case "tools/call":
		var params mcp.CallToolParams
		if uerr := json.Unmarshal(req.Params, &params); uerr != nil {
			writeError(w, req.ID, -32602, "invalid params")
			return
		}
		result, err = n.session.CallTool(r.Context(), &params)
	default:
		writeError(w, req.ID, -32601, "method not found: "+req.Method)
		return
	}
	if err != nil {
		writeError(w, req.ID, -32000, err.Error())
		return
	}
	writeResult(w, req.ID, result)
}

func writeResult(w http.ResponseWriter, id any, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id, "result": result,
	})
}

func writeError(w http.ResponseWriter, id any, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": msg},
	})
}
