# Session Lifecycle: HTTP vs. stdio

Companion to `MASTER_PLAN.md` §3 (Phase 1) and the code in `internal/proxy/` — the
"how" behind session mapping, for both transports, as three request
lifecycles: establishing a session (`initialize`), continuing one
(`tools/call`), and ending one (`DELETE`). A fourth diagram covers the
stdio-only crash/self-heal path, which has no HTTP equivalent.

The one constant across every diagram: `Gateway.ServeHTTP` and
`sessionManager` are fully transport-agnostic. Everything that differs
lives inside `sessionUpstream` — `httpUpstreamSession` or
`stdioUpstreamSession`.

## HTTP-backed node (e.g. `jira`)

### `initialize` — new session

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway as Gateway.ServeHTTP
    participant Sessions as sessionManager
    participant HTTPUp as httpUpstreamSession
    participant Upstream as Real upstream MCP server

    Agent->>Gateway: POST /mcp/jira/ (initialize, no Mcp-Session-Id)
    Gateway->>Gateway: inbound scan, rpcMethod = "initialize"
    Gateway->>HTTPUp: newUpstream() -- just a struct, no connection yet
    Gateway->>Sessions: create("jira", httpUp)
    Sessions-->>Gateway: mcpSession{id: gatewayID}
    Gateway->>HTTPUp: ServeHTTP(buf, r)
    HTTPUp->>Upstream: POST / (initialize, Mcp-Session-Id stripped)
    Upstream-->>HTTPUp: 200 + Mcp-Session-Id: upstreamID + result
    HTTPUp->>HTTPUp: capture upstreamSessionID; strip header from response
    HTTPUp-->>Gateway: buffered response (no upstream session id)
    Gateway->>Gateway: outbound DLP scan
    Gateway-->>Agent: 200 + Mcp-Session-Id: gatewayID + Set-Cookie + result
```

Note the ordering: the gateway's session ID is minted *before* the real
upstream round trip happens. The upstream's own session ID is only known
once its response comes back -- captured into `httpUp.upstreamSessionID`
for every later request on this session.

### Continuing `tools/call`

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway as Gateway.ServeHTTP
    participant Sessions as sessionManager
    participant HTTPUp as httpUpstreamSession
    participant Upstream as Real upstream MCP server

    Agent->>Gateway: POST /mcp/jira/ (tools/call, Mcp-Session-Id: gatewayID)
    Gateway->>Sessions: get(gatewayID)
    Sessions-->>Gateway: mcpSession found, node matches
    Gateway->>HTTPUp: alive()
    HTTPUp-->>Gateway: true (no persistent process to die)
    Gateway->>Sessions: touch(gatewayID)
    Gateway->>HTTPUp: ServeHTTP(buf, r)
    HTTPUp->>Upstream: POST / (tools/call, Mcp-Session-Id: upstreamID substituted in)
    Upstream-->>HTTPUp: 200 + result
    HTTPUp-->>Gateway: buffered response
    Gateway-->>Agent: 200 + result (no session header re-stamped)
```

### `DELETE`

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway as Gateway.ServeHTTP
    participant Sessions as sessionManager
    participant HTTPUp as httpUpstreamSession
    participant Upstream as Real upstream MCP server

    Agent->>Gateway: DELETE /mcp/jira/ (Mcp-Session-Id: gatewayID)
    Gateway->>Sessions: end(gatewayID)
    Sessions->>Sessions: delete mapping (immediately, before teardown)
    Sessions->>HTTPUp: teardown(ctx)
    HTTPUp->>Upstream: DELETE / (Mcp-Session-Id: upstreamID)
    Upstream-->>HTTPUp: 204
    Gateway-->>Agent: 204

    Agent->>Gateway: POST /mcp/jira/ (Mcp-Session-Id: gatewayID, now dead)
    Gateway->>Sessions: get(gatewayID)
    Sessions-->>Gateway: not found
    Gateway-->>Agent: 404 (never silently re-created)
```

## stdio-backed node (e.g. `echo`)

### `initialize` — spawns a dedicated process for this session

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway as Gateway.ServeHTTP
    participant Health as nodeHealth
    participant Node as stdioadapter.Node
    participant Child as Spawned child process
    participant Watcher as background watcher goroutine
    participant Sessions as sessionManager

    Agent->>Gateway: POST /mcp/echo/ (initialize, no Mcp-Session-Id)
    Gateway->>Gateway: inbound scan, rpcMethod = "initialize"
    Gateway->>Health: decide(now)
    Health-->>Gateway: spawnAllow
    Gateway->>Node: New(ctx, "echo", command, args)
    Node->>Child: spawn (exec.Command)
    Node->>Child: real initialize handshake, over stdin/stdout
    Child-->>Node: InitializeResult (cached on the Node)
    Node->>Watcher: go func() { session.Wait() }
    Node-->>Gateway: Node ready
    Gateway->>Sessions: create("echo", stdioUpstreamSession{node})
    Sessions-->>Gateway: mcpSession{id: gatewayID}
    Gateway->>Node: ServeHTTP(buf, r) [initialize]
    Node-->>Gateway: cached InitializeResult (no new handshake)
    Gateway->>Gateway: outbound DLP scan
    Gateway-->>Agent: 200 + Mcp-Session-Id: gatewayID + Set-Cookie + result
```

The real handshake already happened *inside* `New`, before the session
even exists in `sessionManager` -- the opposite order from HTTP, where the
session is minted before the real upstream call.

### Continuing `tools/call`

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway as Gateway.ServeHTTP
    participant Sessions as sessionManager
    participant Node as stdioadapter.Node
    participant Child as Spawned child process

    Agent->>Gateway: POST /mcp/echo/ (tools/call, Mcp-Session-Id: gatewayID)
    Gateway->>Sessions: get(gatewayID)
    Sessions-->>Gateway: mcpSession found, node matches
    Gateway->>Node: alive()
    Node-->>Gateway: true (dead flag not set)
    Gateway->>Sessions: touch(gatewayID)
    Gateway->>Node: ServeHTTP(buf, r) [tools/call]
    Node->>Child: CallTool -- a real round trip over stdio
    Child-->>Node: CallToolResult
    Node-->>Gateway: buffered response
    Gateway-->>Agent: 200 + result
```

### `DELETE`

```mermaid
sequenceDiagram
    participant Agent
    participant Gateway as Gateway.ServeHTTP
    participant Sessions as sessionManager
    participant Node as stdioadapter.Node
    participant Child as Spawned child process
    participant Watcher as background watcher goroutine

    Agent->>Gateway: DELETE /mcp/echo/ (Mcp-Session-Id: gatewayID)
    Gateway->>Sessions: end(gatewayID)
    Sessions->>Sessions: delete mapping
    Sessions->>Node: teardown() -> Close()
    Node->>Child: close stdin, SIGTERM if still alive after grace period
    Child--xChild: exits
    Child-->>Watcher: Wait() returns
    Watcher->>Node: dead = true (moot, session already gone)
    Gateway-->>Agent: 204
```

### Bonus: unexpected crash mid-session -- self-heal

The one path with no HTTP equivalent at all, since HTTP upstreams have no
persistent process to crash.

```mermaid
sequenceDiagram
    participant Child as Spawned child process
    participant Watcher as background watcher goroutine
    participant Node as stdioadapter.Node
    participant Agent
    participant Gateway as Gateway.ServeHTTP
    participant Sessions as sessionManager

    Child--xChild: unexpected exit (not via our Close())
    Child-->>Watcher: Wait() returns
    Watcher->>Node: dead = true

    Agent->>Gateway: POST /mcp/echo/ (tools/call, Mcp-Session-Id: gatewayID)
    Gateway->>Sessions: get(gatewayID)
    Sessions-->>Gateway: mcpSession found (mapping doesn't know yet)
    Gateway->>Node: alive()
    Node-->>Gateway: false
    Gateway->>Sessions: end(gatewayID) -- self-heal
    Gateway-->>Agent: 200 + JSON-RPC error: "re-initialize"

    Agent->>Gateway: POST /mcp/echo/ (tools/call, same dead session id)
    Gateway->>Sessions: get(gatewayID)
    Sessions-->>Gateway: not found
    Gateway-->>Agent: 404

    Agent->>Gateway: POST /mcp/echo/ (initialize, no session header)
    Gateway-->>Agent: 200 + Mcp-Session-Id: a brand new gatewayID
```

Note the real race this diagram simplifies: there's a small window between
the process actually dying and the watcher goroutine noticing. A request
landing in that window instead fails via `CallTool`'s own error return
(the normal dispatch path, session not yet cleaned up) rather than the
`alive()` check catching it -- the *following* request is what's
guaranteed to see it as gone. `TestGateway_StdioCrashMidSessionFailsCleanlyThenSelfHeals`
polls for this rather than asserting on a single specific request.
