package proxy

import "context"

// ErrSessionNotFound is the exported form of errSessionNotFound, for
// callers outside this package (internal/adminapi, issue #35's
// kill-session) that need to distinguish "no such session" from any
// other EndSession failure -- e.g. to map it to an HTTP 404 the same way
// deleteNode already does for its own store.ErrNotFound case.
var ErrSessionNotFound = errSessionNotFound

// ListSessions returns a snapshot of every currently live MCP session
// across every node, for admin visibility (issue #35, kill-session).
func (g *Gateway) ListSessions() []SessionInfo {
	return g.sessions.list()
}

// EndSession ends the session identified by id, tearing down its
// upstream resource through the exact same path a session's own owner
// already gets via DELETE /mcp/{node} (handleDelete) -- this is simply a
// second, admin-authenticated door onto that existing mechanism, not new
// teardown logic (issue #35, kill-session). Returns ErrSessionNotFound if
// id doesn't correspond to a live session.
func (g *Gateway) EndSession(ctx context.Context, id string) error {
	return g.sessions.end(ctx, id)
}
