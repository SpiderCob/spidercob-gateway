// Package adminmcp is the gateway's own MCP server (issue #59, design
// doc §9.1): a real, spec-correct MCP server exposing the gateway's
// admin surface as tools, reached through the exact same policy/pin/
// scan/audit pipeline every other node already goes through -- via
// internal/proxy's in-process node mechanism, not a second network
// service. "spidercob-admin" is a reserved node name the composition
// root always registers at startup (internal/proxy.Gateway.
// RegisterInProcessNode); reachability is governed entirely by ordinary
// policy, same as any other node -- default-deny until an operator
// grants a group access through the existing REST admin API.
package adminmcp

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sumeetgp/spidercob-gateway/internal/audit"
	"github.com/sumeetgp/spidercob-gateway/internal/pin"
	"github.com/sumeetgp/spidercob-gateway/internal/proxy"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// ServerName is this node's reserved name -- the composition root
// registers it under this exact name, and it's what an admin grants a
// group access to via an ordinary policy rule.
const ServerName = "spidercob-admin"

// SessionKiller is what this package needs from the gateway's own live
// session state -- kill_session is the only tool that needs it, so this
// stays a single-method interface rather than mirroring
// internal/adminapi.MCPSessionManager's full (list + end) shape; there's
// no list_sessions tool in this issue's scope. Defined here, not
// imported from internal/adminapi, so this package's dependency surface
// stays minimal. The composition root adapts *proxy.Gateway to it.
type SessionKiller interface {
	EndSession(ctx context.Context, id string) error
}

// Config is Server's construction input. All four fields are required --
// New fails loudly rather than building a partially-wired server that
// would panic on first tool call.
type Config struct {
	Store    store.Store
	Pins     *pin.Registry
	Fetch    pin.Fetcher
	Sessions SessionKiller
}

// Server wraps the real *mcp.Server plus its store-backed tool handlers.
type Server struct {
	store    store.Store
	pins     *pin.Registry
	fetch    pin.Fetcher
	sessions SessionKiller
	mcp      *mcp.Server
}

// New builds a Server and registers all seven tools.
func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Pins == nil || cfg.Fetch == nil || cfg.Sessions == nil {
		return nil, fmt.Errorf("adminmcp: Store, Pins, Fetch, and Sessions are all required")
	}
	s := &Server{store: cfg.Store, pins: cfg.Pins, fetch: cfg.Fetch, sessions: cfg.Sessions}
	s.mcp = mcp.NewServer(&mcp.Implementation{
		Name:    ServerName,
		Title:   "Spidercob Gateway Admin",
		Version: "0.1.0",
	}, nil)
	s.registerTools()
	return s, nil
}

// Handler returns a real, spec-correct streamable_http http.Handler for
// this server, the exact shape internal/proxy.Gateway.
// RegisterInProcessNode expects. JSONResponse is forced true: this
// node's own responses are always small (node lists, audit pages, tool
// descriptions), so there's no reason to prefer SSE framing for them --
// deterministic plain JSON keeps this node's own traffic simple, though
// nothing about the in-process transport mechanism itself would break if
// a future in-process node did want to stream.
func (s *Server) Handler() http.Handler {
	return mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return s.mcp },
		&mcp.StreamableHTTPOptions{JSONResponse: true},
	)
}

// actorFromContext extracts the calling principal from ctx -- mirrors
// internal/proxy's own actorFieldsFromClaims exactly (the same
// "agent:"/"user:" Subject-prefix convention), duplicated here rather
// than imported since that helper is unexported and this is the only
// other place that needs it. The claims were stashed by the gateway's
// own bearer-token auth (proxy.Gateway.authenticate) before this tool
// call ever reached this package -- ctx is the same request's context
// throughout, propagated by inProcessUpstreamSession.roundTrip's
// r.Clone(r.Context()).
func actorFromContext(ctx context.Context) (nhiSubject, humanUsername string) {
	claims, ok := proxy.AuthClaimsFromContext(ctx)
	if !ok {
		return "", ""
	}
	switch {
	case strings.HasPrefix(claims.Subject, "agent:"):
		return claims.Subject, ""
	case strings.HasPrefix(claims.Subject, "user:"):
		return "", strings.TrimPrefix(claims.Subject, "user:")
	default:
		return "", ""
	}
}

// auditAction writes one more, tool-specific audit_log row on top of the
// generic per-MCP-request record internal/proxy already produces for
// every tools/call (issue #45) -- matching the granularity
// internal/adminapi.logAdminAction already gives REST-mediated admin
// actions, so "what was granted to whom" is answerable from the audit
// trail, not just "someone called grant_access." A store failure here is
// logged but never fails the tool call that already succeeded -- the
// same "store succeeded, audit is best-effort" posture logAdminAction
// itself already takes.
func (s *Server) auditAction(ctx context.Context, action, resource string) {
	nhi, human := actorFromContext(ctx)
	rec := audit.Record{
		Timestamp:          time.Now(),
		ActorNHISubject:    nhi,
		ActorHumanUsername: human,
		Action:             action,
		Resource:           resource,
	}
	if _, err := s.store.AppendAuditRecord(ctx, rec); err != nil {
		slog.Error("adminmcp: failed to append audit record", "action", action, "resource", resource, "err", err)
	}
}
