package proxy

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
)

// buildNodeConfig turns a validated config.Node into the *nodeConfig
// shape both New's construction loop and AddNode need -- pulled out so
// the two never drift on what "a node" actually means internally.
func buildNodeConfig(n config.Node) (*nodeConfig, error) {
	nc := &nodeConfig{name: n.Name, transport: n.Transport, command: n.Command, args: n.Args}
	if n.Transport == config.TransportStreamableHTTP {
		u, err := url.Parse(n.UpstreamURL)
		if err != nil {
			return nil, fmt.Errorf("node %s: %w", n.Name, err)
		}
		nc.upstreamURL = u
	}
	return nc, nil
}

// AddNode registers a new node on an already-running Gateway (issue
// #57): the routing-table half of hot-reload. Validates via the same
// config.ValidateNode the admin API already runs before this is ever
// called -- defense in depth, not a new validation path -- so a
// rejected AddNode never partially registers anything. Returns an error
// if a node with this name is already registered; the store's own
// uniqueness constraint should make that unreachable in practice via the
// admin API, but this method doesn't trust that.
func (g *Gateway) AddNode(n config.Node) error {
	validated, err := config.ValidateNode(n)
	if err != nil {
		return err
	}
	nc, err := buildNodeConfig(validated)
	if err != nil {
		return err
	}

	g.nodesMu.Lock()
	defer g.nodesMu.Unlock()
	if existing, exists := g.nodes[nc.name]; exists {
		if existing.inProcessHandler != nil {
			return fmt.Errorf("proxy: node %s is reserved and cannot be registered", nc.name)
		}
		return fmt.Errorf("proxy: node %s is already registered", nc.name)
	}
	g.nodes[nc.name] = nc
	return nil
}

// RegisterInProcessNode registers a node backed by an in-process
// http.Handler instead of a real upstream (issue #59: spidercob-admin).
// Deliberately not reachable from the admin API or any config.Node-
// driven path -- config.Node has no field that could carry an
// http.Handler, and this method's only caller is the composition root
// (cmd/spidercob/main.go), at startup, exactly once. That's what makes a
// node registered this way reserved rather than admin-creatable: there
// is no request path that can reach this method at all. Unlike AddNode,
// this always overwrites an existing entry of the same name rather than
// rejecting it -- there's exactly one caller, at startup, registering
// exactly one well-known name; rejecting a "duplicate" here would only
// ever indicate a composition-root bug, not a real conflict worth
// surfacing as an error to handle.
func (g *Gateway) RegisterInProcessNode(name string, handler http.Handler) {
	g.nodesMu.Lock()
	defer g.nodesMu.Unlock()
	g.nodes[name] = &nodeConfig{name: name, inProcessHandler: handler}
}

// RemoveNode unregisters a node on an already-running Gateway (issue
// #57). Deliberately does not touch any already-established session on
// this node (story 5 of the spec) -- a live session holds its own
// sessionUpstream reference independent of g.nodes, so removing the
// routing-table entry only prevents a *new* initialize from reaching
// this node; ServeHTTP's existing unknown-node 404 path now also covers
// "was known, just removed." Also clears any nodeHealth bookkeeping for
// this node, so a later re-add of the same name starts with a clean
// crash/backoff history rather than stale state from before the
// removal. A name that isn't currently registered is not an error --
// removal is idempotent, matching store.DeleteNode's own posture.
//
// Refuses to remove a node registered via RegisterInProcessNode (issue
// #59 review finding, security-critical): without this check, a store
// row named the same as a reserved in-process node -- reachable today
// only if internal/adminapi's own reserved-name check somewhere above
// this ever had a gap -- would let an ordinary DELETE /admin/nodes call
// tear down spidercob-admin's live routing entry, a real DoS of the
// gateway's own admin MCP surface until a restart. This is deliberate
// defense in depth: the REST-layer check is the primary guard, but this
// invariant is enforced here too, at the one place that actually deletes
// from g.nodes, so it holds regardless of what any future caller (or a
// bug in a future caller) does.
func (g *Gateway) RemoveNode(name string) error {
	g.nodesMu.Lock()
	if existing, exists := g.nodes[name]; exists && existing.inProcessHandler != nil {
		g.nodesMu.Unlock()
		return fmt.Errorf("proxy: node %s is reserved and cannot be removed", name)
	}
	delete(g.nodes, name)
	g.nodesMu.Unlock()

	g.nodeHealthMu.Lock()
	delete(g.nodeHealth, name)
	g.nodeHealthMu.Unlock()
	return nil
}
