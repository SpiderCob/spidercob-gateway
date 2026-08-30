package proxy

import (
	"fmt"
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
	if _, exists := g.nodes[nc.name]; exists {
		return fmt.Errorf("proxy: node %s is already registered", nc.name)
	}
	g.nodes[nc.name] = nc
	return nil
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
func (g *Gateway) RemoveNode(name string) error {
	g.nodesMu.Lock()
	delete(g.nodes, name)
	g.nodesMu.Unlock()

	g.nodeHealthMu.Lock()
	delete(g.nodeHealth, name)
	g.nodeHealthMu.Unlock()
	return nil
}
