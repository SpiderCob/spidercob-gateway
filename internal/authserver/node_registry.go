package authserver

// AddNode registers a new node's name on an already-running AuthServer
// (issue #57): the minting/discovery half of hot-reload. Once this
// returns, /token can mint a real, node-scoped access token for name,
// and ServeProtectedResourceMetadata serves real RFC 9728 metadata for
// it -- neither worked before this call, both work immediately after.
// Idempotent: adding an already-registered name is a no-op, not an
// error, matching store.UpsertConfigNode's own create-or-update posture
// rather than proxy.Gateway.AddNode's stricter reject-a-duplicate one --
// there's no meaningfully different "second" node state here to reject,
// just a name being present or absent.
func (a *AuthServer) AddNode(name string) {
	a.nodesMu.Lock()
	a.nodes[name] = struct{}{}
	a.nodesMu.Unlock()
}

// RemoveNode unregisters a node's name (issue #57). After this returns,
// /token refuses to mint a token for name (client_credentials and
// jwt-bearer both resolve a "resource" through resolveNode, which this
// empties) and ServeProtectedResourceMetadata 404s for it -- but
// ValidateAccessToken does NOT depend on a.nodes at all (it only compares
// a token's aud claim against resourceURI(node), a pure string
// construction), so an already-minted, still-unexpired token for a
// removed node keeps validating. That's deliberate, not an oversight:
// it's what lets an already-established session on that node keep
// working after removal (proxy.Gateway.RemoveNode's own doc comment,
// story 5) -- this method only closes the *minting* and *discovery*
// doors, not a live session's existing credential. Idempotent, same as
// AddNode.
func (a *AuthServer) RemoveNode(name string) {
	a.nodesMu.Lock()
	delete(a.nodes, name)
	a.nodesMu.Unlock()
}
