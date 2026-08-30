package adminapi

import "github.com/sumeetgp/spidercob-gateway/internal/config"

// NodeRegistrar is what adminapi needs to apply a node registration or
// removal live, on an already-running gateway (issue #57, hot-reload) --
// mirrors MCPSessionManager's existing shape and rationale exactly: this
// package's dependency surface stays minimal (it doesn't need to import
// internal/proxy/internal/authserver/internal/pin directly), main.go is
// the only place that needs to know the concrete components satisfy it,
// fanning one call out to all three.
//
// The store write (createNode/deleteNode's existing store.CreateNode/
// store.DeleteNode calls) is always the first, authoritative step; a
// NodeRegistrar call only ever happens after that succeeds, and its own
// failure is logged but never turns an already-succeeded store write
// into a failed admin request -- see createNode/deleteNode's doc
// comments.
type NodeRegistrar interface {
	AddNode(n config.Node) error
	RemoveNode(name string) error
}
