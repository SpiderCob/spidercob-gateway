// Package audit is the gateway's hash-chained audit trail (issue #23),
// wired to two consumers: internal/adminapi's admin-mutation actions
// (logAdminAction), and, since issue #45, internal/proxy's per-MCP-request
// traffic (Gateway.enqueueAudit, via the AuditRecorder seam) -- exactly
// the docs/design.md §6 fuller vision issue #23 originally deferred as
// separate, hot-path-sensitive work. Both consumers share this same
// Record shape (see its own doc comment) and one continuous
// store-persisted chain; audit.Verify has no notion of "which consumer
// wrote this row."
//
// This package is pure -- no I/O, no store dependency -- mirroring
// internal/pin's Hash/Drifted split: Hash/Verify are the directly
// testable decision logic, internal/store owns actually persisting
// records and computing each one's place in the chain.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Record is one audit-worthy event. Field names are deliberately
// generic (not e.g. NodeID/Method/Tool-specific) so both consumers can
// share this one shape rather than needing separate types or a breaking
// schema change (issue #23 spec, story 12) -- issue #45's per-MCP-request
// records reuse it exactly this way: Action encodes "<rpc_method>:
// <outcome>" (e.g. "tools/call:denied_policy"), Resource encodes
// "<node>[/<tool>]".
type Record struct {
	Timestamp time.Time
	// ActorNHISubject may be empty -- a UI-session-originated admin
	// action has no NHI subject, mirroring internal/adminapi's
	// existing adminIdentity.nhiSubject field, which is already
	// sometimes empty for that exact reason (issue #17). A
	// per-MCP-request record (issue #45) populates exactly one of
	// ActorNHISubject/ActorHumanUsername, never both, and leaves
	// ActorHumanRole empty -- AuthClaims carries no role concept.
	ActorNHISubject    string
	ActorHumanUsername string
	ActorHumanRole     string
	Action             string
	Resource           string
}

// StoredRecord is a Record together with the hash-chain values it was
// actually persisted with -- what Verify checks. internal/store
// constructs these from real audit_log rows; tests construct them
// directly via chainOf-style helpers to exercise Verify without a
// database.
type StoredRecord struct {
	Record
	PrevHash string
	Hash     string
}

// GenesisPrevHash is the fixed, documented sentinel prevHash for the
// first record in a chain -- an explicit, testable value ("chain has
// zero prior records") rather than an edge case that happens to fall
// out of using an empty string. A real const, not a package var
// (issue found by Copilot's review on PR #24): this defines the audit
// chain's genesis sentinel, and nothing outside this package should be
// able to mutate it, accidentally or otherwise -- a var would have let
// that happen, silently changing what every chain in the process
// considers valid.
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Hash returns a stable digest of prevHash chained with rec's fields
// -- mirrors pin.Hash's exact pattern (null-byte-separated fields, so
// "ab"+"c" can never hash the same as "a"+"bc"). The error return
// exists for symmetry with pin.Hash and to leave room for a future
// field type that could fail to canonicalize; nothing in the current
// field set can actually produce one.
func Hash(prevHash string, rec Record) (string, error) {
	sum := sha256.New()
	sum.Write([]byte(prevHash))
	sum.Write([]byte{0})
	sum.Write([]byte(rec.Timestamp.UTC().Format(time.RFC3339Nano)))
	sum.Write([]byte{0})
	sum.Write([]byte(rec.ActorNHISubject))
	sum.Write([]byte{0})
	sum.Write([]byte(rec.ActorHumanUsername))
	sum.Write([]byte{0})
	sum.Write([]byte(rec.ActorHumanRole))
	sum.Write([]byte{0})
	sum.Write([]byte(rec.Action))
	sum.Write([]byte{0})
	sum.Write([]byte(rec.Resource))
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// Verify walks records in order, recomputing each one's hash from its
// own fields plus the previous record's hash, and reports a
// descriptive error identifying exactly which record (by its position
// in records) doesn't match the first time one doesn't -- not just
// "chain broken somewhere". This is the real tamper-evidence check:
// an altered field, a swapped-in wrong prevHash, or two records
// reordered all break the very next recomputation, because each
// record's own stored Hash was only ever valid for its original
// fields plus its original PrevHash.
func Verify(records []StoredRecord) error {
	prev := GenesisPrevHash
	for i, r := range records {
		if r.PrevHash != prev {
			return fmt.Errorf("audit: record %d: prev_hash %q does not match the actual preceding hash %q", i, r.PrevHash, prev)
		}
		want, err := Hash(r.PrevHash, r.Record)
		if err != nil {
			return fmt.Errorf("audit: record %d: %w", i, err)
		}
		if want != r.Hash {
			return fmt.Errorf("audit: record %d: stored hash %q does not match recomputed hash %q -- record was altered after being written", i, r.Hash, want)
		}
		prev = r.Hash
	}
	return nil
}
