// Package pin implements tool pinning (rug-pull defense, issue #9):
// trust-on-first-observation (TOFU) of a node's tools/list, periodic
// background drift detection against that baseline, and per-tool
// quarantine on drift. See Registry's doc comment for why TOFU -- rather
// than an admin-approval flow that doesn't exist yet -- is the trust
// mechanism, and why persistence across restarts is not optional.
package pin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ToolDef is the subset of an observed tool definition pinning cares
// about: name, description, and inputSchema together -- exactly the
// three fields design doc §5 names as the rug-pull surface. Deliberately
// not the MCP SDK's richer Tool type: this package stays decoupled from
// the wire-protocol representation, the same posture internal/policy
// already takes working with plain tool names rather than SDK types.
// internal/proxy is responsible for extracting these from a real
// tools/list response.
type ToolDef struct {
	Name        string
	Description string
	InputSchema json.RawMessage
}

// Hash returns a stable digest of t's name+description+inputSchema.
// InputSchema is canonicalized (re-marshaled through a generic value,
// which sorts object keys deterministically) before hashing, so
// semantically-identical-but-differently-ordered JSON never
// false-positives as drift (story 2's canonicalization requirement).
func Hash(t ToolDef) (string, error) {
	canonicalSchema, err := canonicalizeJSON(t.InputSchema)
	if err != nil {
		return "", err
	}
	sum := sha256.New()
	sum.Write([]byte(t.Name))
	sum.Write([]byte{0}) // separator: "ab"+"c" must not hash the same as "a"+"bc"
	sum.Write([]byte(t.Description))
	sum.Write([]byte{0})
	sum.Write(canonicalSchema)
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// canonicalizeJSON re-marshals raw through a generic Go value.
// encoding/json's Marshal sorts map keys, so this gives a stable byte
// representation regardless of the input's original key order or
// whitespace.
func canonicalizeJSON(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("null"), nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// Drifted reports whether newHash differs from a pin's stored hash. This
// is deliberately just an inequality check, named and isolated so the
// "did this tool's definition actually change" decision is one small,
// independently testable thing (story 13), not buried inside I/O.
func Drifted(pinnedHash, newHash string) bool {
	return pinnedHash != newHash
}
