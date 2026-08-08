package pin

import (
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
)

// ValidateArguments validates arguments (a tools/call request's raw
// params.arguments JSON) against schema (a tool's pinned inputSchema),
// using google/jsonschema-go rather than hand-rolled JSON Schema parsing
// -- the same "vetted library for security-sensitive parsing" posture
// already established for golang-jwt/keyfunc (MASTER_PLAN.md §6,
// 2026-08-07). Already an indirect dependency, pulled in transitively by
// the MCP go-sdk itself, which uses it to define tool inputSchemas.
//
// An empty or nil schema means no inputSchema was ever pinned for this
// tool -- nothing to validate against, so anything passes (story 23: a
// tool that legitimately takes no structured arguments must never be
// blocked by this check). Pure aside from the schema library's own
// parsing/compilation -- no I/O, no store access -- directly testable
// against known schema/argument pairs (story 13's testing posture,
// applied here to schema enforcement).
func ValidateArguments(schema, arguments json.RawMessage) error {
	if len(schema) == 0 {
		return nil
	}

	var s jsonschema.Schema
	if err := json.Unmarshal(schema, &s); err != nil {
		return fmt.Errorf("pin: parse pinned schema: %w", err)
	}
	resolved, err := s.Resolve(nil)
	if err != nil {
		return fmt.Errorf("pin: resolve pinned schema: %w", err)
	}

	var instance any
	if len(arguments) == 0 {
		instance = map[string]any{}
	} else if err := json.Unmarshal(arguments, &instance); err != nil {
		return fmt.Errorf("pin: parse arguments: %w", err)
	}

	if err := resolved.Validate(instance); err != nil {
		return fmt.Errorf("arguments do not match pinned schema: %w", err)
	}
	return nil
}
