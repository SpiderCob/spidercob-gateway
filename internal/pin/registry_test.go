package pin

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

func newTestRegistry(t *testing.T) (*Registry, store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return NewRegistry(s), s
}

func TestRegistry_ObserveEstablishesTOFUPin(t *testing.T) {
	reg, s := newTestRegistry(t)
	ctx := context.Background()

	def := ToolDef{Name: "search_docs", Description: "search", InputSchema: []byte(`{"type":"object"}`)}
	if err := reg.Observe(ctx, "jira", []ToolDef{def}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	pin, err := s.GetToolPin(ctx, "jira", "search_docs")
	if err != nil {
		t.Fatalf("GetToolPin after first observation: %v", err)
	}
	wantHash, err := Hash(def)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if pin.Hash != wantHash {
		t.Fatalf("pinned hash = %q, want %q", pin.Hash, wantHash)
	}
	if pin.QuarantinedAt != nil {
		t.Fatalf("newly established pin is quarantined, want not quarantined")
	}
}

func TestRegistry_ObserveNoDriftLeavesUnquarantined(t *testing.T) {
	reg, s := newTestRegistry(t)
	ctx := context.Background()

	def := ToolDef{Name: "search_docs", Description: "search", InputSchema: []byte(`{"type":"object"}`)}
	if err := reg.Observe(ctx, "jira", []ToolDef{def}); err != nil {
		t.Fatalf("first Observe: %v", err)
	}
	// Re-observe the identical definition, as a subsequent background
	// refresh would.
	if err := reg.Observe(ctx, "jira", []ToolDef{def}); err != nil {
		t.Fatalf("second Observe: %v", err)
	}

	pin, err := s.GetToolPin(ctx, "jira", "search_docs")
	if err != nil {
		t.Fatalf("GetToolPin: %v", err)
	}
	if pin.QuarantinedAt != nil {
		t.Fatalf("pin quarantined after re-observing an unchanged definition")
	}
}

func TestRegistry_ObserveDriftQuarantines(t *testing.T) {
	reg, s := newTestRegistry(t)
	ctx := context.Background()

	original := ToolDef{Name: "search_docs", Description: "search", InputSchema: []byte(`{"type":"object"}`)}
	if err := reg.Observe(ctx, "jira", []ToolDef{original}); err != nil {
		t.Fatalf("first Observe: %v", err)
	}

	drifted := original
	drifted.Description = "search and also delete everything"
	if err := reg.Observe(ctx, "jira", []ToolDef{drifted}); err != nil {
		t.Fatalf("second Observe: %v", err)
	}

	pin, err := s.GetToolPin(ctx, "jira", "search_docs")
	if err != nil {
		t.Fatalf("GetToolPin: %v", err)
	}
	if pin.QuarantinedAt == nil {
		t.Fatalf("pin not quarantined after drift")
	}
	if pin.DriftDetail == nil || *pin.DriftDetail == "" {
		t.Fatalf("DriftDetail not recorded on quarantine")
	}
	// The stored hash stays the original baseline -- quarantine records
	// that drift happened, it doesn't silently re-pin the new (untrusted)
	// definition as the new baseline.
	origHash, _ := Hash(original)
	if pin.Hash != origHash {
		t.Fatalf("pin.Hash = %q, want unchanged original baseline %q", pin.Hash, origHash)
	}
}

func TestRegistry_ObserveDoesNotReQuarantineOrUndo(t *testing.T) {
	reg, s := newTestRegistry(t)
	ctx := context.Background()

	original := ToolDef{Name: "search_docs", Description: "search", InputSchema: []byte(`{"type":"object"}`)}
	if err := reg.Observe(ctx, "jira", []ToolDef{original}); err != nil {
		t.Fatalf("Observe (establish): %v", err)
	}
	drifted := original
	drifted.Description = "search and also delete everything"
	if err := reg.Observe(ctx, "jira", []ToolDef{drifted}); err != nil {
		t.Fatalf("Observe (drift): %v", err)
	}
	// A third refresh observing the same drifted definition again --
	// there is no re-approval mechanism, so this must not error and must
	// leave the tool quarantined.
	if err := reg.Observe(ctx, "jira", []ToolDef{drifted}); err != nil {
		t.Fatalf("Observe (repeat drift): %v", err)
	}

	pin, err := s.GetToolPin(ctx, "jira", "search_docs")
	if err != nil {
		t.Fatalf("GetToolPin: %v", err)
	}
	if pin.QuarantinedAt == nil {
		t.Fatalf("pin unquarantined after repeat observation, want still quarantined")
	}
}

func TestRegistry_NonQuarantinedFiltersOutQuarantinedTools(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	safe := ToolDef{Name: "safe_tool", Description: "d", InputSchema: []byte(`{}`)}
	risky := ToolDef{Name: "risky_tool", Description: "d", InputSchema: []byte(`{}`)}
	if err := reg.Observe(ctx, "jira", []ToolDef{safe, risky}); err != nil {
		t.Fatalf("Observe (establish): %v", err)
	}
	driftedRisky := risky
	driftedRisky.Description = "changed"
	if err := reg.Observe(ctx, "jira", []ToolDef{safe, driftedRisky}); err != nil {
		t.Fatalf("Observe (drift): %v", err)
	}

	got := reg.NonQuarantined(ctx, "jira", []string{"safe_tool", "risky_tool"})
	if len(got) != 1 || got[0] != "safe_tool" {
		t.Fatalf("NonQuarantined = %v, want [safe_tool]", got)
	}
}

func TestRegistry_NonQuarantinedIncludesNeverObservedTools(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	// A tool with no pin at all (never observed by any refresh yet)
	// passes through unfiltered -- absence of a pin is not evidence of
	// drift, and pinning happens on the background refresh cadence, not
	// synchronously with every tools/list call.
	got := reg.NonQuarantined(ctx, "jira", []string{"brand_new_tool"})
	if len(got) != 1 || got[0] != "brand_new_tool" {
		t.Fatalf("NonQuarantined = %v, want [brand_new_tool]", got)
	}
}

func TestRegistry_IsQuarantined(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	if reg.IsQuarantined(ctx, "jira", "never_seen") {
		t.Fatalf("IsQuarantined = true for a tool with no pin, want false")
	}

	def := ToolDef{Name: "search_docs", Description: "search", InputSchema: []byte(`{"type":"object"}`)}
	if err := reg.Observe(ctx, "jira", []ToolDef{def}); err != nil {
		t.Fatalf("Observe (establish): %v", err)
	}
	if reg.IsQuarantined(ctx, "jira", "search_docs") {
		t.Fatalf("IsQuarantined = true for a freshly pinned, non-drifted tool, want false")
	}

	drifted := def
	drifted.Description = "search and also delete everything"
	if err := reg.Observe(ctx, "jira", []ToolDef{drifted}); err != nil {
		t.Fatalf("Observe (drift): %v", err)
	}
	if !reg.IsQuarantined(ctx, "jira", "search_docs") {
		t.Fatalf("IsQuarantined = false for a drifted tool, want true")
	}
}

func TestRegistry_PinnedSchema(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	schema, exists, err := reg.PinnedSchema(ctx, "jira", "never_seen")
	if err != nil {
		t.Fatalf("PinnedSchema (never observed): %v", err)
	}
	if exists {
		t.Fatalf("PinnedSchema exists = true for a tool with no pin, want false")
	}
	if schema != nil {
		t.Fatalf("PinnedSchema schema = %v, want nil for a tool with no pin", schema)
	}

	def := ToolDef{
		Name:        "search_docs",
		Description: "search",
		InputSchema: []byte(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`),
	}
	if err := reg.Observe(ctx, "jira", []ToolDef{def}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	schema, exists, err = reg.PinnedSchema(ctx, "jira", "search_docs")
	if err != nil {
		t.Fatalf("PinnedSchema: %v", err)
	}
	if !exists {
		t.Fatalf("PinnedSchema exists = false for a pinned tool, want true")
	}
	if string(schema) != string(def.InputSchema) {
		t.Fatalf("PinnedSchema = %s, want %s", schema, def.InputSchema)
	}
}

func TestRegistry_PinnedSchema_NoInputSchemaPinned(t *testing.T) {
	// A tool that legitimately takes no structured arguments (no
	// InputSchema at observation time) must resolve as "a pin exists,
	// but there's no schema" -- not confused with "no pin exists at all."
	reg, _ := newTestRegistry(t)
	ctx := context.Background()

	def := ToolDef{Name: "no_args_tool", Description: "takes no arguments"}
	if err := reg.Observe(ctx, "jira", []ToolDef{def}); err != nil {
		t.Fatalf("Observe: %v", err)
	}

	schema, exists, err := reg.PinnedSchema(ctx, "jira", "no_args_tool")
	if err != nil {
		t.Fatalf("PinnedSchema: %v", err)
	}
	if !exists {
		t.Fatalf("PinnedSchema exists = false for a pinned tool, want true")
	}
	if schema != nil {
		t.Fatalf("PinnedSchema schema = %s, want nil (no inputSchema was ever pinned)", schema)
	}
}
