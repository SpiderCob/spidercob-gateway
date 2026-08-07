package pin

import "testing"

func mustHash(t *testing.T, def ToolDef) string {
	t.Helper()
	h, err := Hash(def)
	if err != nil {
		t.Fatalf("Hash(%+v): %v", def, err)
	}
	return h
}

func TestHash_IdenticalDefinitionNoDrift(t *testing.T) {
	def := ToolDef{
		Name:        "search_docs",
		Description: "Search internal documentation",
		InputSchema: []byte(`{"type":"object","properties":{"query":{"type":"string"}}}`),
	}
	h1 := mustHash(t, def)
	h2 := mustHash(t, def)
	if h1 != h2 {
		t.Fatalf("identical ToolDef hashed differently: %q vs %q", h1, h2)
	}
	if Drifted(h1, h2) {
		t.Fatalf("Drifted(%q, %q) = true, want false for identical definitions", h1, h2)
	}
}

func TestHash_DescriptionChangeDrifts(t *testing.T) {
	base := ToolDef{
		Name:        "search_docs",
		Description: "Search internal documentation",
		InputSchema: []byte(`{"type":"object"}`),
	}
	changed := base
	changed.Description = "Search internal documentation and code"

	h1 := mustHash(t, base)
	h2 := mustHash(t, changed)
	if !Drifted(h1, h2) {
		t.Fatalf("Drifted(%q, %q) = false, want true after description change", h1, h2)
	}
}

func TestHash_InputSchemaChangeDrifts(t *testing.T) {
	base := ToolDef{
		Name:        "search_docs",
		Description: "Search internal documentation",
		InputSchema: []byte(`{"type":"object","properties":{"query":{"type":"string"}}}`),
	}
	changed := base
	changed.InputSchema = []byte(`{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer"}}}`)

	h1 := mustHash(t, base)
	h2 := mustHash(t, changed)
	if !Drifted(h1, h2) {
		t.Fatalf("Drifted(%q, %q) = false, want true after inputSchema change", h1, h2)
	}
}

func TestHash_NameChangeDrifts(t *testing.T) {
	base := ToolDef{
		Name:        "search_docs",
		Description: "Search internal documentation",
		InputSchema: []byte(`{"type":"object"}`),
	}
	changed := base
	changed.Name = "search_documents"

	h1 := mustHash(t, base)
	h2 := mustHash(t, changed)
	if !Drifted(h1, h2) {
		t.Fatalf("Drifted(%q, %q) = false, want true after name change", h1, h2)
	}
}

func TestHash_ReorderedJSONKeysNoDrift(t *testing.T) {
	base := ToolDef{
		Name:        "search_docs",
		Description: "Search internal documentation",
		InputSchema: []byte(`{"type":"object","properties":{"query":{"type":"string"},"limit":{"type":"integer"}}}`),
	}
	// Same schema, semantically, but with object keys reordered and
	// whitespace differing -- a schema-serialization detail that must
	// never be mistaken for the node changing the tool's behavior.
	reordered := base
	reordered.InputSchema = []byte(`{
		"properties": {
			"limit": {"type": "integer"},
			"query": {"type": "string"}
		},
		"type": "object"
	}`)

	h1 := mustHash(t, base)
	h2 := mustHash(t, reordered)
	if h1 != h2 {
		t.Fatalf("reordered/re-whitespaced inputSchema hashed differently: %q vs %q", h1, h2)
	}
	if Drifted(h1, h2) {
		t.Fatalf("Drifted(%q, %q) = true, want false for reordered-but-identical inputSchema", h1, h2)
	}
}

func TestHash_EmptyInputSchemaIsStable(t *testing.T) {
	def := ToolDef{Name: "no_args_tool", Description: "Takes no arguments"}
	h1 := mustHash(t, def)
	h2 := mustHash(t, def)
	if h1 != h2 {
		t.Fatalf("nil InputSchema hashed differently across calls: %q vs %q", h1, h2)
	}
}

func TestHash_InvalidInputSchemaErrors(t *testing.T) {
	def := ToolDef{
		Name:        "broken",
		Description: "has malformed schema JSON",
		InputSchema: []byte(`{not valid json`),
	}
	if _, err := Hash(def); err == nil {
		t.Fatal("Hash() with malformed InputSchema JSON: got nil error, want non-nil")
	}
}
