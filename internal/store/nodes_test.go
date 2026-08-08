package store

import (
	"context"
	"errors"
	"testing"
)

func TestCreateAndGetNode_StreamableHTTP(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	created, err := s.CreateNode(ctx, Node{
		Name: "jira", Transport: "streamable_http",
		UpstreamURL: strPtr("http://localhost:3001"),
		Source:      NodeSourceAdmin,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if created.ID == 0 || created.Name != "jira" || created.Transport != "streamable_http" {
		t.Fatalf("unexpected node: %+v", created)
	}
	if created.UpstreamURL == nil || *created.UpstreamURL != "http://localhost:3001" {
		t.Fatalf("UpstreamURL = %v, want http://localhost:3001", created.UpstreamURL)
	}
	if created.Command != nil {
		t.Fatalf("Command = %v, want nil for a streamable_http node", created.Command)
	}
	if created.Source != NodeSourceAdmin {
		t.Fatalf("Source = %q, want %q", created.Source, NodeSourceAdmin)
	}
	if created.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}

	got, err := s.GetNodeByName(ctx, "jira")
	if err != nil {
		t.Fatalf("GetNodeByName: %v", err)
	}
	if got.ID != created.ID || *got.UpstreamURL != *created.UpstreamURL {
		t.Fatalf("GetNodeByName = %+v, want %+v", got, created)
	}
}

func TestCreateAndGetNode_Stdio_ArgsRoundTrip(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	created, err := s.CreateNode(ctx, Node{
		Name: "local", Transport: "stdio",
		Command: strPtr("go"), Args: []string{"run", "./x"},
		Source: NodeSourceAdmin,
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if created.Command == nil || *created.Command != "go" {
		t.Fatalf("Command = %v, want go", created.Command)
	}
	if len(created.Args) != 2 || created.Args[0] != "run" || created.Args[1] != "./x" {
		t.Fatalf("Args = %v, want [run ./x]", created.Args)
	}

	got, err := s.GetNodeByName(ctx, "local")
	if err != nil {
		t.Fatalf("GetNodeByName: %v", err)
	}
	if len(got.Args) != 2 || got.Args[0] != "run" || got.Args[1] != "./x" {
		t.Fatalf("GetNodeByName Args = %v, want [run ./x]", got.Args)
	}
}

func TestCreateNode_DuplicateNameRejected(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateNode(ctx, Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtr("http://a"), Source: NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := s.CreateNode(ctx, Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtr("http://b"), Source: NodeSourceConfig}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate CreateNode = %v, want ErrConflict", err)
	}
}

func TestGetNodeByName_NotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GetNodeByName(context.Background(), "never-existed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetNodeByName (unknown) = %v, want ErrNotFound", err)
	}
}

func TestListNodes_StableOrderAcrossSources(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateNode(ctx, Node{Name: "zeta", Transport: "streamable_http", UpstreamURL: strPtr("http://z"), Source: NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := s.UpsertConfigNode(ctx, Node{Name: "alpha", Transport: "streamable_http", UpstreamURL: strPtr("http://a")}); err != nil {
		t.Fatalf("UpsertConfigNode: %v", err)
	}

	nodes, err := s.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("ListNodes = %+v, want 2 nodes", nodes)
	}
	if nodes[0].Name != "alpha" || nodes[1].Name != "zeta" {
		t.Fatalf("ListNodes order = [%s %s], want [alpha zeta]", nodes[0].Name, nodes[1].Name)
	}
}

func TestDeleteNode(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateNode(ctx, Node{Name: "throwaway", Transport: "streamable_http", UpstreamURL: strPtr("http://a"), Source: NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if err := s.DeleteNode(ctx, "throwaway"); err != nil {
		t.Fatalf("DeleteNode: %v", err)
	}
	if _, err := s.GetNodeByName(ctx, "throwaway"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetNodeByName after delete = %v, want ErrNotFound", err)
	}
	if err := s.DeleteNode(ctx, "never-existed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteNode (unknown) = %v, want ErrNotFound", err)
	}
}

func TestUpsertConfigNode_CreatesWhenAbsent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	got, err := s.UpsertConfigNode(ctx, Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtr("http://a")})
	if err != nil {
		t.Fatalf("UpsertConfigNode: %v", err)
	}
	if got.Source != NodeSourceConfig {
		t.Fatalf("Source = %q, want %q (UpsertConfigNode always sets it, caller doesn't need to)", got.Source, NodeSourceConfig)
	}
}

func TestUpsertConfigNode_UpdatesInPlaceWhenSourceIsConfig(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.UpsertConfigNode(ctx, Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtr("http://old")}); err != nil {
		t.Fatalf("UpsertConfigNode (first): %v", err)
	}
	updated, err := s.UpsertConfigNode(ctx, Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtr("http://new")})
	if err != nil {
		t.Fatalf("UpsertConfigNode (second): %v", err)
	}
	if updated.UpstreamURL == nil || *updated.UpstreamURL != "http://new" {
		t.Fatalf("UpstreamURL after re-upsert = %v, want http://new (config must stay authoritative)", updated.UpstreamURL)
	}

	nodes, err := s.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("ListNodes = %+v, want exactly 1 node (update, not a second row)", nodes)
	}
}

func TestUpsertConfigNode_ConflictWhenExistingIsAdminSourced(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if _, err := s.CreateNode(ctx, Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtr("http://admin-owned"), Source: NodeSourceAdmin}); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	if _, err := s.UpsertConfigNode(ctx, Node{Name: "jira", Transport: "streamable_http", UpstreamURL: strPtr("http://config-says")}); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpsertConfigNode over an admin-sourced node = %v, want ErrConflict", err)
	}
	// The admin-owned row must be untouched.
	got, err := s.GetNodeByName(ctx, "jira")
	if err != nil {
		t.Fatalf("GetNodeByName: %v", err)
	}
	if got.Source != NodeSourceAdmin || *got.UpstreamURL != "http://admin-owned" {
		t.Fatalf("admin-owned node was modified: %+v", got)
	}
}
