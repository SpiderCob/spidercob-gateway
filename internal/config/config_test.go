package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoad_DefaultsTransportToStreamableHTTP(t *testing.T) {
	path := writeConfig(t, `{"nodes":[{"name":"jira","upstream_url":"http://localhost:3001"}]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Nodes[0].Transport; got != TransportStreamableHTTP {
		t.Fatalf("Transport = %q, want %q", got, TransportStreamableHTTP)
	}
}

func TestLoad_StdioNodeRequiresCommand(t *testing.T) {
	path := writeConfig(t, `{"nodes":[{"name":"local","transport":"stdio"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a stdio node with no command, got nil")
	}
}

func TestLoad_StdioNodeWithCommandIsValid(t *testing.T) {
	path := writeConfig(t, `{"nodes":[{"name":"local","transport":"stdio","command":"go","args":["run","./testdata/echoserver"]}]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	n := cfg.Nodes[0]
	if n.Transport != TransportStdio || n.Command != "go" || len(n.Args) != 2 {
		t.Fatalf("unexpected node: %+v", n)
	}
}

func TestLoad_StreamableHTTPNodeRequiresUpstreamURL(t *testing.T) {
	path := writeConfig(t, `{"nodes":[{"name":"jira"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a streamable_http node with no upstream_url, got nil")
	}
}
