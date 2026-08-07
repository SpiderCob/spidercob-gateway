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

func TestLoad_IdentityDefaultsApplied(t *testing.T) {
	path := writeConfig(t, `{"listen":":9090","nodes":[]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Issuer != "http://localhost:9090" {
		t.Fatalf("Issuer = %q, want http://localhost:9090", cfg.Issuer)
	}
	if cfg.StoreDBPath != DefaultStoreDBPath {
		t.Fatalf("StoreDBPath = %q, want %q", cfg.StoreDBPath, DefaultStoreDBPath)
	}
	if cfg.NHITokenTTLSeconds != DefaultNHITokenTTLSeconds {
		t.Fatalf("NHITokenTTLSeconds = %d, want %d", cfg.NHITokenTTLSeconds, DefaultNHITokenTTLSeconds)
	}
	if cfg.HumanTokenTTLSeconds != DefaultHumanTokenTTLSeconds {
		t.Fatalf("HumanTokenTTLSeconds = %d, want %d", cfg.HumanTokenTTLSeconds, DefaultHumanTokenTTLSeconds)
	}
	if cfg.LocalSessionTTLSeconds != DefaultLocalSessionTTLSeconds {
		t.Fatalf("LocalSessionTTLSeconds = %d, want %d", cfg.LocalSessionTTLSeconds, DefaultLocalSessionTTLSeconds)
	}
}

func TestLoad_SeedAgentRequiresAllFields(t *testing.T) {
	path := writeConfig(t, `{"nodes":[],"seed_agents":[{"client_id":"a"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a seed_agents entry missing client_secret/name")
	}
}

func TestLoad_ValidSeedAgentAccepted(t *testing.T) {
	path := writeConfig(t, `{"nodes":[],"seed_agents":[{"client_id":"a","client_secret":"s","name":"n"}]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SeedAgents) != 1 || cfg.SeedAgents[0].ClientID != "a" {
		t.Fatalf("SeedAgents = %+v", cfg.SeedAgents)
	}
}

func TestLoad_ExplicitIssuerNotOverridden(t *testing.T) {
	path := writeConfig(t, `{"issuer":"https://gateway.example.com","nodes":[]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Issuer != "https://gateway.example.com" {
		t.Fatalf("Issuer = %q, want the explicit value preserved", cfg.Issuer)
	}
}
