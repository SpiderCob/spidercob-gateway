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

func TestLoad_SeedAgentGroupsAccepted(t *testing.T) {
	path := writeConfig(t, `{"nodes":[],"seed_agents":[{"client_id":"a","client_secret":"s","name":"n","groups":["engineering","sre"]}]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SeedAgents[0].Groups) != 2 {
		t.Fatalf("SeedAgents[0].Groups = %v", cfg.SeedAgents[0].Groups)
	}
}

func TestLoad_PolicyRequiresGroupAndNode(t *testing.T) {
	path := writeConfig(t, `{"nodes":[],"policies":[{"rule_type":"allow"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a policies entry missing group/node")
	}
}

func TestLoad_PolicyRequiresValidRuleType(t *testing.T) {
	path := writeConfig(t, `{"nodes":[],"policies":[{"group":"eng","node":"jira","rule_type":"maybe"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for an invalid rule_type")
	}
}

func TestLoad_PolicyRateLimitFieldsMustBePaired(t *testing.T) {
	path := writeConfig(t, `{"nodes":[],"policies":[{"group":"eng","node":"jira","rule_type":"allow","rate_limit_max_calls":10}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error when rate_limit_max_calls is set without rate_limit_window_seconds")
	}
}

func TestLoad_ValidPolicyAccepted(t *testing.T) {
	path := writeConfig(t, `{"nodes":[],"policies":[
		{"group":"eng","node":"jira","rule_type":"allow","methods":["tools/call"],"tools":["search_issues"],
		 "rate_limit_max_calls":10,"rate_limit_window_seconds":60,"block_on_scan_flag":true}
	]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Policies) != 1 {
		t.Fatalf("Policies = %+v", cfg.Policies)
	}
	p := cfg.Policies[0]
	if p.Group != "eng" || p.Node != "jira" || p.RuleType != "allow" || !p.BlockOnScanFlag {
		t.Fatalf("unexpected policy: %+v", p)
	}
	if p.RateLimitMaxCalls == nil || *p.RateLimitMaxCalls != 10 {
		t.Fatalf("RateLimitMaxCalls = %v", p.RateLimitMaxCalls)
	}
}

func TestLoad_TrustedIdPRequiresAllFields(t *testing.T) {
	path := writeConfig(t, `{"nodes":[],"trusted_idps":[{"issuer":"https://idp.example.com"}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a trusted_idps entry missing jwks_url/expected_audience")
	}
}

func TestLoad_ValidTrustedIdPAccepted(t *testing.T) {
	path := writeConfig(t, `{"nodes":[],"trusted_idps":[{"issuer":"https://idp.example.com","jwks_url":"https://idp.example.com/jwks","expected_audience":"https://gw.test"}]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.TrustedIdPs) != 1 || cfg.TrustedIdPs[0].Issuer != "https://idp.example.com" {
		t.Fatalf("TrustedIdPs = %+v", cfg.TrustedIdPs)
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
