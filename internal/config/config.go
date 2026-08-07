// Package config loads the gateway configuration.
// JSON for now to stay stdlib-only; YAML lands with the admin UI (design doc §9).
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Transport identifies how the gateway reaches a node's upstream.
const (
	TransportStreamableHTTP = "streamable_http"
	TransportStdio          = "stdio"
)

// Node is one upstream MCP server registered behind the gateway.
type Node struct {
	Name        string   `json:"name"`
	Transport   string   `json:"transport,omitempty"` // TransportStreamableHTTP (default) or TransportStdio
	UpstreamURL string   `json:"upstream_url,omitempty"`
	Command     string   `json:"command,omitempty"`
	Args        []string `json:"args,omitempty"`
}

// DefaultIdleSessionTimeoutSeconds is used when idle_session_timeout_seconds
// is unset. Sessions with no activity for this long are torn down the same
// way as an explicit DELETE (design doc decisions log, 2026-08-04).
const DefaultIdleSessionTimeoutSeconds = 1800 // 30 minutes

// DefaultNHITokenTTLSeconds and DefaultHumanTokenTTLSeconds mirror
// authserver.DefaultNHITokenTTL/DefaultHumanTokenTTL (issue #3, admin-
// configurable per MASTER_PLAN.md §6, 2026-08-04) -- kept as plain int
// constants here so this package doesn't need to import internal/authserver
// just to know its own defaults.
const (
	DefaultNHITokenTTLSeconds   = 120
	DefaultHumanTokenTTLSeconds = 600
	// DefaultLocalSessionTTLSeconds bounds how long a human can silently
	// re-mint node-scoped access tokens (authserver.DefaultLocalSessionTTL)
	// before needing to log in again.
	DefaultLocalSessionTTLSeconds = 8 * 60 * 60
	// DefaultStoreDBPath is where the identity SQLite database lives when
	// store_db_path isn't set.
	DefaultStoreDBPath = "spidercob.db"
)

type Config struct {
	Listen                    string `json:"listen"`
	IdleSessionTimeoutSeconds int    `json:"idle_session_timeout_seconds,omitempty"`
	Nodes                     []Node `json:"nodes"`

	// Issuer is this gateway's own authserver identity -- stamped as iss on
	// every minted token, and used to build both aud (per-node resource
	// URIs, RFC 8707) and the JWKS/RFC 9728 metadata URLs advertised to
	// clients. Must be reachable at the URL clients will actually use, so
	// there's no safe default beyond a same-host guess -- set this
	// explicitly for any real deployment (e.g. "https://gateway.company.com").
	Issuer string `json:"issuer,omitempty"`
	// StoreDBPath is the SQLite file backing internal/store (users, agents,
	// groups, revocations).
	StoreDBPath string `json:"store_db_path,omitempty"`

	NHITokenTTLSeconds     int `json:"nhi_token_ttl_seconds,omitempty"`
	HumanTokenTTLSeconds   int `json:"human_token_ttl_seconds,omitempty"`
	LocalSessionTTLSeconds int `json:"local_session_ttl_seconds,omitempty"`

	// SeedAgents declares NHI credentials with known, caller-chosen
	// secrets, created idempotently on startup. There's no admin API to
	// register agents yet (Phase 4) -- this is the bootstrap path until
	// then, primarily for automation/run-e2e-auth.sh to mint real tokens
	// against the compiled binary via curl. Real deployments should prefer
	// whatever the admin API becomes once it exists; a secret written into
	// a config file is weaker than a generated one.
	SeedAgents []SeedAgent `json:"seed_agents,omitempty"`

	// DevAllowAllPolicy, if true, makes the gateway use policy.AllowAll{}
	// instead of the real policy.DenyAll{} default. This exists ONLY so
	// automation/run-e2e.sh can exercise the full session/DLP pipeline
	// against the real binary before Phase 3's policy engine exists to
	// author real rules with -- it defaults to false (safe), and setting
	// it true means every authenticated caller can reach every tool on
	// every registered node. Never set this outside local dev or CI.
	DevAllowAllPolicy bool `json:"dev_allow_all_policy,omitempty"`

	// TrustedIdPs declares external IdPs this gateway accepts ID-JAGs from
	// (Mode B, issue #5). Config-file-only bootstrap, same pattern as
	// SeedAgents -- there's no admin API yet to register trust over HTTP.
	// Absent or empty means Mode B is entirely disabled: the jwt-bearer
	// grant is rejected and RFC 9728 metadata never advertises id-jag
	// support.
	TrustedIdPs []TrustedIdP `json:"trusted_idps,omitempty"`
}

// SeedAgent is one config-declared bootstrap NHI credential. See
// Config.SeedAgents.
type SeedAgent struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Name         string `json:"name"`
}

// TrustedIdP is one externally-trusted IdP an ID-JAG may come from. See
// Config.TrustedIdPs.
type TrustedIdP struct {
	// Issuer must exactly match the `iss` claim the IdP stamps on its
	// ID-JAGs.
	Issuer string `json:"issuer"`
	// JWKSURL is where this IdP publishes its own signing keys.
	JWKSURL string `json:"jwks_url"`
	// ExpectedAudience is what an ID-JAG's `aud` must equal to be accepted
	// -- this gateway's own AS identity (normally the same value as
	// Config.Issuer), per RFC 7523's resource-server-is-the-audience
	// requirement. Not a node -- that's the resulting access token's aud,
	// a separate value.
	ExpectedAudience string `json:"expected_audience"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.IdleSessionTimeoutSeconds <= 0 {
		c.IdleSessionTimeoutSeconds = DefaultIdleSessionTimeoutSeconds
	}
	if c.Issuer == "" {
		c.Issuer = "http://localhost" + c.Listen // dev-friendly guess; set explicitly for real deployments
	}
	if c.StoreDBPath == "" {
		c.StoreDBPath = DefaultStoreDBPath
	}
	if c.NHITokenTTLSeconds <= 0 {
		c.NHITokenTTLSeconds = DefaultNHITokenTTLSeconds
	}
	if c.HumanTokenTTLSeconds <= 0 {
		c.HumanTokenTTLSeconds = DefaultHumanTokenTTLSeconds
	}
	if c.LocalSessionTTLSeconds <= 0 {
		c.LocalSessionTTLSeconds = DefaultLocalSessionTTLSeconds
	}
	for i, n := range c.Nodes {
		if n.Name == "" {
			return nil, fmt.Errorf("every node needs a name")
		}
		if n.Transport == "" {
			n.Transport = TransportStreamableHTTP
		}
		switch n.Transport {
		case TransportStreamableHTTP:
			if n.UpstreamURL == "" {
				return nil, fmt.Errorf("node %s: streamable_http nodes need upstream_url", n.Name)
			}
		case TransportStdio:
			if n.Command == "" {
				return nil, fmt.Errorf("node %s: stdio nodes need command", n.Name)
			}
		default:
			return nil, fmt.Errorf("node %s: unknown transport %q", n.Name, n.Transport)
		}
		c.Nodes[i] = n
	}
	for _, a := range c.SeedAgents {
		if a.ClientID == "" || a.ClientSecret == "" || a.Name == "" {
			return nil, fmt.Errorf("seed_agents entries need client_id, client_secret, and name")
		}
	}
	for _, t := range c.TrustedIdPs {
		if t.Issuer == "" || t.JWKSURL == "" || t.ExpectedAudience == "" {
			return nil, fmt.Errorf("trusted_idps entries need issuer, jwks_url, and expected_audience")
		}
	}
	return &c, nil
}
