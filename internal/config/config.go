// Package config loads the gateway configuration.
// JSON for now to stay stdlib-only; YAML lands with the admin UI (design doc §9).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
	// PinRefreshIntervalSeconds overrides Config.PinRefreshIntervalSeconds
	// for this node only (issue #9 story 5: a slow-changing internal tool
	// and a frequently-updated third-party server can have different
	// staleness tolerances). Zero means "use the config-level default."
	PinRefreshIntervalSeconds int `json:"pin_refresh_interval_seconds,omitempty"`
}

// ValidateNode validates n and returns a normalized copy (Transport
// defaulted to TransportStreamableHTTP if unset) -- the exact per-
// transport validation config.Load's node loop always applied, now a
// standalone, pure, reusable function (issue #15) so internal/adminapi's
// node-creation endpoint enforces the identical rules without
// duplicating them. Name must also be safe as a URL path segment
// (routing is "/mcp/<name>/") and as the RFC 8707 resource-URI suffix
// (issuer + "/mcp/" + name) -- no "/", no leading/trailing whitespace.
func ValidateNode(n Node) (Node, error) {
	if n.Name == "" {
		return Node{}, fmt.Errorf("every node needs a name")
	}
	if strings.Contains(n.Name, "/") {
		return Node{}, fmt.Errorf("node %s: name must not contain \"/\"", n.Name)
	}
	if strings.TrimSpace(n.Name) != n.Name {
		return Node{}, fmt.Errorf("node %s: name must not have leading or trailing whitespace", n.Name)
	}
	if n.Transport == "" {
		n.Transport = TransportStreamableHTTP
	}
	switch n.Transport {
	case TransportStreamableHTTP:
		if n.UpstreamURL == "" {
			return Node{}, fmt.Errorf("node %s: streamable_http nodes need upstream_url", n.Name)
		}
	case TransportStdio:
		if n.Command == "" {
			return Node{}, fmt.Errorf("node %s: stdio nodes need command", n.Name)
		}
	default:
		return Node{}, fmt.Errorf("node %s: unknown transport %q", n.Name, n.Transport)
	}
	return n, nil
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
	// DefaultPinRefreshIntervalSeconds is how often each node's tools are
	// re-fetched and drift-checked (issue #9) when neither a node-level
	// nor config-level override is set.
	DefaultPinRefreshIntervalSeconds = 300 // 5 minutes
	// DefaultPinCheckIntervalSeconds is how often the background
	// scheduler wakes up to see whether *any* node is due -- independent
	// of, and normally much shorter than, any individual node's own
	// refresh interval (mirrors idleReapInterval's role for the
	// idle-session reaper).
	DefaultPinCheckIntervalSeconds = 10
	// DefaultSpiderSnoopIntrospectionTimeoutSeconds bounds a single live
	// GET {base}/api/users/me call (issue #13) -- short, since this sits
	// in the request path of every admin API call.
	DefaultSpiderSnoopIntrospectionTimeoutSeconds = 5
	// DefaultSpiderSnoopIntrospectionCacheTTLSeconds bounds how stale a
	// cached introspection result can be -- short enough that a
	// spider-snoop logout is respected promptly, long enough that a burst
	// of admin requests doesn't cost a live network call each.
	DefaultSpiderSnoopIntrospectionCacheTTLSeconds = 30
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
	// secrets, created idempotently on startup. Primarily for
	// automation/run-e2e-*.sh to mint real tokens against the compiled
	// binary via curl, and for bootstrapping the one agent
	// (AdminIntegrationClientIDs) that's allowed to call the admin API
	// (issue #13) before any admin API call could otherwise create it.
	// Real deployments should prefer internal/adminapi's agent-creation
	// endpoint for anything else; a secret written into a config file is
	// weaker than a generated one.
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

	// Policies declares the real access-control rules (issue #7) --
	// config-file bootstrap, same posture as SeedAgents/TrustedIdPs (no
	// admin API yet). Unlike SeedAgents (create-if-missing, since
	// credentials must never be silently regenerated), Policies fully
	// REPLACES whatever's in the store's policies table on every startup:
	// policy has no independent state of its own beyond config in this
	// phase, so config is the complete desired state, not a set of
	// increments. Absent or empty means every request is denied
	// (policy.DenyAll{}'s effective behavior even with the real evaluator
	// wired in -- no groups have any rules).
	Policies []PolicyRule `json:"policies,omitempty"`

	// PinRefreshIntervalSeconds is the default tool-pin drift-check
	// interval (issue #9) for any node that doesn't set its own
	// pin_refresh_interval_seconds. Falls back to
	// DefaultPinRefreshIntervalSeconds when unset.
	PinRefreshIntervalSeconds int `json:"pin_refresh_interval_seconds,omitempty"`
	// PinCheckIntervalSeconds is how often the background pin scheduler
	// wakes up to check whether any node is due for a refresh. Falls back
	// to DefaultPinCheckIntervalSeconds when unset; unrelated to, and
	// normally much shorter than, PinRefreshIntervalSeconds itself.
	PinCheckIntervalSeconds int `json:"pin_check_interval_seconds,omitempty"`

	// ScanDetectEmail and ScanDetectPhone gate the two lower-confidence
	// PII categories (issue #11 story 10-11: design doc §7's "email/phone
	// (configurable — often legitimate)") -- both default false. SSN and
	// Luhn-valid credit-card detection are unconditional and not gated by
	// either flag, the same "confirmed shape redacts by default" posture
	// SecretScanner already takes.
	ScanDetectEmail bool `json:"scan_detect_email,omitempty"`
	ScanDetectPhone bool `json:"scan_detect_phone,omitempty"`

	// AdminIntegrationClientIDs and SpiderSnoopBaseURL together enable
	// internal/adminapi (issue #13). AdminIntegrationClientIDs is the
	// allowlist of agent client_ids permitted to mint a token for the
	// reserved admin resource -- ordinary per-node tokens stay open to
	// any authenticated agent, but this one is not. SpiderSnoopBaseURL is
	// where the admin API live-introspects a human's session
	// (GET {base}/api/users/me) to confirm they currently hold an
	// admin/superadmin role in spider-snoop. Both must be set together,
	// or neither -- the admin API is entirely disabled (no /admin/*
	// routes mounted) if both are empty, and Load fails loudly rather
	// than starting in a half-configured state if only one is set.
	AdminIntegrationClientIDs []string `json:"admin_integration_client_ids,omitempty"`
	SpiderSnoopBaseURL        string   `json:"spider_snoop_base_url,omitempty"`
	// SpiderSnoopIntrospectionTimeoutSeconds bounds how long a hung
	// spider-snoop can block an admin request before the gateway fails
	// closed (never open) on it. SpiderSnoopIntrospectionCacheTTLSeconds
	// bounds how stale a cached "is this human currently an admin" result
	// can be -- a deliberate, short, explicit staleness window, not zero
	// (every admin request would otherwise cost a live network call to
	// spider-snoop) and not unbounded (a spider-snoop logout wouldn't be
	// respected promptly). Both fall back to their Default* constants
	// when the admin integration is enabled but these are unset.
	SpiderSnoopIntrospectionTimeoutSeconds  int `json:"spider_snoop_introspection_timeout_seconds,omitempty"`
	SpiderSnoopIntrospectionCacheTTLSeconds int `json:"spider_snoop_introspection_cache_ttl_seconds,omitempty"`
}

// AdminAPIEnabled reports whether internal/adminapi's routes should be
// mounted at all -- both AdminIntegrationClientIDs and SpiderSnoopBaseURL
// must be set (Load already refuses a half-configured combination, so by
// the time this is called it's an all-or-nothing question).
func (c *Config) AdminAPIEnabled() bool {
	return len(c.AdminIntegrationClientIDs) > 0 && c.SpiderSnoopBaseURL != ""
}

// SeedAgent is one config-declared bootstrap NHI credential. See
// Config.SeedAgents.
type SeedAgent struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Name         string `json:"name"`
	// Groups assigns this agent to the named groups at startup
	// (auto-creating any that don't already exist) -- issue #7's
	// bootstrap path for exercising an authorized NHI policy path from
	// automation, the same reason SeedAgents itself exists. No equivalent
	// mechanism exists for human (Mode A) users in this phase.
	Groups []string `json:"groups,omitempty"`
}

// PolicyRule is one config-declared access-control rule. See
// Config.Policies.
type PolicyRule struct {
	// Group is a name -- auto-created if it doesn't already exist.
	Group string `json:"group"`
	// Node must match a registered node's name. There is still no
	// persisted mcp_nodes table (design doc §8) -- policy references
	// nodes by their config-defined name, same posture as SeedAgents/
	// TrustedIdPs deferring real admin-managed resource registration.
	Node string `json:"node"`
	// RuleType is "allow" or "deny". An explicit deny always overrides a
	// matching allow, across every group a principal belongs to
	// (MASTER_PLAN.md §6, 2026-08-04).
	RuleType string `json:"rule_type"`
	// Methods restricts which JSON-RPC methods this rule covers,
	// including "initialize" -- there's no special-casing, a group needs
	// an explicit grant to even start a session. Empty means every
	// method.
	Methods []string `json:"methods,omitempty"`
	// Tools restricts which tool names this rule covers, only meaningful
	// when Methods includes "tools/call". Empty means every tool.
	Tools []string `json:"tools,omitempty"`
	// RateLimitMaxCalls and RateLimitWindowSeconds, if both set, cap how
	// many calls this rule's group/node combination may make in a
	// rolling window -- defense-in-depth, in-memory, per-process only
	// (not durable, not shared across replicas).
	RateLimitMaxCalls      *int `json:"rate_limit_max_calls,omitempty"`
	RateLimitWindowSeconds *int `json:"rate_limit_window_seconds,omitempty"`
	// BlockOnScanFlag escalates any non-clean verdict from the existing
	// request-scan pipeline (e.g. the injection heuristics, which
	// otherwise only log) to an actual block, for calls this rule
	// allows.
	BlockOnScanFlag bool `json:"block_on_scan_flag,omitempty"`
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
	if c.PinRefreshIntervalSeconds <= 0 {
		c.PinRefreshIntervalSeconds = DefaultPinRefreshIntervalSeconds
	}
	if c.PinCheckIntervalSeconds <= 0 {
		c.PinCheckIntervalSeconds = DefaultPinCheckIntervalSeconds
	}
	haveClientIDs := len(c.AdminIntegrationClientIDs) > 0
	haveBaseURL := c.SpiderSnoopBaseURL != ""
	if haveClientIDs != haveBaseURL {
		return nil, fmt.Errorf("admin_integration_client_ids and spider_snoop_base_url must be set together (both, or neither) -- got client_ids=%v, base_url=%q", c.AdminIntegrationClientIDs, c.SpiderSnoopBaseURL)
	}
	if c.AdminAPIEnabled() {
		if c.SpiderSnoopIntrospectionTimeoutSeconds <= 0 {
			c.SpiderSnoopIntrospectionTimeoutSeconds = DefaultSpiderSnoopIntrospectionTimeoutSeconds
		}
		if c.SpiderSnoopIntrospectionCacheTTLSeconds <= 0 {
			c.SpiderSnoopIntrospectionCacheTTLSeconds = DefaultSpiderSnoopIntrospectionCacheTTLSeconds
		}
	}
	for i, n := range c.Nodes {
		validated, err := ValidateNode(n)
		if err != nil {
			return nil, err
		}
		c.Nodes[i] = validated
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
	for _, p := range c.Policies {
		if p.Group == "" || p.Node == "" {
			return nil, fmt.Errorf("policies entries need group and node")
		}
		if p.RuleType != "allow" && p.RuleType != "deny" {
			return nil, fmt.Errorf("policies entry for group %q node %q: rule_type must be \"allow\" or \"deny\", got %q", p.Group, p.Node, p.RuleType)
		}
		if (p.RateLimitMaxCalls == nil) != (p.RateLimitWindowSeconds == nil) {
			return nil, fmt.Errorf("policies entry for group %q node %q: rate_limit_max_calls and rate_limit_window_seconds must be set together", p.Group, p.Node)
		}
	}
	return &c, nil
}
