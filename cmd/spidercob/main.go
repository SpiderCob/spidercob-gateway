package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/adminapi"
	"github.com/sumeetgp/spidercob-gateway/internal/authserver"
	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/idptrust"
	"github.com/sumeetgp/spidercob-gateway/internal/metrics"
	"github.com/sumeetgp/spidercob-gateway/internal/pin"
	"github.com/sumeetgp/spidercob-gateway/internal/policy"
	"github.com/sumeetgp/spidercob-gateway/internal/proxy"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
	"github.com/sumeetgp/spidercob-gateway/internal/uisession"
	"github.com/sumeetgp/spidercob-gateway/internal/webui"
)

// authValidator adapts *authserver.AuthServer to proxy.TokenValidator so
// internal/proxy never needs to import internal/authserver directly --
// this composition root is the only place that wires the two together.
type authValidator struct{ as *authserver.AuthServer }

func (a authValidator) ValidateAccessToken(node, token string) (proxy.AuthClaims, error) {
	c, err := a.as.ValidateAccessToken(node, token)
	if err != nil {
		return proxy.AuthClaims{}, err
	}
	return proxy.AuthClaims{Subject: c.Subject, Act: c.Act}, nil
}

// adminAuthValidator adapts *authserver.AuthServer to
// adminapi.AdminTokenValidator, the same "define the minimal interface
// in the dependent package, adapt here" pattern authValidator already
// uses for proxy.TokenValidator (issue #13).
type adminAuthValidator struct{ as *authserver.AuthServer }

func (a adminAuthValidator) ValidateAdminAccessToken(token string) (adminapi.AdminClaims, error) {
	c, err := a.as.ValidateAdminAccessToken(token)
	if err != nil {
		return adminapi.AdminClaims{}, err
	}
	return adminapi.AdminClaims{Subject: c.Subject}, nil
}

// getOrCreateGroup resolves a group by name, creating it if it doesn't
// already exist -- both SeedAgents.Groups and Policies reference groups by
// name, auto-created rather than requiring a separate bootstrap step.
func getOrCreateGroup(db store.Store, name string) (store.Group, error) {
	g, err := db.CreateGroup(context.Background(), name)
	if err == nil {
		return g, nil
	}
	if !errors.Is(err, store.ErrConflict) {
		return store.Group{}, err
	}
	return db.GetGroupByName(context.Background(), name)
}

// configNodeToStoreNode converts a config.json-declared node into the
// store.Node shape UpsertConfigNode accepts -- Source is left unset here,
// UpsertConfigNode always sets it to store.NodeSourceConfig itself
// (issue #15).
func configNodeToStoreNode(n config.Node) store.Node {
	sn := store.Node{Name: n.Name, Transport: n.Transport, Args: n.Args}
	if n.UpstreamURL != "" {
		sn.UpstreamURL = &n.UpstreamURL
	}
	if n.Command != "" {
		sn.Command = &n.Command
	}
	if n.PinRefreshIntervalSeconds > 0 {
		sn.PinRefreshIntervalSeconds = &n.PinRefreshIntervalSeconds
	}
	return sn
}

// storeNodeToConfigNode is configNodeToStoreNode's inverse -- once every
// node (config- and admin-sourced alike) lives in the store, this is how
// cmd/spidercob builds the config.Node list that proxy.New/
// authserver.Config.Nodes/the pin scheduler already know how to consume,
// with zero changes required inside any of those three packages
// (issue #15).
func storeNodeToConfigNode(n store.Node) config.Node {
	cn := config.Node{Name: n.Name, Transport: n.Transport, Args: n.Args}
	if n.UpstreamURL != nil {
		cn.UpstreamURL = *n.UpstreamURL
	}
	if n.Command != nil {
		cn.Command = *n.Command
	}
	if n.PinRefreshIntervalSeconds != nil {
		cn.PinRefreshIntervalSeconds = *n.PinRefreshIntervalSeconds
	}
	return cn
}

func main() {
	cfgPath := flag.String("config", "config.json", "path to gateway config file")
	flag.Parse()

	// Structured JSON logs to stdout — ship them anywhere (Loki, etc.)
	// with a log collector. See docs/observability.md.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("failed to load config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}

	db, err := store.Open(cfg.StoreDBPath)
	if err != nil {
		slog.Error("failed to open store", "path", cfg.StoreDBPath, "err", err)
		os.Exit(1)
	}
	defer db.Close()

	identitySvc := identity.NewService(db)

	for _, seed := range cfg.SeedAgents {
		agent, err := identitySvc.CreateAgentWithCredentials(context.Background(), seed.ClientID, seed.ClientSecret, seed.Name)
		switch {
		case err == nil:
			slog.Info("seeded agent", "client_id", seed.ClientID, "name", seed.Name)
		case errors.Is(err, store.ErrConflict):
			// Already seeded on a previous startup -- fine, idempotent.
			// Group assignment below still needs the agent's ID, so fetch
			// the existing record rather than skipping the rest of this
			// iteration.
			agent, err = db.GetAgentByClientID(context.Background(), seed.ClientID)
			if err != nil {
				slog.Error("failed to look up already-seeded agent", "client_id", seed.ClientID, "err", err)
				os.Exit(1)
			}
		default:
			slog.Error("failed to seed agent", "client_id", seed.ClientID, "err", err)
			os.Exit(1)
		}
		for _, groupName := range seed.Groups {
			g, err := getOrCreateGroup(db, groupName)
			if err != nil {
				slog.Error("failed to resolve seed agent group", "group", groupName, "err", err)
				os.Exit(1)
			}
			if err := db.AssignAgentGroup(context.Background(), agent.ID, g.ID); err != nil {
				slog.Error("failed to assign seed agent to group", "client_id", seed.ClientID, "group", groupName, "err", err)
				os.Exit(1)
			}
		}
	}

	// SeedUsers (issue #21): the standalone-deployment (no spider-snoop)
	// bootstrap for local Mode A humans, CSV-sourced via
	// cfg.SeedUsersCSVPath. Mirrors the SeedAgents loop immediately
	// above exactly -- create-if-missing, group assignment always runs
	// (even for an already-seeded user, so adding a group to an
	// existing CSV row and restarting still takes effect), and an
	// existing user's password is never touched by a later run: a
	// store.ErrConflict here means "already provisioned," not "update
	// it," the same idempotency posture SeedAgents already has and
	// deliberately not Policies'/mcp_nodes' "config wins, update in
	// place" posture -- resetting a live human's password from a stale
	// or edited CSV would be a real security foot-gun, not a
	// convenience.
	for _, seed := range cfg.SeedUsers {
		user, err := identitySvc.CreateUser(context.Background(), seed.Username, seed.Password)
		switch {
		case err == nil:
			slog.Info("seeded user", "username", seed.Username)
		case errors.Is(err, store.ErrConflict):
			slog.Info("user already seeded, leaving existing password untouched", "username", seed.Username)
			user, err = db.GetUserByUsername(context.Background(), seed.Username)
			if err != nil {
				slog.Error("failed to look up already-seeded user", "username", seed.Username, "err", err)
				os.Exit(1)
			}
		default:
			slog.Error("failed to seed user", "username", seed.Username, "err", err)
			os.Exit(1)
		}
		for _, groupName := range seed.Groups {
			g, err := getOrCreateGroup(db, groupName)
			if err != nil {
				slog.Error("failed to resolve seed user group", "group", groupName, "err", err)
				os.Exit(1)
			}
			if err := db.AssignUserGroup(context.Background(), user.ID, g.ID); err != nil {
				slog.Error("failed to assign seed user to group", "username", seed.Username, "group", groupName, "err", err)
				os.Exit(1)
			}
		}
	}

	// Policy config is the sole source of policy truth in this phase (no
	// admin API exists yet, issue #7) -- fully replaces whatever's in the
	// store on every startup, unlike identity data. See
	// store.Store.ReplacePolicies's doc comment for why that's the right
	// idempotency strategy here specifically.
	newPolicies := make([]store.NewPolicy, 0, len(cfg.Policies))
	for _, p := range cfg.Policies {
		g, err := getOrCreateGroup(db, p.Group)
		if err != nil {
			slog.Error("failed to resolve policy group", "group", p.Group, "err", err)
			os.Exit(1)
		}
		newPolicies = append(newPolicies, store.NewPolicy{
			GroupID:                g.ID,
			Node:                   p.Node,
			RuleType:               store.PolicyRuleType(p.RuleType),
			Methods:                p.Methods,
			Tools:                  p.Tools,
			RateLimitMaxCalls:      p.RateLimitMaxCalls,
			RateLimitWindowSeconds: p.RateLimitWindowSeconds,
			BlockOnScanFlag:        p.BlockOnScanFlag,
		})
	}
	if err := db.ReplacePolicies(context.Background(), newPolicies); err != nil {
		slog.Error("failed to apply policy config", "err", err)
		os.Exit(1)
	}
	slog.Info("policy config applied", "rules", len(newPolicies))

	// Node bootstrap (issue #15): config.json stays authoritative for its
	// own nodes -- each is upserted into the store on every startup
	// (store.UpsertConfigNode refuses to clobber a same-named node an
	// admin registered via the API instead). The FULL current set (config-
	// and admin-sourced alike) then replaces cfg.Nodes for every
	// downstream construction step below, so proxy.New/authserver.New/the
	// pin scheduler need zero internal changes to pick up admin-registered
	// nodes -- on the *next* startup. A node created via POST /admin/nodes
	// while the gateway is already running has no effect on this running
	// process; there is no hot-reload yet (MASTER_PLAN.md §6, 2026-08-08).
	for _, n := range cfg.Nodes {
		if _, err := db.UpsertConfigNode(context.Background(), configNodeToStoreNode(n)); err != nil {
			slog.Error("failed to bootstrap config-defined node into the store", "node", n.Name, "err", err)
			os.Exit(1)
		}
	}
	storedNodes, err := db.ListNodes(context.Background())
	if err != nil {
		slog.Error("failed to list nodes", "err", err)
		os.Exit(1)
	}
	cfg.Nodes = make([]config.Node, 0, len(storedNodes))
	for _, n := range storedNodes {
		cfg.Nodes = append(cfg.Nodes, storeNodeToConfigNode(n))
	}

	nodeNames := make([]string, 0, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		nodeNames = append(nodeNames, n.Name)
	}

	var trust *idptrust.TrustStore
	if len(cfg.TrustedIdPs) > 0 {
		issuers := make([]idptrust.TrustedIssuer, 0, len(cfg.TrustedIdPs))
		for _, t := range cfg.TrustedIdPs {
			issuers = append(issuers, idptrust.TrustedIssuer{
				Issuer: t.Issuer, JWKSURL: t.JWKSURL, ExpectedAudience: t.ExpectedAudience,
			})
		}
		trust, err = idptrust.New(context.Background(), issuers)
		if err != nil {
			slog.Error("failed to build idptrust", "err", err)
			os.Exit(1)
		}
		slog.Info("Mode B (external IdP) enabled", "trusted_issuers", len(issuers))
	}

	as, err := authserver.New(context.Background(), authserver.Config{
		Issuer:                    cfg.Issuer,
		Nodes:                     nodeNames,
		Identity:                  identitySvc,
		Store:                     db,
		IdPTrust:                  trust,
		NHITokenTTL:               time.Duration(cfg.NHITokenTTLSeconds) * time.Second,
		HumanTokenTTL:             time.Duration(cfg.HumanTokenTTLSeconds) * time.Second,
		LocalSessionTTL:           time.Duration(cfg.LocalSessionTTLSeconds) * time.Second,
		AdminIntegrationClientIDs: cfg.AdminIntegrationClientIDs,
	})
	if err != nil {
		slog.Error("failed to build authserver", "err", err)
		os.Exit(1)
	}

	gw, err := proxy.New(cfg, authValidator{as: as})
	if err != nil {
		slog.Error("failed to build proxy", "err", err)
		os.Exit(1)
	}
	if !cfg.DevAllowAllPolicy {
		// DevAllowAllPolicy, when set, is a blunt dev/CI-only escape hatch
		// (automation/run-e2e.sh) that must win outright -- it's not meant
		// to be quietly overridden by whatever real policy config happens
		// to also be present.
		gw.SetPolicy(policy.NewEvaluator(db))
	}

	// Tool pinning (issue #9): always wired in, independent of
	// DevAllowAllPolicy -- that flag exists to bypass the authorization
	// question ("who may call what"), pinning answers a different one
	// ("is the tool still what it was when it was first observed"), and
	// automation/run-e2e.sh needs both a permissive policy AND working
	// drift detection to actually exercise this feature end-to-end.
	pinRegistry := pin.NewRegistry(db)
	gw.SetPinRegistry(pinRegistry)

	pinIntervals := make(map[string]time.Duration, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n.PinRefreshIntervalSeconds > 0 {
			pinIntervals[n.Name] = time.Duration(n.PinRefreshIntervalSeconds) * time.Second
		}
	}
	pinScheduler := pin.NewScheduler(pin.SchedulerConfig{
		Registry:        pinRegistry,
		Fetch:           gw.FetchToolsForPin,
		Nodes:           nodeNames,
		Intervals:       pinIntervals,
		DefaultInterval: time.Duration(cfg.PinRefreshIntervalSeconds) * time.Second,
		CheckInterval:   time.Duration(cfg.PinCheckIntervalSeconds) * time.Second,
	})
	pinScheduler.Start()
	defer pinScheduler.Stop()

	// Admin API (issue #13): mounted only when both admin_integration_
	// client_ids and spider_snoop_base_url are set -- config.Load already
	// refuses a half-configured combination, so AdminAPIEnabled() here is
	// a clean on/off switch, not a partial-state check.
	var adminAPI *adminapi.AdminAPI
	if cfg.AdminAPIEnabled() {
		introspector := adminapi.NewCachingIntrospector(
			adminapi.NewHTTPIntrospector(cfg.SpiderSnoopBaseURL, time.Duration(cfg.SpiderSnoopIntrospectionTimeoutSeconds)*time.Second),
			time.Duration(cfg.SpiderSnoopIntrospectionCacheTTLSeconds)*time.Second,
		)
		uiSessions := uisession.NewRegistry(uisession.RegistryConfig{
			MaxAge: time.Duration(cfg.AdminUISessionMaxAgeSeconds) * time.Second,
		})
		adminAPI, err = adminapi.New(adminapi.Config{
			Store:        db,
			Identity:     identitySvc,
			Authn:        adminAuthValidator{as: as},
			Introspector: introspector,
			UISessions:   uiSessions,
		})
		if err != nil {
			slog.Error("failed to build adminapi", "err", err)
			os.Exit(1)
		}
		slog.Info("admin API enabled", "spider_snoop_base_url", cfg.SpiderSnoopBaseURL, "integration_agents", len(cfg.AdminIntegrationClientIDs))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := db.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("store unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.Handle("/metrics", metrics.Handler())
	mux.Handle("/", as.Routes()) // /token, JWKS, RFC 9728 metadata
	mux.Handle("/mcp/", gw)
	// The admin UI (issue #17) is served unconditionally when built into
	// the binary -- no separate feature flag, matching the "ship the
	// mechanism now" posture the rest of Phase 4 already takes. It's
	// inert without the admin API actually being enabled: every /admin/*
	// call the UI makes still goes through the exact same dual-trust (or
	// cookie) gate below.
	mux.Handle("/ui/", webui.Handler())
	if adminAPI != nil {
		mux.Handle("/admin/", adminAPI.Routes())
	}

	slog.Info("spidercob gateway listening", "addr", cfg.Listen, "nodes", len(cfg.Nodes), "issuer", cfg.Issuer)
	if err := http.ListenAndServe(cfg.Listen, mux); err != nil {
		slog.Error("server exited", "err", err)
		os.Exit(1)
	}
}
