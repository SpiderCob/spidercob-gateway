package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/authserver"
	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/idptrust"
	"github.com/sumeetgp/spidercob-gateway/internal/metrics"
	"github.com/sumeetgp/spidercob-gateway/internal/policy"
	"github.com/sumeetgp/spidercob-gateway/internal/proxy"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
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
		Issuer:          cfg.Issuer,
		Nodes:           nodeNames,
		Identity:        identitySvc,
		Store:           db,
		IdPTrust:        trust,
		NHITokenTTL:     time.Duration(cfg.NHITokenTTLSeconds) * time.Second,
		HumanTokenTTL:   time.Duration(cfg.HumanTokenTTLSeconds) * time.Second,
		LocalSessionTTL: time.Duration(cfg.LocalSessionTTLSeconds) * time.Second,
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

	slog.Info("spidercob gateway listening", "addr", cfg.Listen, "nodes", len(cfg.Nodes), "issuer", cfg.Issuer)
	if err := http.ListenAndServe(cfg.Listen, mux); err != nil {
		slog.Error("server exited", "err", err)
		os.Exit(1)
	}
}
