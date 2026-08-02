package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/metrics"
	"github.com/sumeetgp/spidercob-gateway/internal/proxy"
)

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

	gw, err := proxy.New(cfg)
	if err != nil {
		slog.Error("failed to build proxy", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		// TODO(phase 1): add store.Ping() once the sqlite store lands.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.Handle("/metrics", metrics.Handler())
	// TODO(phase 2): /token endpoint (RFC 7523 ID-JAG grant + internal exchange),
	// /.well-known/oauth-protected-resource/{node} (RFC 9728), JWKS.
	mux.Handle("/mcp/", gw)

	slog.Info("spidercob gateway listening", "addr", cfg.Listen, "nodes", len(cfg.Nodes))
	if err := http.ListenAndServe(cfg.Listen, mux); err != nil {
		slog.Error("server exited", "err", err)
		os.Exit(1)
	}
}
