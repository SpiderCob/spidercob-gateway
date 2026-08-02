# Observability on Free Tiers (until funding)

Everything below runs on permanent free tiers — no trials, no card required
for the core path.

## What the gateway exposes

- `GET /metrics` — Prometheus text format (dependency-free exporter,
  `internal/metrics`). Key series:
  - `spidercob_requests_total{node,rpc_method,code}`
  - `spidercob_scan_verdicts_total{scanner,action,direction,node}` — the
    `action="redact"` counter is your demo stat
  - `spidercob_upstream_duration_seconds_bucket{node,le}`
- `GET /healthz` (liveness) and `GET /readyz` (readiness)
- Structured JSON logs on stdout (`log/slog`) — scan verdicts, startup, errors

## Recommended free stack

| Concern | Service | Free tier |
|---|---|---|
| Metrics + dashboards | Grafana Cloud | 10k active series, 14-day retention, permanent |
| Logs | Grafana Cloud Loki | 50 GB/month included in the same free account |
| Healthcheck alerting | healthchecks.io | 20 checks free; or self-host Uptime Kuma |
| CI | GitHub Actions | free for public repos |

## Setup (~15 minutes)

1. Create a free account at grafana.com → note your Prometheus remote_write
   URL + API key and Loki push URL + key.
2. Run Grafana Alloy as a sidecar to scrape and ship both:

```alloy
prometheus.scrape "spidercob" {
  targets    = [{ __address__ = "gateway:8080" }]
  forward_to = [prometheus.remote_write.grafanacloud.receiver]
}

prometheus.remote_write "grafanacloud" {
  endpoint {
    url = "<YOUR_PROM_PUSH_URL>"
    basic_auth { username = "<INSTANCE_ID>", password = "<API_KEY>" }
  }
}

loki.source.docker "gateway_logs" {
  host       = "unix:///var/run/docker.sock"
  targets    = [{ job = "spidercob" }]
  forward_to = [loki.write.grafanacloud.receiver]
}

loki.write "grafanacloud" {
  endpoint {
    url = "<YOUR_LOKI_PUSH_URL>"
    basic_auth { username = "<INSTANCE_ID>", password = "<API_KEY>" }
  }
}
```

   (Add an `alloy` service to `deploy/docker-compose.yml` mounting this
   config; grafana/alloy image is free.)
3. Import `deploy/grafana-dashboard.json` in Grafana → Dashboards → Import,
   pick your Prometheus datasource.
4. Healthchecks: point healthchecks.io (or Uptime Kuma) at `/healthz` on a
   1-minute interval.

## Free-tier budget guardrails

- Cardinality is the thing that breaks the 10k-series cap: labels are
  bounded (node, scanner, action, code, rpc_method). Do NOT add user IDs,
  session IDs, or tool arguments as metric labels — those belong in logs.
- 14-day metric retention is fine pre-funding; export screenshots for
  launch content.
- When you outgrow free: Grafana Cloud pay-as-you-go, or self-host
  Prometheus+Grafana in the same compose file — the gateway doesn't care.
