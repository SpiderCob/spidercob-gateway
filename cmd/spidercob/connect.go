package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/connect"
)

// multiFlag implements flag.Value for a repeatable -node flag (issue
// #52: one connect instance can proxy every node a single credential
// has access to, not just one).
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// httpMinter is connect.Minter's real implementation -- hits the real
// gateway's existing, unchanged POST /token client_credentials grant,
// exactly the same request shape internal/authserver already serves for
// any other NHI caller. No new gateway-side surface at all.
type httpMinter struct {
	gatewayURL   string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

func (m *httpMinter) Mint(ctx context.Context, node string) (string, time.Time, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {m.clientID},
		"client_secret": {m.clientSecret},
		"resource":      {node},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(m.gatewayURL, "/")+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("POST /token for node %q: %w", node, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", time.Time{}, fmt.Errorf("POST /token for node %q: decoding response: %w", node, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("POST /token for node %q: %s: %s: %s", node, resp.Status, body.Error, body.ErrorDescription)
	}
	return body.AccessToken, time.Now().Add(time.Duration(body.ExpiresIn) * time.Second), nil
}

// runConnect implements the "spidercob connect" subcommand (issue #52):
// a local reverse proxy that holds one long-lived NHI credential, mints
// and silently refreshes short-lived node-scoped tokens in the
// background, and forwards MCP traffic to the real gateway. The calling
// MCP client's config collapses to a bare local URL -- no Authorization
// header, no expiry to think about.
func runConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	gatewayURL := fs.String("gateway", "", "base URL of the real gateway, e.g. http://gateway.internal:8080 (required)")
	listen := fs.String("listen", "127.0.0.1:8090", "local address for the MCP client to point at")
	clientID := fs.String("client-id", "", "the NHI agent's client_id (required)")
	clientSecret := fs.String("client-secret", "",
		"the NHI agent's client_secret -- prefer the SPIDERCOB_CLIENT_SECRET environment variable instead, it never ends up in shell history or `ps`")
	allowNonLoopback := fs.Bool("allow-non-loopback", false,
		"allow -listen to bind somewhere other than loopback -- exposes an unauthenticated credential-holding proxy to whatever network that address is reachable from; only set this if you understand that")
	var nodes multiFlag
	fs.Var(&nodes, "node", "a node this credential should be usable against (repeatable -- pass -node once per node)")
	_ = fs.Parse(args)

	secret := *clientSecret
	if secret == "" {
		secret = os.Getenv("SPIDERCOB_CLIENT_SECRET")
	}
	switch {
	case *gatewayURL == "":
		fatalConnect("connect: -gateway is required")
	case *clientID == "":
		fatalConnect("connect: -client-id is required")
	case secret == "":
		fatalConnect("connect: a client secret is required, via -client-secret or (preferred) the SPIDERCOB_CLIENT_SECRET environment variable")
	case len(nodes) == 0:
		fatalConnect("connect: at least one -node is required")
	}

	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		fatalConnect(fmt.Sprintf("connect: -listen %q: %v", *listen, err))
	}
	if !isLoopbackHost(host) && !*allowNonLoopback {
		fatalConnect(fmt.Sprintf(
			"connect: refusing to bind -listen %q -- not a loopback address, and -allow-non-loopback wasn't set. This would expose an unauthenticated credential-holding proxy to whatever network that address is reachable from.",
			*listen))
	}

	gwURL, err := url.Parse(*gatewayURL)
	if err != nil {
		fatalConnect(fmt.Sprintf("connect: -gateway %q: %v", *gatewayURL, err))
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	minter := &httpMinter{
		gatewayURL:   *gatewayURL,
		clientID:     *clientID,
		clientSecret: secret,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
	}
	px := connect.New(gwURL, nodes, minter)
	if err := px.Start(context.Background()); err != nil {
		slog.Error("connect: failed to start", "err", err)
		os.Exit(1)
	}
	defer func() { _ = px.Close() }()

	slog.Info("spidercob connect listening", "listen", *listen, "gateway", *gatewayURL, "nodes", []string(nodes))
	if err := http.ListenAndServe(*listen, px); err != nil {
		slog.Error("connect: server failed", "err", err)
		os.Exit(1)
	}
}

// isLoopbackHost is deliberately conservative: an empty host (":8090",
// binding every interface) is NOT loopback, and only a literal
// loopback IP or "localhost" counts -- issue #52 spec's default-safe
// posture, not something worth being clever about.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func fatalConnect(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}
