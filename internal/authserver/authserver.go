// Package authserver is the gateway's embedded OAuth-shaped token issuer:
// local users and NHI (agent) credentials in, short-lived node-scoped
// access tokens out (design doc §6, issue #3). It deliberately does not
// use a full OAuth AS framework (ory/fosite, zitadel/oidc) -- see
// MASTER_PLAN.md §6, 2026-08-07 decision -- because its actual grant
// surface (a non-standard local-session exchange for humans, plus
// client_credentials for NHIs) doesn't match what those frameworks assume.
// Token construction/verification itself still leans on a vetted JWT
// library (golang-jwt/jwt/v5); only the AS orchestration is bespoke.
package authserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/idptrust"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// Grant types. "client_credentials" is the standard RFC 6749 one;
// "jwt-bearer" is the standard RFC 7523 one (issue #5, Mode B); the other
// two are this gateway's own internal exchange (issue #3's Implementation
// Decisions calls this "the internal exchange grant") -- namespaced under
// a urn: prefix, the same convention RFC 8693 uses for its own
// grant/token-type identifiers, so they're unambiguously not a standard
// OAuth grant a generic client might misinterpret.
const (
	grantClientCredentials = "client_credentials"
	grantJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	grantLogin             = "urn:spidercob:params:oauth:grant-type:login"
	grantSession           = "urn:spidercob:params:oauth:grant-type:session"
)

// AdminResource is the reserved "resource" value (RFC 8707) for minting
// an admin-audience access token (issue #13) -- deliberately shaped so it
// can never collide with a real, customer-chosen node name (nodes are
// bare names like "jira"; this is underscore-prefixed and resolved
// through its own path, never through resolveNode's node registry).
// Unlike an ordinary node resource -- open to any authenticated agent,
// since policy enforcement happens downstream at request time, not at
// mint time -- minting a token for this one is restricted to a config-
// designated allowlist of agent client_ids, checked at mint time.
const AdminResource = "_admin"

// idJAGGrantProfile is what this gateway advertises in RFC 9728's
// authorization_grant_profiles_supported once at least one external IdP
// is trusted (issue #5) -- the MCP EMA extension's client-discovery
// signal for "this resource server accepts ID-JAGs."
const idJAGGrantProfile = "urn:ietf:params:oauth:grant-profile:id-jag"

// sessionCookieName is the Mode A local-session cookie, scoped to Path
// "/token" only -- it must never be sent to /mcp/ routes, which use their
// own, unrelated Mcp-Session-Id mirrored cookie (internal/proxy).
const sessionCookieName = "spidercob_session"

const (
	// DefaultNHITokenTTL and DefaultHumanTokenTTL are issue #3's decided
	// defaults (MASTER_PLAN.md §6, 2026-08-04), both admin-configurable.
	DefaultNHITokenTTL   = 120 * time.Second
	DefaultHumanTokenTTL = 10 * time.Minute
	// DefaultLocalSessionTTL bounds how long a human can silently re-mint
	// node-scoped access tokens (story 17) without re-entering their
	// password. Not one of issue #3's explicitly-named TTL knobs, but a
	// necessary consequence of it: the human access-token TTL (10m) is
	// too short to be "the session," so a longer-lived, still-short,
	// signed session credential stands in for repeated logins.
	DefaultLocalSessionTTL = 8 * time.Hour
)

// Config configures a new AuthServer.
type Config struct {
	// Issuer is this AS's own identity -- stamped as iss on every token,
	// and used to build aud (per-node resource URIs) and the JWKS/RFC 9728
	// URLs advertised to clients. E.g. "https://gateway.example.com".
	Issuer string
	// Nodes is the set of registered MCP node names tokens may be scoped
	// to -- normally the same node list the proxy is configured with.
	Nodes []string

	Identity *identity.Service
	Store    store.Store
	// IdPTrust enables Mode B (issue #5): the RFC 7523 jwt-bearer grant
	// and RFC 9728's id-jag grant-profile advertisement. Nil (or an empty
	// TrustStore) means Mode B is entirely absent -- ServeToken rejects
	// the jwt-bearer grant type the same way it rejects any other
	// unsupported grant, and metadata never advertises id-jag support.
	IdPTrust *idptrust.TrustStore

	NHITokenTTL     time.Duration // zero -> DefaultNHITokenTTL
	HumanTokenTTL   time.Duration // zero -> DefaultHumanTokenTTL
	LocalSessionTTL time.Duration // zero -> DefaultLocalSessionTTL

	// AdminIntegrationClientIDs is the allowlist of agent client_ids
	// permitted to mint a token for AdminResource (issue #13). Empty
	// (the default) means no agent can mint one -- the admin API is
	// unreachable, not open by omission.
	AdminIntegrationClientIDs []string

	// LocalAdminGroup enables LoginLocalAdmin/ValidateLocalAdminSession
	// (issue #43, standalone admin login): any local user in this group
	// is a gateway admin, checked live on every request. Empty (the
	// default) means this admin-auth mode is off -- both methods return
	// an error unconditionally.
	LocalAdminGroup string
}

// AuthServer issues, publishes verification keys for, and validates this
// gateway's own node-scoped access tokens.
type AuthServer struct {
	issuer   string
	identity *identity.Service
	idpTrust *idptrust.TrustStore // nil means Mode B is disabled entirely
	keys     *KeySet
	nodes    map[string]struct{}
	denylist *denylist

	nhiTTL     time.Duration
	humanTTL   time.Duration
	sessionTTL time.Duration

	adminIntegrationClientIDs map[string]struct{}
	localAdminGroup           string
}

// New builds an AuthServer, generating its first signing key and
// hydrating the revocation denylist from cfg.Store so a restart doesn't
// forget which tokens were revoked (their own exp still bounds how long
// that matters).
func New(ctx context.Context, cfg Config) (*AuthServer, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("authserver: Issuer is required")
	}
	if cfg.Identity == nil || cfg.Store == nil {
		return nil, fmt.Errorf("authserver: Identity and Store are required")
	}

	keys, err := NewKeySet()
	if err != nil {
		return nil, err
	}
	dl := newDenylist(cfg.Store)
	if err := dl.hydrate(ctx); err != nil {
		return nil, fmt.Errorf("hydrate revocation denylist: %w", err)
	}

	nodes := make(map[string]struct{}, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		nodes[n] = struct{}{}
	}
	adminClientIDs := make(map[string]struct{}, len(cfg.AdminIntegrationClientIDs))
	for _, id := range cfg.AdminIntegrationClientIDs {
		adminClientIDs[id] = struct{}{}
	}

	as := &AuthServer{
		issuer:                    strings.TrimRight(cfg.Issuer, "/"),
		identity:                  cfg.Identity,
		idpTrust:                  cfg.IdPTrust,
		keys:                      keys,
		nodes:                     nodes,
		denylist:                  dl,
		nhiTTL:                    cfg.NHITokenTTL,
		humanTTL:                  cfg.HumanTokenTTL,
		sessionTTL:                cfg.LocalSessionTTL,
		adminIntegrationClientIDs: adminClientIDs,
		localAdminGroup:           cfg.LocalAdminGroup,
	}
	if as.nhiTTL <= 0 {
		as.nhiTTL = DefaultNHITokenTTL
	}
	if as.humanTTL <= 0 {
		as.humanTTL = DefaultHumanTokenTTL
	}
	if as.sessionTTL <= 0 {
		as.sessionTTL = DefaultLocalSessionTTL
	}
	return as, nil
}

// Routes returns every endpoint this package serves: /token, JWKS, and
// per-node RFC 9728 protected-resource metadata. The caller (cmd/spidercob)
// mounts this alongside the proxy's /mcp/ handler on one http.Server.
func (a *AuthServer) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", a.ServeJWKS)
	mux.HandleFunc("/.well-known/oauth-protected-resource/", a.ServeProtectedResourceMetadata)
	mux.HandleFunc("/token", a.ServeToken)
	return mux
}

// resourceURI is a node's canonical RFC 8707 resource identifier -- both
// the aud a token is minted for and the "resource" field of its RFC 9728
// metadata. Matches the proxy's own routing path (/mcp/<node>/...) so the
// two halves of the system agree on what "this node" means without a
// separate mapping table.
func (a *AuthServer) resourceURI(node string) string {
	return a.issuer + "/mcp/" + node
}

// MetadataURL is the RFC 9728 protected-resource metadata URL for node,
// for building a WWW-Authenticate header (internal/proxy calls this).
func (a *AuthServer) MetadataURL(node string) string {
	return a.issuer + "/.well-known/oauth-protected-resource/" + node
}

// adminResourceURI is AdminResource's canonical RFC 8707 identifier, the
// same "issuer + path" shape resourceURI uses for nodes but never
// collidable with one (nodes route under /mcp/, this doesn't).
func (a *AuthServer) adminResourceURI() string {
	return a.issuer + "/" + AdminResource
}

// isAdminResource accepts either the bare reserved value or its full URI
// form, mirroring resolveNode's bare-name-or-URI convenience for nodes.
func (a *AuthServer) isAdminResource(resource string) bool {
	return resource == AdminResource || resource == a.adminResourceURI()
}

// resolveNode accepts either a bare node name or that node's full
// canonical resourceURI in the "resource" parameter -- convenient for
// simple clients while staying RFC 8707-correct for spec-following ones.
func (a *AuthServer) resolveNode(resource string) (node string, ok bool) {
	if resource == "" {
		return "", false
	}
	if _, exists := a.nodes[resource]; exists {
		return resource, true
	}
	for n := range a.nodes {
		if a.resourceURI(n) == resource {
			return n, true
		}
	}
	return "", false
}

// ValidateAccessToken is the proxy's hot-path call: verify signature, typ,
// issuer, that aud matches exactly this node, and that jti isn't revoked.
// Every distinct failure has its own sentinel error so it's independently
// testable (issue #3's Testing Decisions) without waiting out a real TTL
// or hand-forging a valid-looking token.
func (a *AuthServer) ValidateAccessToken(node, tokenString string) (Claims, error) {
	claims, err := parseAndVerify(a.keys, tokenString, typAccess)
	if err != nil {
		return Claims{}, err
	}
	if claims.Issuer != a.issuer {
		return Claims{}, ErrTokenWrongIssuer
	}
	want := a.resourceURI(node)
	if len(claims.Audience) != 1 || claims.Audience[0] != want {
		return Claims{}, ErrTokenWrongAudience
	}
	if a.denylist.isRevoked(claims.ID) {
		return Claims{}, ErrTokenRevoked
	}
	return *claims, nil
}

// ValidateAdminAccessToken is internal/adminapi's hot-path call --
// mirrors ValidateAccessToken exactly, just checking aud against
// adminResourceURI instead of a specific node's resourceURI, so an
// ordinary node-scoped token (or vice versa, an admin-scoped one
// presented to the MCP data plane) is never interchangeable with this
// one -- the two audiences are structurally distinct values.
func (a *AuthServer) ValidateAdminAccessToken(tokenString string) (Claims, error) {
	claims, err := parseAndVerify(a.keys, tokenString, typAccess)
	if err != nil {
		return Claims{}, err
	}
	if claims.Issuer != a.issuer {
		return Claims{}, ErrTokenWrongIssuer
	}
	want := a.adminResourceURI()
	if len(claims.Audience) != 1 || claims.Audience[0] != want {
		return Claims{}, ErrTokenWrongAudience
	}
	if a.denylist.isRevoked(claims.ID) {
		return Claims{}, ErrTokenRevoked
	}
	return *claims, nil
}

// RevokeJTI immediately denylists jti (design doc: revoked tokens rejected
// on every subsequent request, not just the next one) and persists the
// revocation so it survives a restart.
func (a *AuthServer) RevokeJTI(ctx context.Context, jti string, expiresAt time.Time) error {
	return a.denylist.revoke(ctx, jti, expiresAt)
}

func (a *AuthServer) mintAccessToken(sub, act, node string, ttl time.Duration) (signed string, claims *Claims, err error) {
	jti, err := randomID()
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	claims = &Claims{
		Act:   act,
		Scope: "mcp:invoke", // placeholder scope until Phase 3's policy engine has real scopes to grant
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{a.resourceURI(node)},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	signed, err = a.keys.sign(claims, typAccess)
	return signed, claims, err
}

// mintAdminAccessToken mirrors mintAccessToken, scoped to adminResourceURI
// instead of a node, and always sub'd to an agent (issue #13: the admin
// API's service-to-service leg is NHI-only -- the human behind the
// request is established separately, via live introspection, not by this
// token). Same NHI TTL posture as an ordinary agent token.
func (a *AuthServer) mintAdminAccessToken(sub string) (signed string, claims *Claims, err error) {
	jti, err := randomID()
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	claims = &Claims{
		Scope: "admin:manage",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.issuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{a.adminResourceURI()},
			ExpiresAt: jwt.NewNumericDate(now.Add(a.nhiTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	signed, err = a.keys.sign(claims, typAccess)
	return signed, claims, err
}

func (a *AuthServer) mintSessionToken(username string) (string, error) {
	jti, err := randomID()
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    a.issuer,
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(now.Add(a.sessionTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	return a.keys.sign(claims, typSession)
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ServeJWKS publishes every currently-trusted verification key.
func (a *AuthServer) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.keys.JWKS())
}

// ServeProtectedResourceMetadata implements RFC 9728 per node:
// /.well-known/oauth-protected-resource/{node}.
func (a *AuthServer) ServeProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource/")
	if _, ok := a.nodes[node]; !ok {
		http.NotFound(w, r)
		return
	}
	profiles := []string{}
	if a.idpTrust != nil && a.idpTrust.HasAny() {
		profiles = append(profiles, idJAGGrantProfile)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":                               a.resourceURI(node),
		"authorization_servers":                  []string{a.issuer},
		"bearer_methods_supported":               []string{"header"},
		"authorization_grant_profiles_supported": profiles,
	})
}

// ServeToken implements POST /token for all three grants this phase
// supports: client_credentials (NHI), and the internal login/session pair
// (Mode A humans).
func (a *AuthServer) ServeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "could not parse form body")
		return
	}

	resource := r.FormValue("resource")
	if a.isAdminResource(resource) {
		// The admin resource only ever supports client_credentials --
		// admin API access is NHI-only at the token layer (the human
		// behind a request is established separately, via live
		// introspection, not by minting them a node-shaped Mode A/B
		// token for a resource that isn't a real MCP node).
		if r.FormValue("grant_type") != grantClientCredentials {
			writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "the admin resource only supports client_credentials")
			return
		}
		a.handleAdminClientCredentials(w, r)
		return
	}

	node, ok := a.resolveNode(resource)
	if !ok {
		writeTokenError(w, http.StatusBadRequest, "invalid_target", "resource must name a registered node")
		return
	}

	switch r.FormValue("grant_type") {
	case grantClientCredentials:
		a.handleClientCredentials(w, r, node)
	case grantJWTBearer:
		a.handleJWTBearer(w, r, node)
	case grantLogin:
		a.handleLogin(w, r, node)
	case grantSession:
		a.handleSession(w, r, node)
	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "unknown grant_type")
	}
}

func (a *AuthServer) handleClientCredentials(w http.ResponseWriter, r *http.Request, node string) {
	clientID, secret := clientCredentialsFromRequest(r)
	agent, err := a.identity.AuthenticateAgent(r.Context(), clientID, secret)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}
	signed, claims, err := a.mintAccessToken("agent:"+agent.ClientID, "", node, a.nhiTTL)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to mint token")
		return
	}
	writeTokenResponse(w, signed, claims, "")
}

// handleAdminClientCredentials mints an AdminResource-scoped token
// (issue #13) -- same credential check as an ordinary NHI, plus one more
// gate ordinary node tokens don't have: the authenticated agent's
// client_id must be in the config-designated allowlist. A non-
// allowlisted (but otherwise valid) agent gets the exact same
// invalid_client response as a wrong secret -- "this agent exists but
// isn't allowed to mint admin tokens" must never be distinguishable from
// "these credentials don't work at all," the same non-enumeration
// posture AuthenticateAgent already takes.
func (a *AuthServer) handleAdminClientCredentials(w http.ResponseWriter, r *http.Request) {
	clientID, secret := clientCredentialsFromRequest(r)
	agent, err := a.identity.AuthenticateAgent(r.Context(), clientID, secret)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}
	if _, allowed := a.adminIntegrationClientIDs[agent.ClientID]; !allowed {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")
		return
	}
	signed, claims, err := a.mintAdminAccessToken("agent:" + agent.ClientID)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to mint token")
		return
	}
	writeTokenResponse(w, signed, claims, "")
}

// handleJWTBearer implements RFC 7523's JWT-bearer grant for Mode B
// (issue #5): the assertion is a real external ID-JAG, already validated
// by the customer's IdP via RFC 8693 token exchange before it ever reaches
// this gateway. This handler's job is narrower: confirm the assertion is
// genuinely from a trusted issuer and bound to this gateway (idptrust),
// enforce its one-time-use jti, JIT-resolve-or-create the local user, and
// mint the exact same shape of access token every other grant already
// produces -- no new minting logic, no new claim shape (story 13).
func (a *AuthServer) handleJWTBearer(w http.ResponseWriter, r *http.Request, node string) {
	if a.idpTrust == nil {
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "no trusted external IdP is configured")
		return
	}
	assertion := r.FormValue("assertion")
	if assertion == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "missing assertion")
		return
	}

	claims, err := a.idpTrust.Validate(assertion)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "invalid ID-JAG assertion")
		return
	}

	// One-time-use (story 7): atomically check-and-mark so two concurrent
	// redemptions of a captured assertion can't both slip through the
	// same TOCTOU gap this closes for access-token revocation elsewhere.
	fresh, err := a.denylist.tryConsume(r.Context(), claims.ID, claims.ExpiresAt.Time)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to record assertion use")
		return
	}
	if !fresh {
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "assertion already used")
		return
	}

	user, err := a.identity.ResolveOrCreateExternalUser(r.Context(), claims.Issuer, claims.Subject)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to resolve user")
		return
	}

	signed, accessClaims, err := a.mintAccessToken("user:"+user.Username, claims.Act, node, a.humanTTL)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to mint token")
		return
	}
	writeTokenResponse(w, signed, accessClaims, "")
}

func (a *AuthServer) handleLogin(w http.ResponseWriter, r *http.Request, node string) {
	username, password := r.FormValue("username"), r.FormValue("password")
	user, err := a.identity.Authenticate(r.Context(), username, password)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "invalid username or password")
		return
	}
	signed, claims, err := a.mintAccessToken("user:"+user.Username, "", node, a.humanTTL)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to mint token")
		return
	}
	sessionToken, err := a.mintSessionToken(user.Username)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to mint session")
		return
	}
	// MaxAge matches a.sessionTTL -- without it this was a session-only
	// cookie the browser drops on close, unexpectedly shortening how
	// long a human can silently re-mint tokens versus what the signed
	// session_token itself actually allows for. Secure is conditional on
	// the request having actually arrived over TLS: unconditionally true
	// would silently break local/dev deployments with no TLS
	// termination, unconditionally false would let the cookie leak over
	// a later cleartext connection once this gateway is deployed behind
	// real TLS.
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: sessionToken,
		Path: "/token", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(a.sessionTTL.Seconds()), Secure: r.TLS != nil,
	})
	writeTokenResponse(w, signed, claims, sessionToken)
}

func (a *AuthServer) handleSession(w http.ResponseWriter, r *http.Request, node string) {
	sessionToken := sessionTokenFromRequest(r)
	if sessionToken == "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "missing session_token")
		return
	}
	claims, err := parseAndVerify(a.keys, sessionToken, typSession)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "invalid or expired session")
		return
	}
	// Re-resolve against the store rather than trusting the session
	// token's claims alone -- a user deleted after the session was minted
	// must not be able to keep silently re-minting access tokens off it.
	user, err := a.identity.GetUser(r.Context(), claims.Subject)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_grant", "session's user no longer exists")
		return
	}
	signed, accessClaims, err := a.mintAccessToken("user:"+user.Username, "", node, a.humanTTL)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to mint token")
		return
	}
	writeTokenResponse(w, signed, accessClaims, "")
}

func clientCredentialsFromRequest(r *http.Request) (clientID, secret string) {
	if id, sec, ok := r.BasicAuth(); ok {
		return id, sec
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

func sessionTokenFromRequest(r *http.Request) string {
	if v := r.FormValue("session_token"); v != "" {
		return v
	}
	if c, err := r.Cookie(sessionCookieName); err == nil {
		return c.Value
	}
	return ""
}

func writeTokenResponse(w http.ResponseWriter, accessToken string, claims *Claims, sessionToken string) {
	body := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(claims.ExpiresAt.Time).Seconds()),
		"scope":        claims.Scope,
	}
	if sessionToken != "" {
		body["session_token"] = sessionToken
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func writeTokenError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}
