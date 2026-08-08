package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/identity"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// HumanSessionHeader carries the acting human's own spider-snoop session
// token on every /admin/* request -- deliberately not Authorization,
// which is already spoken for by the service-to-service NHI token (issue
// #13: both checks are independent and both required, see Gate).
const HumanSessionHeader = "X-Spidercob-Admin-Session"

// AdminClaims is the subset of a validated admin-audience token's claims
// this package needs. Defined here, not in internal/authserver, so this
// package's dependency surface stays minimal -- mirrors internal/proxy's
// AuthClaims/TokenValidator pattern exactly.
type AdminClaims struct {
	Subject string // sub: "agent:<client_id>" of the calling NHI
}

// AdminTokenValidator is what adminapi needs from an authserver: given an
// admin-audience bearer token, either the validated NHI principal or an
// error. main.go is the only place that needs to know an
// *authserver.AuthServer actually implements this.
type AdminTokenValidator interface {
	ValidateAdminAccessToken(token string) (AdminClaims, error)
}

// adminIdentityCtxKey is the context key the Gate stamps a successfully-
// authenticated request's dual identity under, for logging.
type adminIdentityCtxKey struct{}

type adminIdentity struct {
	nhiSubject    string
	humanUsername string
	humanRole     string
}

// Config is AdminAPI's construction input. All four fields are required
// -- New fails loudly rather than building a partially-wired API that
// would panic on first use.
type Config struct {
	Store        store.Store
	Identity     *identity.Service
	Authn        AdminTokenValidator
	Introspector SpiderSnoopIntrospector
}

// AdminAPI serves the gateway's HTTP admin surface (issue #13).
type AdminAPI struct {
	store        store.Store
	identity     *identity.Service
	authn        AdminTokenValidator
	introspector SpiderSnoopIntrospector
}

// New builds an AdminAPI from cfg.
func New(cfg Config) (*AdminAPI, error) {
	if cfg.Store == nil || cfg.Identity == nil || cfg.Authn == nil || cfg.Introspector == nil {
		return nil, fmt.Errorf("adminapi: Store, Identity, Authn, and Introspector are all required")
	}
	return &AdminAPI{
		store:        cfg.Store,
		identity:     cfg.Identity,
		authn:        cfg.Authn,
		introspector: cfg.Introspector,
	}, nil
}

// Routes returns every /admin/* endpoint this package serves. Uses Go's
// method- and path-parameter-aware ServeMux patterns (Go 1.22+) --
// genuinely path-parameterized REST routes (a group name, a client_id, a
// membership type+identifier), unlike this repo's other handlers, which
// are either fixed paths or do their own prefix-stripping because they
// never needed more than that.
func (a *AdminAPI) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/agents", a.gate(a.listAgents))
	mux.HandleFunc("POST /admin/agents", a.gate(a.createAgent))
	mux.HandleFunc("DELETE /admin/agents/{client_id}", a.gate(a.revokeAgent))

	mux.HandleFunc("GET /admin/groups", a.gate(a.listGroups))
	mux.HandleFunc("POST /admin/groups", a.gate(a.createGroup))
	mux.HandleFunc("DELETE /admin/groups/{name}", a.gate(a.deleteGroup))
	mux.HandleFunc("POST /admin/groups/{name}/members", a.gate(a.addGroupMember))
	mux.HandleFunc("DELETE /admin/groups/{name}/members/{type}/{identifier}", a.gate(a.removeGroupMember))

	mux.HandleFunc("GET /admin/policies", a.gate(a.listPolicies))
	mux.HandleFunc("PUT /admin/policies", a.gate(a.replacePolicies))

	mux.HandleFunc("GET /admin/nodes", a.gate(a.listNodes))
	mux.HandleFunc("POST /admin/nodes", a.gate(a.createNode))
	mux.HandleFunc("DELETE /admin/nodes/{name}", a.gate(a.deleteNode))
	return mux
}

// gate composes both of issue #13's independent trust checks, fail-
// static throughout: an NHI-token error, a missing/empty human-session
// header, an introspection error, or a non-admin role all deny. Neither
// check alone is sufficient -- both must pass before next runs.
func (a *AdminAPI) gate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nhiToken, ok := bearerToken(r)
		if !ok {
			writeAdminError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
			return
		}
		claims, err := a.authn.ValidateAdminAccessToken(nhiToken)
		if err != nil {
			writeAdminError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}

		humanToken := r.Header.Get(HumanSessionHeader)
		if humanToken == "" {
			writeAdminError(w, http.StatusUnauthorized, "missing "+HumanSessionHeader+" header")
			return
		}
		result, err := a.introspector.Introspect(r.Context(), humanToken)
		if err != nil {
			// Fail closed on an introspection error (spider-snoop
			// unreachable, timed out, or returned something unexpected)
			// -- never treat "we couldn't check" as "it's fine."
			writeAdminError(w, http.StatusServiceUnavailable, "failed to verify admin session")
			return
		}
		if !isAdminRole(result.Role) {
			writeAdminError(w, http.StatusForbidden, "session does not have admin access")
			return
		}

		ident := adminIdentity{nhiSubject: claims.Subject, humanUsername: result.Username, humanRole: result.Role}
		next(w, r.WithContext(context.WithValue(r.Context(), adminIdentityCtxKey{}, ident)))
	}
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, prefix) {
		return "", false
	}
	return strings.TrimPrefix(authz, prefix), true
}

// logAdminAction records every successful admin mutation with both
// halves of the request's identity (story 22) -- a queryable trail even
// before internal/audit exists.
func logAdminAction(r *http.Request, action, resource string) {
	ident, _ := r.Context().Value(adminIdentityCtxKey{}).(adminIdentity)
	slog.Info("admin action",
		"nhi_subject", ident.nhiSubject,
		"admin_username", ident.humanUsername,
		"admin_role", ident.humanRole,
		"action", action, "resource", resource)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAdminError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"code": status, "message": message},
	})
}

// --- Agents ---

type agentResponse struct {
	ClientID  string  `json:"client_id"`
	Name      string  `json:"name"`
	CreatedAt string  `json:"created_at"`
	RevokedAt *string `json:"revoked_at,omitempty"`
}

func toAgentResponse(a store.Agent) agentResponse {
	resp := agentResponse{ClientID: a.ClientID, Name: a.Name, CreatedAt: a.CreatedAt.Format(time.RFC3339)}
	if a.RevokedAt != nil {
		s := a.RevokedAt.Format(time.RFC3339)
		resp.RevokedAt = &s
	}
	return resp
}

func (a *AdminAPI) listAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := a.store.ListAgents(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}
	out := make([]agentResponse, 0, len(agents))
	for _, ag := range agents {
		out = append(out, toAgentResponse(ag))
	}
	writeJSON(w, http.StatusOK, out)
}

type createAgentRequest struct {
	Name string `json:"name"`
}

type createAgentResponse struct {
	ClientID string `json:"client_id"`
	// Secret is returned exactly once, the same contract
	// identity.Service.CreateAgent already documents -- only its hash is
	// ever persisted, so it cannot be recovered later, only rotated
	// (create a new agent).
	Secret string `json:"secret"`
	Name   string `json:"name"`
}

func (a *AdminAPI) createAgent(w http.ResponseWriter, r *http.Request) {
	var req createAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeAdminError(w, http.StatusBadRequest, "name is required")
		return
	}
	agent, secret, err := a.identity.CreateAgent(r.Context(), req.Name)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to create agent")
		return
	}
	logAdminAction(r, "create_agent", agent.ClientID)
	writeJSON(w, http.StatusCreated, createAgentResponse{ClientID: agent.ClientID, Secret: secret, Name: agent.Name})
}

func (a *AdminAPI) revokeAgent(w http.ResponseWriter, r *http.Request) {
	clientID := r.PathValue("client_id")
	if err := a.store.RevokeAgent(r.Context(), clientID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeAdminError(w, http.StatusNotFound, "agent not found")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "failed to revoke agent")
		return
	}
	logAdminAction(r, "revoke_agent", clientID)
	w.WriteHeader(http.StatusNoContent)
}

// --- Groups ---

type groupResponse struct {
	Name string `json:"name"`
}

func (a *AdminAPI) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := a.store.ListGroups(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to list groups")
		return
	}
	out := make([]groupResponse, 0, len(groups))
	for _, g := range groups {
		out = append(out, groupResponse{Name: g.Name})
	}
	writeJSON(w, http.StatusOK, out)
}

type createGroupRequest struct {
	Name string `json:"name"`
}

func (a *AdminAPI) createGroup(w http.ResponseWriter, r *http.Request) {
	var req createGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeAdminError(w, http.StatusBadRequest, "name is required")
		return
	}
	g, err := a.store.CreateGroup(r.Context(), req.Name)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeAdminError(w, http.StatusConflict, "group already exists")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "failed to create group")
		return
	}
	logAdminAction(r, "create_group", g.Name)
	writeJSON(w, http.StatusCreated, groupResponse{Name: g.Name})
}

func (a *AdminAPI) deleteGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := a.store.DeleteGroup(r.Context(), name); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeAdminError(w, http.StatusNotFound, "group not found")
		case errors.Is(err, store.ErrConflict):
			writeAdminError(w, http.StatusConflict, "group is still referenced by one or more policies")
		default:
			writeAdminError(w, http.StatusInternalServerError, "failed to delete group")
		}
		return
	}
	logAdminAction(r, "delete_group", name)
	w.WriteHeader(http.StatusNoContent)
}

// groupMemberRequest identifies a member by username (Type "user") or
// client_id (Type "agent") -- an external caller naturally knows those,
// not the store's internal numeric IDs.
type groupMemberRequest struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

func (a *AdminAPI) resolveMemberID(ctx context.Context, memberType, identifier string) (id int64, err error) {
	switch memberType {
	case "user":
		u, err := a.store.GetUserByUsername(ctx, identifier)
		if err != nil {
			return 0, err
		}
		return u.ID, nil
	case "agent":
		ag, err := a.store.GetAgentByClientID(ctx, identifier)
		if err != nil {
			return 0, err
		}
		return ag.ID, nil
	default:
		return 0, fmt.Errorf(`type must be "user" or "agent", got %q`, memberType)
	}
}

func (a *AdminAPI) addGroupMember(w http.ResponseWriter, r *http.Request) {
	groupName := r.PathValue("name")
	g, err := a.store.GetGroupByName(r.Context(), groupName)
	if err != nil {
		writeAdminError(w, http.StatusNotFound, "group not found")
		return
	}
	var req groupMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	memberID, err := a.resolveMemberID(r.Context(), req.Type, req.Identifier)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "unknown or invalid member: "+err.Error())
		return
	}
	switch req.Type {
	case "user":
		err = a.store.AssignUserGroup(r.Context(), memberID, g.ID)
	case "agent":
		err = a.store.AssignAgentGroup(r.Context(), memberID, g.ID)
	}
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to assign group membership")
		return
	}
	logAdminAction(r, "add_group_member", fmt.Sprintf("%s:%s:%s", groupName, req.Type, req.Identifier))
	w.WriteHeader(http.StatusNoContent)
}

func (a *AdminAPI) removeGroupMember(w http.ResponseWriter, r *http.Request) {
	groupName := r.PathValue("name")
	memberType := r.PathValue("type")
	identifier := r.PathValue("identifier")

	g, err := a.store.GetGroupByName(r.Context(), groupName)
	if err != nil {
		writeAdminError(w, http.StatusNotFound, "group not found")
		return
	}
	memberID, err := a.resolveMemberID(r.Context(), memberType, identifier)
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, "unknown or invalid member: "+err.Error())
		return
	}
	switch memberType {
	case "user":
		err = a.store.RemoveUserGroup(r.Context(), memberID, g.ID)
	case "agent":
		err = a.store.RemoveAgentGroup(r.Context(), memberID, g.ID)
	}
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to remove group membership")
		return
	}
	logAdminAction(r, "remove_group_member", fmt.Sprintf("%s:%s:%s", groupName, memberType, identifier))
	w.WriteHeader(http.StatusNoContent)
}

// --- Policies ---

type policyRuleRequest struct {
	Group                  string   `json:"group"`
	Node                   string   `json:"node"`
	RuleType               string   `json:"rule_type"`
	Methods                []string `json:"methods,omitempty"`
	Tools                  []string `json:"tools,omitempty"`
	RateLimitMaxCalls      *int     `json:"rate_limit_max_calls,omitempty"`
	RateLimitWindowSeconds *int     `json:"rate_limit_window_seconds,omitempty"`
	BlockOnScanFlag        bool     `json:"block_on_scan_flag,omitempty"`
}

type policyRuleResponse struct {
	Group                  string   `json:"group"`
	Node                   string   `json:"node"`
	RuleType               string   `json:"rule_type"`
	Methods                []string `json:"methods,omitempty"`
	Tools                  []string `json:"tools,omitempty"`
	RateLimitMaxCalls      *int     `json:"rate_limit_max_calls,omitempty"`
	RateLimitWindowSeconds *int     `json:"rate_limit_window_seconds,omitempty"`
	BlockOnScanFlag        bool     `json:"block_on_scan_flag,omitempty"`
}

func (a *AdminAPI) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := a.store.AllPolicies(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to list policies")
		return
	}
	groups, err := a.store.ListGroups(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to resolve group names")
		return
	}
	groupNames := make(map[int64]string, len(groups))
	for _, g := range groups {
		groupNames[g.ID] = g.Name
	}

	out := make([]policyRuleResponse, 0, len(policies))
	for _, p := range policies {
		out = append(out, policyRuleResponse{
			Group: groupNames[p.GroupID], Node: p.Node, RuleType: string(p.RuleType),
			Methods: p.Methods, Tools: p.Tools,
			RateLimitMaxCalls: p.RateLimitMaxCalls, RateLimitWindowSeconds: p.RateLimitWindowSeconds,
			BlockOnScanFlag: p.BlockOnScanFlag,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// replacePolicies reuses store.ReplacePolicies's exact semantics (issue
// #7) -- a full replace, not an incremental diff, the same idempotency
// strategy config.Policies bootstrap already relies on. This is now a
// second caller of that same store method, not a second policy-
// application code path.
func (a *AdminAPI) replacePolicies(w http.ResponseWriter, r *http.Request) {
	var reqs []policyRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&reqs); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	newPolicies := make([]store.NewPolicy, 0, len(reqs))
	for _, pr := range reqs {
		if pr.Group == "" || pr.Node == "" {
			writeAdminError(w, http.StatusBadRequest, "each policy needs group and node")
			return
		}
		if pr.RuleType != "allow" && pr.RuleType != "deny" {
			writeAdminError(w, http.StatusBadRequest, `rule_type must be "allow" or "deny"`)
			return
		}
		g, err := a.store.GetGroupByName(r.Context(), pr.Group)
		if err != nil {
			writeAdminError(w, http.StatusBadRequest, "unknown group: "+pr.Group)
			return
		}
		newPolicies = append(newPolicies, store.NewPolicy{
			GroupID: g.ID, Node: pr.Node, RuleType: store.PolicyRuleType(pr.RuleType),
			Methods: pr.Methods, Tools: pr.Tools,
			RateLimitMaxCalls: pr.RateLimitMaxCalls, RateLimitWindowSeconds: pr.RateLimitWindowSeconds,
			BlockOnScanFlag: pr.BlockOnScanFlag,
		})
	}

	if err := a.store.ReplacePolicies(r.Context(), newPolicies); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to replace policies")
		return
	}
	logAdminAction(r, "replace_policies", fmt.Sprintf("%d rules", len(newPolicies)))
	w.WriteHeader(http.StatusNoContent)
}

// --- Nodes (issue #15) ---

type nodeResponse struct {
	Name                      string   `json:"name"`
	Transport                 string   `json:"transport"`
	UpstreamURL               *string  `json:"upstream_url,omitempty"`
	Command                   *string  `json:"command,omitempty"`
	Args                      []string `json:"args,omitempty"`
	PinRefreshIntervalSeconds *int     `json:"pin_refresh_interval_seconds,omitempty"`
	Source                    string   `json:"source"`
	CreatedAt                 string   `json:"created_at"`
}

func toNodeResponse(n store.Node) nodeResponse {
	return nodeResponse{
		Name: n.Name, Transport: n.Transport, UpstreamURL: n.UpstreamURL, Command: n.Command,
		Args: n.Args, PinRefreshIntervalSeconds: n.PinRefreshIntervalSeconds, Source: n.Source,
		CreatedAt: n.CreatedAt.Format(time.RFC3339),
	}
}

func (a *AdminAPI) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := a.store.ListNodes(r.Context())
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to list nodes")
		return
	}
	out := make([]nodeResponse, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, toNodeResponse(n))
	}
	writeJSON(w, http.StatusOK, out)
}

type createNodeRequest struct {
	Name                      string   `json:"name"`
	Transport                 string   `json:"transport,omitempty"`
	UpstreamURL               string   `json:"upstream_url,omitempty"`
	Command                   string   `json:"command,omitempty"`
	Args                      []string `json:"args,omitempty"`
	PinRefreshIntervalSeconds int      `json:"pin_refresh_interval_seconds,omitempty"`
}

// createNode reuses config.ValidateNode -- the exact per-transport
// validation config.Load already enforces for config.json-declared
// nodes, so the two entry points can never silently diverge on what
// counts as a valid node (story 10). Always creates a "admin"-sourced
// row; a node registered this way is persisted and listed immediately,
// but -- like every node -- only becomes reachable via /mcp/<name>/ or
// mintable via /token after the next gateway restart (story 8; no hot-
// reload yet, MASTER_PLAN.md §6, 2026-08-08).
func (a *AdminAPI) createNode(w http.ResponseWriter, r *http.Request) {
	var req createNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	validated, err := config.ValidateNode(config.Node{
		Name: req.Name, Transport: req.Transport, UpstreamURL: req.UpstreamURL,
		Command: req.Command, Args: req.Args, PinRefreshIntervalSeconds: req.PinRefreshIntervalSeconds,
	})
	if err != nil {
		writeAdminError(w, http.StatusBadRequest, err.Error())
		return
	}

	sn := store.Node{Name: validated.Name, Transport: validated.Transport, Args: validated.Args, Source: store.NodeSourceAdmin}
	if validated.UpstreamURL != "" {
		sn.UpstreamURL = &validated.UpstreamURL
	}
	if validated.Command != "" {
		sn.Command = &validated.Command
	}
	if validated.PinRefreshIntervalSeconds > 0 {
		sn.PinRefreshIntervalSeconds = &validated.PinRefreshIntervalSeconds
	}

	created, err := a.store.CreateNode(r.Context(), sn)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeAdminError(w, http.StatusConflict, "a node with this name already exists")
			return
		}
		writeAdminError(w, http.StatusInternalServerError, "failed to create node")
		return
	}
	logAdminAction(r, "create_node", created.Name)
	writeJSON(w, http.StatusCreated, toNodeResponse(created))
}

// deleteNode refuses to delete a "config"-sourced node (story 5): doing
// so via this API would just have it reappear on the very next restart,
// since config.json is upserted back into the store on every startup.
func (a *AdminAPI) deleteNode(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	existing, err := a.store.GetNodeByName(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		writeAdminError(w, http.StatusNotFound, "node not found")
		return
	}
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to look up node")
		return
	}
	if existing.Source == store.NodeSourceConfig {
		writeAdminError(w, http.StatusConflict, "this node is defined in config.json; remove it there instead")
		return
	}
	if err := a.store.DeleteNode(r.Context(), name); err != nil {
		writeAdminError(w, http.StatusInternalServerError, "failed to delete node")
		return
	}
	logAdminAction(r, "delete_node", name)
	w.WriteHeader(http.StatusNoContent)
}
