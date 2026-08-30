package adminmcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sumeetgp/spidercob-gateway/internal/pin"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// textResult wraps v (any JSON-marshalable value) as a single text
// content block -- the same "Out = any, hand-build Content" idiom this
// repo's own MCP-server test fixtures (echoserver et al.) already use,
// applied here to structured read results rather than a plain string.
func textResult(v any) (*mcp.CallToolResult, any, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
}

// describeResult wraps a plain human-readable description as a text
// content block -- the "not yet confirmed, here's what would happen"
// half of the confirm-required pattern.
func describeResult(text string) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

func (s *Server) registerTools() {
	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_nodes",
		Description: "List every MCP node currently registered on this gateway.",
	}, s.listNodes)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "query_audit",
		Description: "Read the gateway's tamper-evident audit trail, most-recent first.",
	}, s.queryAudit)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name:        "list_quarantined_tools",
		Description: "List every tool, across every node, currently quarantined for a rug-pull (a definition change since it was first observed).",
	}, s.listQuarantinedTools)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: "grant_access",
		Description: "Grant a group access to a node (optionally restricted to specific methods/tools). " +
			"Call once to preview what this would do; call again with confirm=true to actually apply it.",
	}, s.grantAccess)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: "revoke_access",
		Description: "Revoke a group's existing access grant to a node. " +
			"Call once to preview what this would do; call again with confirm=true to actually apply it.",
	}, s.revokeAccess)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: "kill_session",
		Description: "End one live MCP session immediately. " +
			"Call once to preview what this would do; call again with confirm=true to actually apply it.",
	}, s.killSession)

	mcp.AddTool(s.mcp, &mcp.Tool{
		Name: "approve_tool",
		Description: "Re-approve a quarantined tool, trusting its current, freshly-observed definition. " +
			"Call once to preview what this would do; call again with confirm=true to actually apply it.",
	}, s.approveTool)
}

// --- list_nodes ---

type listNodesInput struct{}

func (s *Server) listNodes(ctx context.Context, _ *mcp.CallToolRequest, _ listNodesInput) (*mcp.CallToolResult, any, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, nil, err
	}
	if nodes == nil {
		nodes = []store.Node{} // "[]", not the less legible JSON "null", for zero results
	}
	return textResult(nodes)
}

// --- query_audit ---

type queryAuditInput struct {
	Limit    int   `json:"limit,omitempty" jsonschema:"maximum records to return; defaults to a small page if omitted"`
	BeforeID int64 `json:"before_id,omitempty" jsonschema:"pagination cursor: return records older than this id"`
}

func (s *Server) queryAudit(ctx context.Context, _ *mcp.CallToolRequest, in queryAuditInput) (*mcp.CallToolResult, any, error) {
	records, err := s.store.ListAuditRecordsPage(ctx, in.Limit, in.BeforeID)
	if err != nil {
		return nil, nil, err
	}
	if records == nil {
		records = []store.AuditLogEntry{} // "[]", not "null", for zero results
	}
	return textResult(records)
}

// --- list_quarantined_tools ---

type listQuarantinedToolsInput struct{}

func (s *Server) listQuarantinedTools(ctx context.Context, _ *mcp.CallToolRequest, _ listQuarantinedToolsInput) (*mcp.CallToolResult, any, error) {
	pins, err := s.store.ListQuarantinedToolPins(ctx)
	if err != nil {
		return nil, nil, err
	}
	if pins == nil {
		pins = []store.ToolPin{} // "[]", not "null", for zero results
	}
	return textResult(pins)
}

// --- grant_access / revoke_access ---

type grantAccessInput struct {
	Group   string   `json:"group" jsonschema:"the group name to grant access to"`
	Node    string   `json:"node" jsonschema:"the node name to grant access to"`
	Methods []string `json:"methods,omitempty" jsonschema:"JSON-RPC methods to allow; omit for every method"`
	Tools   []string `json:"tools,omitempty" jsonschema:"tool names to allow for tools/call; omit for every tool"`
	Confirm bool     `json:"confirm,omitempty" jsonschema:"must be true to actually apply the grant; omit or false to preview it"`
}

func (s *Server) grantAccess(ctx context.Context, _ *mcp.CallToolRequest, in grantAccessInput) (*mcp.CallToolResult, any, error) {
	group, err := s.store.GetGroupByName(ctx, in.Group)
	if err != nil {
		return nil, nil, fmt.Errorf("group %q: %w", in.Group, err)
	}
	description := fmt.Sprintf("This will grant group %q access to node %q", in.Group, in.Node)
	if len(in.Methods) > 0 {
		description += fmt.Sprintf(", restricted to methods %v", in.Methods)
	}
	if len(in.Tools) > 0 {
		description += fmt.Sprintf(", restricted to tools %v", in.Tools)
	}
	description += ". Call again with confirm=true to apply it."
	if !in.Confirm {
		return describeResult(description)
	}

	if err := s.upsertAllowPolicy(ctx, group.ID, in.Node, in.Methods, in.Tools); err != nil {
		return nil, nil, err
	}
	s.auditAction(ctx, "mcp_grant_access", fmt.Sprintf("%s:%s", in.Group, in.Node))
	return describeResult(fmt.Sprintf("Granted group %q access to node %q.", in.Group, in.Node))
}

type revokeAccessInput struct {
	Group   string `json:"group" jsonschema:"the group name to revoke access from"`
	Node    string `json:"node" jsonschema:"the node name to revoke access to"`
	Confirm bool   `json:"confirm,omitempty" jsonschema:"must be true to actually apply the revocation; omit or false to preview it"`
}

func (s *Server) revokeAccess(ctx context.Context, _ *mcp.CallToolRequest, in revokeAccessInput) (*mcp.CallToolResult, any, error) {
	group, err := s.store.GetGroupByName(ctx, in.Group)
	if err != nil {
		return nil, nil, fmt.Errorf("group %q: %w", in.Group, err)
	}
	description := fmt.Sprintf("This will revoke group %q's access grant to node %q. Call again with confirm=true to apply it.", in.Group, in.Node)
	if !in.Confirm {
		return describeResult(description)
	}

	removed, err := s.removeAllowPolicy(ctx, group.ID, in.Node)
	if err != nil {
		return nil, nil, err
	}
	if !removed {
		return describeResult(fmt.Sprintf("Group %q had no access grant to node %q -- nothing to revoke.", in.Group, in.Node))
	}
	s.auditAction(ctx, "mcp_revoke_access", fmt.Sprintf("%s:%s", in.Group, in.Node))
	return describeResult(fmt.Sprintf("Revoked group %q's access to node %q.", in.Group, in.Node))
}

// upsertAllowPolicy adds or updates the one ALLOW rule for (groupID,
// node) -- read-modify-write over store.AllPolicies/ReplacePolicies,
// since no narrower "upsert one rule" store method exists. Every other
// existing rule, for every other group and node, passes through
// completely untouched.
func (s *Server) upsertAllowPolicy(ctx context.Context, groupID int64, node string, methods, tools []string) error {
	existing, err := s.store.AllPolicies(ctx)
	if err != nil {
		return err
	}
	replacement := make([]store.NewPolicy, 0, len(existing)+1)
	found := false
	for _, p := range existing {
		if p.GroupID == groupID && p.Node == node && p.RuleType == store.PolicyAllow {
			found = true
			replacement = append(replacement, store.NewPolicy{
				GroupID: groupID, Node: node, RuleType: store.PolicyAllow,
				Methods: methods, Tools: tools,
				RateLimitMaxCalls: p.RateLimitMaxCalls, RateLimitWindowSeconds: p.RateLimitWindowSeconds,
				BlockOnScanFlag: p.BlockOnScanFlag,
			})
			continue
		}
		replacement = append(replacement, policyToNewPolicy(p))
	}
	if !found {
		replacement = append(replacement, store.NewPolicy{
			GroupID: groupID, Node: node, RuleType: store.PolicyAllow,
			Methods: methods, Tools: tools,
		})
	}
	return s.store.ReplacePolicies(ctx, replacement)
}

// removeAllowPolicy drops the one ALLOW rule for (groupID, node), if any
// exists. removed reports whether there was actually anything to remove
// -- revokeAccess uses this to give an honest "nothing to revoke"
// response instead of claiming a no-op succeeded.
func (s *Server) removeAllowPolicy(ctx context.Context, groupID int64, node string) (removed bool, err error) {
	existing, err := s.store.AllPolicies(ctx)
	if err != nil {
		return false, err
	}
	replacement := make([]store.NewPolicy, 0, len(existing))
	for _, p := range existing {
		if p.GroupID == groupID && p.Node == node && p.RuleType == store.PolicyAllow {
			removed = true
			continue
		}
		replacement = append(replacement, policyToNewPolicy(p))
	}
	if !removed {
		return false, nil
	}
	return true, s.store.ReplacePolicies(ctx, replacement)
}

func policyToNewPolicy(p store.Policy) store.NewPolicy {
	return store.NewPolicy{
		GroupID: p.GroupID, Node: p.Node, RuleType: p.RuleType,
		Methods: p.Methods, Tools: p.Tools,
		RateLimitMaxCalls: p.RateLimitMaxCalls, RateLimitWindowSeconds: p.RateLimitWindowSeconds,
		BlockOnScanFlag: p.BlockOnScanFlag,
	}
}

// --- kill_session ---

type killSessionInput struct {
	SessionID string `json:"session_id" jsonschema:"the live session id to kill"`
	Confirm   bool   `json:"confirm,omitempty" jsonschema:"must be true to actually kill the session; omit or false to preview it"`
}

func (s *Server) killSession(ctx context.Context, _ *mcp.CallToolRequest, in killSessionInput) (*mcp.CallToolResult, any, error) {
	description := fmt.Sprintf("This will immediately end session %q. Call again with confirm=true to apply it.", in.SessionID)
	if !in.Confirm {
		return describeResult(description)
	}
	if err := s.sessions.EndSession(ctx, in.SessionID); err != nil {
		return nil, nil, err
	}
	s.auditAction(ctx, "mcp_kill_session", in.SessionID)
	return describeResult(fmt.Sprintf("Ended session %q.", in.SessionID))
}

// --- approve_tool ---

type approveToolInput struct {
	Node    string `json:"node" jsonschema:"the node the quarantined tool belongs to"`
	Tool    string `json:"tool" jsonschema:"the quarantined tool's name"`
	Confirm bool   `json:"confirm,omitempty" jsonschema:"must be true to actually approve it; omit or false to preview it"`
}

func (s *Server) approveTool(ctx context.Context, _ *mcp.CallToolRequest, in approveToolInput) (*mcp.CallToolResult, any, error) {
	description := fmt.Sprintf(
		"This will re-fetch %s/%s's current live definition and, if reachable, trust it as the new baseline, clearing the quarantine. Call again with confirm=true to apply it.",
		in.Node, in.Tool)
	if !in.Confirm {
		return describeResult(description)
	}

	tools, err := s.fetch(ctx, in.Node)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching %s's current tools to approve %s: %w", in.Node, in.Tool, err)
	}
	found := false
	var current pin.ToolDef
	for _, t := range tools {
		if t.Name == in.Tool {
			current = t
			found = true
			break
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("tool %q is not currently present on node %q -- cannot approve a tool that no longer exists", in.Tool, in.Node)
	}
	if err := s.pins.Approve(ctx, in.Node, current); err != nil {
		return nil, nil, err
	}
	s.auditAction(ctx, "mcp_approve_tool", fmt.Sprintf("%s/%s", in.Node, in.Tool))
	return describeResult(fmt.Sprintf("Approved %s/%s -- quarantine cleared, re-pinned to its current definition.", in.Node, in.Tool))
}
