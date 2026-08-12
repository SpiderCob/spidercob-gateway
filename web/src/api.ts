// Thin fetch wrapper against the gateway's /admin/* JSON API (issue
// #13/#15) and its browser-facing session endpoints (issue #17). No
// bearer token is ever attached here -- authentication is entirely the
// HttpOnly session cookie the browser already sends automatically
// (credentials: 'include'), the whole point of the cookie-based trust
// path this issue adds alongside the existing service-to-service one.

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'include',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    let message = `${method} ${path} failed with ${res.status}`
    try {
      const parsed = (await res.json()) as { error?: { message?: string } }
      if (parsed.error?.message) message = parsed.error.message
    } catch {
      // Response body wasn't JSON (or was empty) -- fall back to the
      // generic message above rather than failing the error path itself.
    }
    throw new ApiError(res.status, message)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

// --- Session (issue #17) ---

export interface WhoAmI {
  username: string
  role: string
}

export function login(spiderSnoopSessionToken: string): Promise<WhoAmI> {
  return request<WhoAmI>('POST', '/admin/ui/session', { spider_snoop_session_token: spiderSnoopSessionToken })
}

export function whoami(): Promise<WhoAmI> {
  return request<WhoAmI>('GET', '/admin/ui/session')
}

export function logout(): Promise<void> {
  return request<void>('DELETE', '/admin/ui/session')
}

// --- Agents ---

export interface Agent {
  client_id: string
  name: string
  created_at: string
  revoked_at?: string
}

export interface CreatedAgent {
  client_id: string
  secret: string
  name: string
}

export function listAgents(): Promise<Agent[]> {
  return request<Agent[]>('GET', '/admin/agents')
}

export function createAgent(name: string): Promise<CreatedAgent> {
  return request<CreatedAgent>('POST', '/admin/agents', { name })
}

export function revokeAgent(clientId: string): Promise<void> {
  return request<void>('DELETE', `/admin/agents/${encodeURIComponent(clientId)}`)
}

// --- Groups ---

export interface Group {
  name: string
}

export function listGroups(): Promise<Group[]> {
  return request<Group[]>('GET', '/admin/groups')
}

export function createGroup(name: string): Promise<Group> {
  return request<Group>('POST', '/admin/groups', { name })
}

export function deleteGroup(name: string): Promise<void> {
  return request<void>('DELETE', `/admin/groups/${encodeURIComponent(name)}`)
}

export type MemberType = 'user' | 'agent'

export function addGroupMember(group: string, type: MemberType, identifier: string): Promise<void> {
  return request<void>('POST', `/admin/groups/${encodeURIComponent(group)}/members`, { type, identifier })
}

export function removeGroupMember(group: string, type: MemberType, identifier: string): Promise<void> {
  return request<void>(
    'DELETE',
    `/admin/groups/${encodeURIComponent(group)}/members/${type}/${encodeURIComponent(identifier)}`,
  )
}

// --- Policies ---

export type RuleType = 'allow' | 'deny'

export interface PolicyRule {
  group: string
  node: string
  rule_type: RuleType
  methods?: string[]
  tools?: string[]
  rate_limit_max_calls?: number
  rate_limit_window_seconds?: number
  block_on_scan_flag?: boolean
}

export function listPolicies(): Promise<PolicyRule[]> {
  return request<PolicyRule[]>('GET', '/admin/policies')
}

export function replacePolicies(rules: PolicyRule[]): Promise<void> {
  return request<void>('PUT', '/admin/policies', rules)
}

// --- Nodes (issue #19: cookie-authenticated same as everything above) ---

export type Transport = 'streamable_http' | 'stdio'

export interface Node {
  name: string
  transport: Transport
  upstream_url?: string
  command?: string
  args?: string[]
  pin_refresh_interval_seconds?: number
  source: 'config' | 'admin'
  created_at: string
}

export interface CreateNodeInput {
  name: string
  transport: Transport
  upstream_url?: string
  command?: string
  args?: string[]
  pin_refresh_interval_seconds?: number
}

export function listNodes(): Promise<Node[]> {
  return request<Node[]>('GET', '/admin/nodes')
}

export function createNode(input: CreateNodeInput): Promise<Node> {
  return request<Node>('POST', '/admin/nodes', input)
}

export function deleteNode(name: string): Promise<void> {
  return request<void>('DELETE', `/admin/nodes/${encodeURIComponent(name)}`)
}

// --- Audit (issue #25) ---

export interface AuditRecord {
  id: number
  ts: string
  actor_nhi_subject?: string
  actor_human_username: string
  actor_human_role: string
  action: string
  resource: string
  prev_hash: string
  hash: string
}

// listAuditRecords fetches one page, most-recent-first. beforeID
// omitted (or 0) starts from the most recent record; pass the last
// record's id from a previous page to fetch older entries -- the same
// "load older" pattern the admin UI's Audit screen uses to append
// rather than replace what's already shown.
export function listAuditRecords(limit?: number, beforeID?: number): Promise<AuditRecord[]> {
  const params = new URLSearchParams()
  if (limit) params.set('limit', String(limit))
  if (beforeID) params.set('before_id', String(beforeID))
  const qs = params.toString()
  return request<AuditRecord[]>('GET', `/admin/audit${qs ? `?${qs}` : ''}`)
}

// --- Sessions (issue #35, kill-session) ---
//
// A live, traffic-facing view -- read straight from the running gateway
// process, not stored -- deliberately distinct from the session/whoami
// endpoints above, which are about *this browser's own admin-UI login*,
// not the MCP sessions clients actually use the gateway for.

export interface Session {
  id: string
  node: string
  principal: string
  idle_since: string
}

export function listSessions(): Promise<Session[]> {
  return request<Session[]>('GET', '/admin/sessions')
}

export function killSession(id: string): Promise<void> {
  return request<void>('DELETE', `/admin/sessions/${encodeURIComponent(id)}`)
}

// --- Config snippet generator (issue #37) ---
//
// mintNodeToken calls the gateway's own public POST /token endpoint
// directly -- the exact same client_credentials grant every NHI agent
// already authenticates with, invoked here with a client_id/secret pair
// the browser already holds in memory from a just-completed createAgent
// response. Deliberately NOT routed through request() above: /token is
// form-urlencoded and cookie-free (client_credentials needs no prior
// admin session -- the secret itself is the credential), and its error
// shape is the OAuth-standard {error, error_description}, not adminapi's
// {error: {message}}.

export interface MintedToken {
  access_token: string
  expires_in: number
}

export async function mintNodeToken(clientId: string, clientSecret: string, node: string): Promise<MintedToken> {
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
    resource: node,
  })
  const res = await fetch('/token', { method: 'POST', body })

  let parsed: { access_token?: string; expires_in?: number; error?: string; error_description?: string } = {}
  try {
    parsed = await res.json()
  } catch {
    // Response body wasn't JSON (or was empty) -- fall back to the
    // generic message below rather than failing the error path itself.
  }
  if (!res.ok || !parsed.access_token) {
    const message = parsed.error_description || parsed.error || `failed to mint a token (status ${res.status})`
    throw new ApiError(res.status, message)
  }
  return { access_token: parsed.access_token, expires_in: parsed.expires_in ?? 0 }
}
