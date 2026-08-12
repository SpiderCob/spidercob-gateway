import { useEffect, useState } from 'react'
import {
  ApiError,
  createAgent,
  listAgents,
  listNodes,
  mintNodeToken,
  revokeAgent,
  type Agent,
  type CreatedAgent,
  type Node,
} from '../api'

// buildMCPConfigSnippet renders the shared mcpServers-shaped JSON config
// Claude Desktop, Claude Code, and Cursor all already use for a remote
// (streamable_http) MCP server (issue #37) -- window.location.origin is
// always correct because the admin UI, /token, and /mcp/* are all served
// by this same gateway process on the same origin.
function buildMCPConfigSnippet(node: string, accessToken: string): string {
  const config = {
    mcpServers: {
      [node]: {
        url: `${window.location.origin}/mcp/${node}/`,
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    },
  }
  return JSON.stringify(config, null, 2)
}

export default function Agents() {
  const [agents, setAgents] = useState<Agent[] | null>(null)
  const [nodes, setNodes] = useState<Node[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)
  // justCreated holds a newly-minted agent's secret for exactly one
  // render cycle's worth of user attention -- the backend never
  // re-returns a secret after this response, so once this component
  // unmounts or the admin navigates away, it is genuinely gone (story 9).
  // It's also the only moment a config snippet (issue #37) can ever be
  // generated for this agent, since the snippet needs that same
  // never-recoverable secret to mint a token.
  const [justCreated, setJustCreated] = useState<CreatedAgent | null>(null)

  const [selectedNode, setSelectedNode] = useState('')
  const [mintingSnippet, setMintingSnippet] = useState(false)
  const [snippet, setSnippet] = useState<string | null>(null)
  const [snippetExpiresIn, setSnippetExpiresIn] = useState<number | null>(null)
  const [snippetError, setSnippetError] = useState<string | null>(null)

  function resetSnippetState() {
    setSelectedNode('')
    setSnippet(null)
    setSnippetExpiresIn(null)
    setSnippetError(null)
  }

  async function refresh() {
    try {
      setAgents(await listAgents())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load agents')
    }
  }

  async function refreshNodes() {
    try {
      setNodes(await listNodes())
    } catch {
      // Node listing failing shouldn't block the rest of this screen --
      // the snippet generator below just won't have anything to offer
      // (surfaced as "no nodes registered yet," not a separate error).
      setNodes([])
    }
  }

  useEffect(() => {
    void refresh()
    void refreshNodes()
  }, [])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!newName.trim()) return
    setCreating(true)
    setError(null)
    try {
      const created = await createAgent(newName.trim())
      setJustCreated(created)
      resetSnippetState() // a new agent's reveal must never carry a stale snippet from a previous one
      setNewName('')
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to create agent')
    } finally {
      setCreating(false)
    }
  }

  async function handleRevoke(clientId: string) {
    setError(null)
    try {
      await revokeAgent(clientId)
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to revoke agent')
    }
  }

  async function handleGenerateSnippet() {
    if (!justCreated || !selectedNode) return
    setMintingSnippet(true)
    setSnippetError(null)
    try {
      const token = await mintNodeToken(justCreated.client_id, justCreated.secret, selectedNode)
      setSnippet(buildMCPConfigSnippet(selectedNode, token.access_token))
      setSnippetExpiresIn(token.expires_in)
    } catch (err) {
      setSnippet(null)
      setSnippetExpiresIn(null)
      setSnippetError(err instanceof ApiError ? err.message : 'failed to generate a config snippet')
    } finally {
      setMintingSnippet(false)
    }
  }

  async function handleCopySnippet() {
    if (!snippet) return
    try {
      await navigator.clipboard.writeText(snippet)
    } catch {
      // Clipboard access can fail (permissions, a non-secure context,
      // etc.) -- the snippet is still visible and selectable by hand, so
      // this is a silent no-op, not an error worth surfacing.
    }
  }

  return (
    <section>
      <h2>Agents</h2>
      {error && <div className="error">{error}</div>}

      {justCreated && (
        <div className="secret-banner">
          <p>
            Agent <strong>{justCreated.name}</strong> created. Copy this secret now -- it will
            never be shown again:
          </p>
          <code>
            client_id: {justCreated.client_id}
            <br />
            secret: {justCreated.secret}
          </code>

          <div className="config-snippet">
            <p>Get a ready-to-paste config for an MCP client (Claude Desktop, Claude Code, Cursor):</p>
            {nodes === null ? (
              <p>Loading nodes…</p>
            ) : nodes.length === 0 ? (
              <p>No nodes registered yet -- register one first to generate a snippet.</p>
            ) : (
              <div className="inline-form">
                <select value={selectedNode} onChange={(e) => setSelectedNode(e.target.value)}>
                  <option value="">choose a node…</option>
                  {nodes.map((n) => (
                    <option key={n.name} value={n.name}>
                      {n.name}
                    </option>
                  ))}
                </select>
                <button type="button" onClick={() => handleGenerateSnippet()} disabled={!selectedNode || mintingSnippet}>
                  {mintingSnippet ? 'Generating…' : 'Generate config snippet'}
                </button>
              </div>
            )}

            {snippetError && <div className="error">{snippetError}</div>}

            {snippet && (
              <>
                <pre>
                  <code>{snippet}</code>
                </pre>
                <button type="button" onClick={() => handleCopySnippet()}>
                  Copy snippet
                </button>
                <p className="snippet-expiry">
                  This token expires in {snippetExpiresIn} second{snippetExpiresIn === 1 ? '' : 's'} -- once it
                  does, generate a fresh snippet (or mint a new token the same way) rather than reusing this
                  one. This is a fast-start convenience, not a permanent credential.
                </p>
              </>
            )}
          </div>

          <button
            type="button"
            onClick={() => {
              setJustCreated(null)
              resetSnippetState()
            }}
          >
            I've copied it, dismiss
          </button>
        </div>
      )}

      <form onSubmit={handleCreate} className="inline-form">
        <input
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="new agent name"
        />
        <button type="submit" disabled={creating || !newName.trim()}>
          Create agent
        </button>
      </form>

      {agents === null ? (
        <p>Loading…</p>
      ) : agents.length === 0 ? (
        <p>No agents registered yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Client ID</th>
              <th>Name</th>
              <th>Created</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.client_id} className={a.revoked_at ? 'revoked' : undefined}>
                <td>{a.client_id}</td>
                <td>{a.name}</td>
                <td>{a.created_at}</td>
                <td>{a.revoked_at ? `revoked ${a.revoked_at}` : 'active'}</td>
                <td>
                  {!a.revoked_at && (
                    <button type="button" onClick={() => handleRevoke(a.client_id)}>
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
