import { useEffect, useState } from 'react'
import { ApiError, createAgent, listAgents, revokeAgent, type Agent, type CreatedAgent } from '../api'

export default function Agents() {
  const [agents, setAgents] = useState<Agent[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)
  // justCreated holds a newly-minted agent's secret for exactly one
  // render cycle's worth of user attention -- the backend never
  // re-returns a secret after this response, so once this component
  // unmounts or the admin navigates away, it is genuinely gone (story 9).
  const [justCreated, setJustCreated] = useState<CreatedAgent | null>(null)

  async function refresh() {
    try {
      setAgents(await listAgents())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load agents')
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!newName.trim()) return
    setCreating(true)
    setError(null)
    try {
      const created = await createAgent(newName.trim())
      setJustCreated(created)
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
          <button type="button" onClick={() => setJustCreated(null)}>
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
