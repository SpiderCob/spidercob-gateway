import { useEffect, useState } from 'react'
import {
  ApiError,
  createProxy,
  listProxies,
  revokeProxy,
  type Proxy,
  type CreatedProxy,
} from '../api'

// Proxies (issue #63, design.md §10): a self-hosted fleet control
// plane's other principal kind. Mirrors Agents.tsx's create/list/revoke
// UX and its reveal-once-secret banner exactly. Deliberately does NOT
// yet reuse Agents.tsx's node-selector/token-minting config-snippet
// generator (issue #37) -- that flow mints a real, immediately-usable
// MCP client token against a live node; there is no equivalent live
// thing to hand a proxy yet (no signing keypair, no bundle format, no
// tunnel -- later phases). Showing a "control_plane_url" config snippet
// today that doesn't actually connect to anything would be dishonest UI,
// not a convenience -- add it once that mechanism is real.
export default function Proxies() {
  const [proxies, setProxies] = useState<Proxy[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)
  // justCreated holds a newly-minted proxy's secret for exactly one
  // render cycle's worth of user attention, same contract as Agents.tsx's
  // justCreated -- the backend never re-returns a secret after this
  // response.
  const [justCreated, setJustCreated] = useState<CreatedProxy | null>(null)

  async function refresh() {
    try {
      setProxies(await listProxies())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load proxies')
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
      const created = await createProxy(newName.trim())
      setJustCreated(created)
      setNewName('')
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to create proxy')
    } finally {
      setCreating(false)
    }
  }

  async function handleRevoke(clientId: string) {
    setError(null)
    try {
      await revokeProxy(clientId)
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to revoke proxy')
    }
  }

  async function handleCopyCredentials() {
    if (!justCreated) return
    try {
      await navigator.clipboard.writeText(
        `client_id: ${justCreated.client_id}\nsecret: ${justCreated.secret}`,
      )
    } catch {
      // Clipboard access can fail -- the credentials are still visible
      // and selectable by hand, so this is a silent no-op.
    }
  }

  return (
    <section>
      <h2>Proxies</h2>
      <p className="screen-intro">
        A proxy is a data-plane gateway instance pairing to this control plane. Pairing a proxy
        here reserves its identity; policy sync to a paired proxy lands in a later phase.
      </p>
      {error && <div className="error">{error}</div>}

      {justCreated && (
        <div className="secret-banner">
          <p>
            Proxy <strong>{justCreated.name}</strong> created. Copy this secret now -- it will
            never be shown again:
          </p>
          <code>
            client_id: {justCreated.client_id}
            <br />
            secret: {justCreated.secret}
          </code>
          <button type="button" onClick={() => handleCopyCredentials()}>
            Copy credentials
          </button>
          <button type="button" onClick={() => setJustCreated(null)}>
            I've copied it, dismiss
          </button>
        </div>
      )}

      <form onSubmit={handleCreate} className="inline-form">
        <input
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="new proxy name"
        />
        <button type="submit" disabled={creating || !newName.trim()}>
          Create proxy
        </button>
      </form>

      {proxies === null ? (
        <p>Loading…</p>
      ) : proxies.length === 0 ? (
        <p>No proxies registered yet.</p>
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
            {proxies.map((p) => (
              <tr key={p.client_id} className={p.revoked_at ? 'revoked' : undefined}>
                <td>{p.client_id}</td>
                <td>{p.name}</td>
                <td>{p.created_at}</td>
                <td>{p.revoked_at ? `revoked ${p.revoked_at}` : 'active'}</td>
                <td>
                  {!p.revoked_at && (
                    <button type="button" onClick={() => handleRevoke(p.client_id)}>
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
