import { useEffect, useState } from 'react'
import { ApiError, createNode, deleteNode, listNodes, type CreateNodeInput, type Node, type Transport } from '../api'

function emptyDraft(): CreateNodeInput {
  return { name: '', transport: 'streamable_http' }
}

export default function Nodes() {
  const [nodes, setNodes] = useState<Node[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [draft, setDraft] = useState<CreateNodeInput>(emptyDraft())
  const [creating, setCreating] = useState(false)
  // justRegistered holds the name of a node this browser just created,
  // so the restart-required notice stays attached to that specific row
  // (and to a summary banner) rather than implying every listed node is
  // in the same not-yet-reachable state -- most rows in a real deployment
  // won't be.
  const [justRegistered, setJustRegistered] = useState<string | null>(null)

  async function refresh() {
    try {
      setNodes(await listNodes())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load nodes')
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!draft.name.trim()) return
    if (draft.transport === 'streamable_http' && !draft.upstream_url?.trim()) {
      setError('streamable_http nodes need an upstream URL')
      return
    }
    if (draft.transport === 'stdio' && !draft.command?.trim()) {
      setError('stdio nodes need a command')
      return
    }
    setCreating(true)
    setError(null)
    try {
      const created = await createNode(draft)
      setJustRegistered(created.name)
      setDraft(emptyDraft())
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to create node')
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete(name: string) {
    setError(null)
    try {
      await deleteNode(name)
      if (justRegistered === name) setJustRegistered(null)
      await refresh()
    } catch (err) {
      // A config-sourced node's delete is refused (409) with an
      // explanatory message from the backend -- surfaced verbatim, the
      // same principle the Groups screen already applies to its own
      // "still referenced by a policy" 409.
      setError(err instanceof ApiError ? err.message : 'failed to delete node')
    }
  }

  return (
    <section>
      <h2>Nodes</h2>
      {error && <div className="error">{error}</div>}

      {justRegistered && (
        <div className="restart-banner">
          Node <strong>{justRegistered}</strong> is registered, but it will not route traffic or
          accept a minted token until the gateway is restarted (no hot-reload yet). Restart the
          gateway process, then it will be reachable.
        </div>
      )}

      <form onSubmit={handleCreate} className="inline-form">
        <input
          value={draft.name}
          onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
          placeholder="node name"
        />
        <select
          value={draft.transport}
          onChange={(e) => setDraft((d) => ({ ...d, transport: e.target.value as Transport }))}
        >
          <option value="streamable_http">streamable_http</option>
          <option value="stdio">stdio</option>
        </select>
        {draft.transport === 'streamable_http' ? (
          <input
            value={draft.upstream_url ?? ''}
            onChange={(e) => setDraft((d) => ({ ...d, upstream_url: e.target.value }))}
            placeholder="upstream URL"
          />
        ) : (
          <>
            <input
              value={draft.command ?? ''}
              onChange={(e) => setDraft((d) => ({ ...d, command: e.target.value }))}
              placeholder="command"
            />
            <input
              value={(draft.args ?? []).join(' ')}
              onChange={(e) =>
                setDraft((d) => ({
                  ...d,
                  args: e.target.value ? e.target.value.split(' ').filter(Boolean) : undefined,
                }))
              }
              placeholder="args (space-separated)"
            />
          </>
        )}
        <input
          type="number"
          min={1}
          value={draft.pin_refresh_interval_seconds ?? ''}
          onChange={(e) =>
            setDraft((d) => ({
              ...d,
              pin_refresh_interval_seconds: e.target.value ? Number(e.target.value) : undefined,
            }))
          }
          placeholder="pin refresh interval (s), optional"
        />
        <button type="submit" disabled={creating || !draft.name.trim()}>
          Register node
        </button>
      </form>

      {nodes === null ? (
        <p>Loading…</p>
      ) : nodes.length === 0 ? (
        <p>No nodes registered yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Transport</th>
              <th>Upstream / Command</th>
              <th>Source</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((n) => (
              <tr key={n.name}>
                <td>{n.name}</td>
                <td>{n.transport}</td>
                <td>{n.upstream_url ?? [n.command, ...(n.args ?? [])].filter(Boolean).join(' ')}</td>
                <td>{n.source}</td>
                <td>
                  <button type="button" onClick={() => handleDelete(n.name)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
