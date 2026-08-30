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
    const name = draft.name.trim()
    if (!name) return
    const upstreamUrl = draft.upstream_url?.trim()
    const command = draft.command?.trim()
    if (draft.transport === 'streamable_http' && !upstreamUrl) {
      setError('streamable_http nodes need an upstream URL')
      return
    }
    if (draft.transport === 'stdio' && !command) {
      setError('stdio nodes need a command')
      return
    }
    // Send a trimmed, transport-scoped payload rather than the raw draft:
    // draft.name passing this function's own non-empty check doesn't mean
    // it's free of leading/trailing whitespace (the backend's
    // config.ValidateNode rejects that), and switching transports in the
    // form leaves the *other* transport's now-irrelevant fields
    // (upstream_url on a stdio node, or command/args on a streamable_http
    // one) sitting in draft state -- they must not get persisted.
    const payload: CreateNodeInput =
      draft.transport === 'streamable_http'
        ? {
            name,
            transport: 'streamable_http',
            upstream_url: upstreamUrl,
            pin_refresh_interval_seconds: draft.pin_refresh_interval_seconds,
          }
        : {
            name,
            transport: 'stdio',
            command,
            args: draft.args,
            pin_refresh_interval_seconds: draft.pin_refresh_interval_seconds,
          }
    setCreating(true)
    setError(null)
    try {
      await createNode(payload)
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
