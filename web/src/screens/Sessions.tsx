import { useEffect, useState } from 'react'
import { ApiError, killSession, listSessions, type Session } from '../api'

export default function Sessions() {
  const [sessions, setSessions] = useState<Session[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function refresh() {
    try {
      setSessions(await listSessions())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load sessions')
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  async function handleKill(id: string) {
    setError(null)
    try {
      await killSession(id)
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to end session')
    }
  }

  return (
    <section>
      <h2>Sessions</h2>
      {error && <div className="error">{error}</div>}

      {sessions === null ? (
        <p>Loading…</p>
      ) : sessions.length === 0 ? (
        <p>No sessions currently live.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Session ID</th>
              <th>Node</th>
              <th>Principal</th>
              <th>Idle since</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s) => (
              <tr key={s.id}>
                <td>{s.id}</td>
                <td>{s.node}</td>
                <td>{s.principal}</td>
                <td>{s.idle_since}</td>
                <td>
                  <button type="button" onClick={() => handleKill(s.id)}>
                    Kill
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
