import { useEffect, useState } from 'react'
import { ApiError, listAuditRecords, type AuditRecord } from '../api'

const PAGE_SIZE = 20

export default function Audit() {
  const [records, setRecords] = useState<AuditRecord[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  // hasMore is inferred from getting a full page back -- a short page
  // means there's nothing older left to load.
  const [hasMore, setHasMore] = useState(true)

  async function loadFirstPage() {
    try {
      const page = await listAuditRecords(PAGE_SIZE)
      setRecords(page)
      setHasMore(page.length === PAGE_SIZE)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load audit records')
    }
  }

  useEffect(() => {
    void loadFirstPage()
  }, [])

  async function loadOlder() {
    if (!records || records.length === 0) return
    setLoadingMore(true)
    setError(null)
    try {
      const oldestID = records[records.length - 1].id
      const page = await listAuditRecords(PAGE_SIZE, oldestID)
      // Append, don't replace -- the admin's already-loaded context and
      // scroll position shouldn't reset on every page fetch.
      setRecords((prev) => [...(prev ?? []), ...page])
      setHasMore(page.length === PAGE_SIZE)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load older audit records')
    } finally {
      setLoadingMore(false)
    }
  }

  return (
    <section>
      <h2>Audit</h2>
      <p className="hint">
        Every admin action, most recent first. Hash-chained and append-only — nothing here can be
        edited or deleted after the fact.
      </p>
      {error && <div className="error">{error}</div>}

      {records === null ? (
        <p>Loading…</p>
      ) : records.length === 0 ? (
        <p>No audit records yet.</p>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
              </tr>
            </thead>
            <tbody>
              {records.map((r) => (
                <tr key={r.id}>
                  <td>{r.ts}</td>
                  <td>
                    {r.actor_human_username} ({r.actor_human_role})
                    {r.actor_nhi_subject ? ` via ${r.actor_nhi_subject}` : ''}
                  </td>
                  <td>{r.action}</td>
                  <td>{r.resource}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {hasMore && (
            <button type="button" onClick={loadOlder} disabled={loadingMore}>
              {loadingMore ? 'Loading…' : 'Load older'}
            </button>
          )}
        </>
      )}
    </section>
  )
}
