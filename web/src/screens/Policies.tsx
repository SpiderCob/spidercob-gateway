import { useEffect, useState } from 'react'
import {
  ApiError,
  listGroups,
  listNodes,
  listPolicies,
  replacePolicies,
  type Group,
  type Node,
  type PolicyRule,
  type RuleType,
} from '../api'
import { classifyCell, rulesForCell, type CellState } from '../policyMatrix'

function emptyRule(): PolicyRule {
  return { group: '', node: '', rule_type: 'allow' }
}

function ruleKey(r: PolicyRule): string {
  return `${r.group}|${r.node}|${r.rule_type}|${(r.methods ?? []).join(',')}|${(r.tools ?? []).join(',')}`
}

// parseCommaList splits a comma-separated input field into a trimmed,
// non-empty entry list, or undefined if that leaves nothing -- matching
// the backend's contract, where a non-empty Methods/Tools list is a
// restrictive allowlist. A trailing/double comma or whitespace-only
// entry must not silently produce an empty-string element: the backend
// would then treat it as an allowlist entry that can never match any
// real method/tool name, locking access down instead of leaving it
// unrestricted.
function parseCommaList(value: string): string[] | undefined {
  const entries = value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
  return entries.length > 0 ? entries : undefined
}

const CELL_LABEL: Record<CellState, string> = {
  'no-rule': '—',
  allowed: 'allow',
  denied: 'deny',
  restricted: 'partial',
}

type View = 'list' | 'matrix'

export default function Policies() {
  const [saved, setSaved] = useState<PolicyRule[] | null>(null)
  const [draft, setDraft] = useState<PolicyRule[]>([])
  const [groups, setGroups] = useState<Group[] | null>(null)
  const [nodes, setNodes] = useState<Node[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [view, setView] = useState<View>('list')
  const [selectedCell, setSelectedCell] = useState<{ group: string; node: string } | null>(null)

  async function refresh() {
    try {
      const rules = await listPolicies()
      setSaved(rules)
      setDraft(rules)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load policies')
    }
  }

  async function refreshGroupsAndNodes() {
    try {
      const [g, n] = await Promise.all([listGroups(), listNodes()])
      setGroups(g)
      setNodes(n)
    } catch {
      // The matrix just has nothing to show if this fails -- the List
      // view (and its own error banner) is unaffected either way.
      setGroups([])
      setNodes([])
    }
  }

  useEffect(() => {
    void refresh()
    void refreshGroupsAndNodes()
  }, [])

  function updateRule(i: number, patch: Partial<PolicyRule>) {
    setDraft((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)))
  }

  function removeRule(i: number) {
    setDraft((prev) => prev.filter((_, idx) => idx !== i))
  }

  function addRule() {
    setDraft((prev) => [...prev, emptyRule()])
  }

  // Rules present in the last-fetched saved set but no longer in the
  // draft -- surfaced as an explicit warning before submit (story 21),
  // since PUT /admin/policies is a full replace, not an incremental
  // diff: silently dropping a row here really does remove that access.
  const removedRules = (saved ?? []).filter(
    (s) => !draft.some((d) => ruleKey(d) === ruleKey(s)),
  )

  async function handleSave() {
    if (removedRules.length > 0) {
      const ok = window.confirm(
        `This will remove ${removedRules.length} existing rule(s) that grant/deny access today. Continue?`,
      )
      if (!ok) return
    }
    setSaving(true)
    setError(null)
    try {
      const cleaned = draft.filter((r) => r.group.trim() && r.node.trim())
      await replacePolicies(cleaned)
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to save policies')
    } finally {
      setSaving(false)
    }
  }

  const selectedRules =
    selectedCell && saved ? rulesForCell(saved, selectedCell.group, selectedCell.node) : []

  return (
    <section>
      <h2>Policies</h2>
      {error && <div className="error">{error}</div>}

      <nav>
        <button className={view === 'list' ? 'active' : ''} onClick={() => setView('list')}>
          List
        </button>
        <button
          className={view === 'matrix' ? 'active' : ''}
          onClick={() => {
            setView('matrix')
            setSelectedCell(null)
          }}
        >
          Matrix
        </button>
      </nav>

      {view === 'list' ? (
        <>
          <p className="hint">
            This is a full replace, not an incremental edit -- saving submits the entire rule set
            below.
          </p>

          {saved === null ? (
            <p>Loading…</p>
          ) : (
            <>
              <table>
                <thead>
                  <tr>
                    <th>Group</th>
                    <th>Node</th>
                    <th>Rule</th>
                    <th>Methods</th>
                    <th>Tools</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {draft.map((r, i) => (
                    <tr key={i}>
                      <td>
                        <input value={r.group} onChange={(e) => updateRule(i, { group: e.target.value })} />
                      </td>
                      <td>
                        <input value={r.node} onChange={(e) => updateRule(i, { node: e.target.value })} />
                      </td>
                      <td>
                        <select
                          value={r.rule_type}
                          onChange={(e) => updateRule(i, { rule_type: e.target.value as RuleType })}
                        >
                          <option value="allow">allow</option>
                          <option value="deny">deny</option>
                        </select>
                      </td>
                      <td>
                        <input
                          value={(r.methods ?? []).join(',')}
                          onChange={(e) => updateRule(i, { methods: parseCommaList(e.target.value) })}
                          placeholder="all"
                        />
                      </td>
                      <td>
                        <input
                          value={(r.tools ?? []).join(',')}
                          onChange={(e) => updateRule(i, { tools: parseCommaList(e.target.value) })}
                          placeholder="all"
                        />
                      </td>
                      <td>
                        <button type="button" onClick={() => removeRule(i)}>
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              <div className="inline-form">
                <button type="button" onClick={addRule}>
                  + Add rule
                </button>
                <button type="button" onClick={handleSave} disabled={saving}>
                  {saving ? 'Saving…' : 'Save policy set'}
                </button>
              </div>

              {removedRules.length > 0 && (
                <p className="warning">
                  {removedRules.length} existing rule(s) will be removed if you save now.
                </p>
              )}
            </>
          )}
        </>
      ) : (
        <>
          <p className="hint">
            Read-only overview of every group's access to every node, reflecting the currently
            saved policy set (not unsaved List-view edits). Click a cell for the rule(s) behind
            it.
          </p>

          {saved === null || groups === null || nodes === null ? (
            <p>Loading…</p>
          ) : groups.length === 0 ? (
            <p>No groups registered yet.</p>
          ) : nodes.length === 0 ? (
            <p>No nodes registered yet.</p>
          ) : (
            <div className="matrix-scroll">
              <table>
                <thead>
                  <tr>
                    <th></th>
                    {nodes.map((n) => (
                      <th key={n.name}>{n.name}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {groups.map((g) => (
                    <tr key={g.name}>
                      <th>{g.name}</th>
                      {nodes.map((n) => {
                        const rules = rulesForCell(saved, g.name, n.name)
                        const state = classifyCell(rules)
                        const clickable = state !== 'no-rule'
                        return (
                          <td
                            key={n.name}
                            className={`cell-${state}`}
                            onClick={clickable ? () => setSelectedCell({ group: g.name, node: n.name }) : undefined}
                            title={clickable ? 'click for details' : undefined}
                          >
                            {CELL_LABEL[state]}
                          </td>
                        )
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {selectedCell && (
            <div className="matrix-cell-detail">
              <h4>
                {selectedCell.group} → {selectedCell.node}
              </h4>
              {selectedRules.length === 0 ? (
                <p>No rules match this pair anymore.</p>
              ) : (
                <ul>
                  {selectedRules.map((r, i) => (
                    <li key={i}>
                      <strong>{r.rule_type}</strong>
                      {' — methods: '}
                      {r.methods && r.methods.length > 0 ? r.methods.join(', ') : 'all'}
                      {', tools: '}
                      {r.tools && r.tools.length > 0 ? r.tools.join(', ') : 'all'}
                      {r.rate_limit_max_calls != null && r.rate_limit_window_seconds != null && (
                        <>
                          {', rate limit: '}
                          {r.rate_limit_max_calls}/{r.rate_limit_window_seconds}s
                        </>
                      )}
                      {r.block_on_scan_flag && ', blocks on scan flag'}
                    </li>
                  ))}
                </ul>
              )}
              <div className="inline-form">
                <button type="button" onClick={() => setView('list')}>
                  Edit in list view
                </button>
                <button type="button" onClick={() => setSelectedCell(null)}>
                  Close
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  )
}
