import { useEffect, useState } from 'react'
import { ApiError, listPolicies, replacePolicies, type PolicyRule, type RuleType } from '../api'

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

export default function Policies() {
  const [saved, setSaved] = useState<PolicyRule[] | null>(null)
  const [draft, setDraft] = useState<PolicyRule[]>([])
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

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

  useEffect(() => {
    void refresh()
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

  return (
    <section>
      <h2>Policies</h2>
      <p className="hint">
        This is a full replace, not an incremental edit -- saving submits the entire rule set
        below.
      </p>
      {error && <div className="error">{error}</div>}

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
    </section>
  )
}
