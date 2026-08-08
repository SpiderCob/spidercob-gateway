import { useEffect, useState } from 'react'
import {
  ApiError,
  addGroupMember,
  createGroup,
  deleteGroup,
  listGroups,
  removeGroupMember,
  type Group,
  type MemberType,
} from '../api'

export default function Groups() {
  const [groups, setGroups] = useState<Group[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)

  const [memberGroup, setMemberGroup] = useState('')
  const [memberType, setMemberType] = useState<MemberType>('user')
  const [memberIdentifier, setMemberIdentifier] = useState('')
  const [memberBusy, setMemberBusy] = useState(false)

  async function refresh() {
    try {
      setGroups(await listGroups())
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to load groups')
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
      await createGroup(newName.trim())
      setNewName('')
      await refresh()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to create group')
    } finally {
      setCreating(false)
    }
  }

  async function handleDelete(name: string) {
    setError(null)
    try {
      await deleteGroup(name)
      await refresh()
    } catch (err) {
      // The backend refuses (409) with an explanatory message when a
      // policy still references this group (story 15) -- surfaced
      // verbatim, not swallowed into a generic failure.
      setError(err instanceof ApiError ? err.message : 'failed to delete group')
    }
  }

  async function handleAddMember(e: React.FormEvent) {
    e.preventDefault()
    if (!memberGroup || !memberIdentifier.trim()) return
    setMemberBusy(true)
    setError(null)
    try {
      await addGroupMember(memberGroup, memberType, memberIdentifier.trim())
      setMemberIdentifier('')
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to add group member')
    } finally {
      setMemberBusy(false)
    }
  }

  async function handleRemoveMember() {
    if (!memberGroup || !memberIdentifier.trim()) return
    setMemberBusy(true)
    setError(null)
    try {
      await removeGroupMember(memberGroup, memberType, memberIdentifier.trim())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'failed to remove group member')
    } finally {
      setMemberBusy(false)
    }
  }

  return (
    <section>
      <h2>Groups</h2>
      {error && <div className="error">{error}</div>}

      <form onSubmit={handleCreate} className="inline-form">
        <input
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
          placeholder="new group name"
        />
        <button type="submit" disabled={creating || !newName.trim()}>
          Create group
        </button>
      </form>

      {groups === null ? (
        <p>Loading…</p>
      ) : groups.length === 0 ? (
        <p>No groups yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {groups.map((g) => (
              <tr key={g.name}>
                <td>{g.name}</td>
                <td>
                  <button type="button" onClick={() => handleDelete(g.name)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h3>Membership</h3>
      <form onSubmit={handleAddMember} className="inline-form">
        <select value={memberGroup} onChange={(e) => setMemberGroup(e.target.value)}>
          <option value="">select group…</option>
          {(groups ?? []).map((g) => (
            <option key={g.name} value={g.name}>
              {g.name}
            </option>
          ))}
        </select>
        <select value={memberType} onChange={(e) => setMemberType(e.target.value as MemberType)}>
          <option value="user">user</option>
          <option value="agent">agent</option>
        </select>
        <input
          value={memberIdentifier}
          onChange={(e) => setMemberIdentifier(e.target.value)}
          placeholder="username or client_id"
        />
        <button type="submit" disabled={memberBusy || !memberGroup || !memberIdentifier.trim()}>
          Add to group
        </button>
        <button
          type="button"
          onClick={handleRemoveMember}
          disabled={memberBusy || !memberGroup || !memberIdentifier.trim()}
        >
          Remove from group
        </button>
      </form>
    </section>
  )
}
