import { useState } from 'react'
import { ApiError, login, type WhoAmI } from '../api'

interface Props {
  onLoggedIn: (who: WhoAmI) => void
}

// v0's login UX is a manual paste of the human's existing spider-snoop
// session token -- not redirect-based SSO (a real spider-snoop-side
// change, deliberately deferred; see the issue #17 spec's "Login UX"
// note). This is the least polished screen in this slice on purpose:
// it ships the mechanism now rather than waiting on cross-repo work.
export default function Login({ onLoggedIn }: Props) {
  const [token, setToken] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!token.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      const who = await login(token.trim())
      onLoggedIn(who)
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError('login failed')
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="login-screen">
      <h1>Spidercob Gateway Admin</h1>
      <p className="hint">
        Paste your spider-snoop session token to sign in. This gateway does not have its own
        login -- it trusts your existing spider-snoop admin session.
      </p>
      <form onSubmit={handleSubmit}>
        <label htmlFor="token">spider-snoop session token</label>
        <textarea
          id="token"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          rows={3}
          placeholder="paste your session token here"
          autoFocus
        />
        {error && <div className="error">{error}</div>}
        <button type="submit" disabled={submitting || !token.trim()}>
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
