import { useEffect, useState } from 'react'
import { ApiError, getAuthMode, login, loginLocal, type AuthMode, type WhoAmI } from '../api'

interface Props {
  onLoggedIn: (who: WhoAmI) => void
}

// Which credential shape to render is deployment-dependent (issue #43:
// standalone, no-spider-snoop deployments use a local username/password
// instead of pasting a spider-snoop session token) -- fetched once from
// the gateway itself before rendering either form, so this screen never
// has to guess or be told at build time. A failed fetch (network hiccup,
// or an admin API that isn't enabled in either mode at all) falls back
// to the spider-snoop form, this screen's original, always-available
// shape.
export default function Login({ onLoggedIn }: Props) {
  const [mode, setMode] = useState<AuthMode | null>(null)

  useEffect(() => {
    getAuthMode()
      .then((res) => setMode(res.mode))
      .catch(() => setMode('spider_snoop'))
  }, [])

  if (mode === null) {
    return <p className="checking">Checking sign-in options…</p>
  }

  return mode === 'local' ? <LocalLogin onLoggedIn={onLoggedIn} /> : <SpiderSnoopLogin onLoggedIn={onLoggedIn} />
}

// v0's spider-snoop login UX is a manual paste of the human's existing
// spider-snoop session token -- not redirect-based SSO (a real
// spider-snoop-side change, deliberately deferred; see the issue #17
// spec's "Login UX" note). This is the least polished screen in this
// slice on purpose: it ships the mechanism now rather than waiting on
// cross-repo work.
function SpiderSnoopLogin({ onLoggedIn }: Props) {
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

// Standalone (no spider-snoop) admin login (issue #43): a real username
// and password against this gateway's own local (Mode A) accounts --
// admin-ness itself is checked server-side (live group membership), not
// anything this screen decides or even sees.
function LocalLogin({ onLoggedIn }: Props) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!username.trim() || !password) return
    setSubmitting(true)
    setError(null)
    try {
      const who = await loginLocal(username.trim(), password)
      onLoggedIn(who)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'login failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="login-screen">
      <h1>Spidercob Gateway Admin</h1>
      <p className="hint">Sign in with a local admin account.</p>
      <form onSubmit={handleSubmit}>
        <label htmlFor="username">username</label>
        <input
          id="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          autoFocus
        />
        <label htmlFor="password">password</label>
        <input
          id="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        {error && <div className="error">{error}</div>}
        <button type="submit" disabled={submitting || !username.trim() || !password}>
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
