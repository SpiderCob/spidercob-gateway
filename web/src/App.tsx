import { useEffect, useState } from 'react'
import { logout, whoami, type WhoAmI } from './api'
import Login from './screens/Login'
import Agents from './screens/Agents'
import Groups from './screens/Groups'
import Policies from './screens/Policies'
import Nodes from './screens/Nodes'
import './App.css'

type Tab = 'agents' | 'groups' | 'policies' | 'nodes'

export default function App() {
  // null = still checking; undefined = checked, not logged in.
  const [who, setWho] = useState<WhoAmI | null | undefined>(null)
  const [tab, setTab] = useState<Tab>('agents')

  useEffect(() => {
    whoami()
      .then(setWho)
      .catch(() => setWho(undefined))
  }, [])

  async function handleLogout() {
    try {
      await logout()
    } finally {
      setWho(undefined)
    }
  }

  if (who === null) {
    return <p className="checking">Checking session…</p>
  }
  if (who === undefined) {
    return <Login onLoggedIn={setWho} />
  }

  return (
    <div className="app">
      <header>
        <h1>Spidercob Gateway Admin</h1>
        <div className="whoami">
          {who.username} ({who.role})
          <button type="button" onClick={handleLogout}>
            Log out
          </button>
        </div>
      </header>
      <nav>
        <button className={tab === 'agents' ? 'active' : ''} onClick={() => setTab('agents')}>
          Agents
        </button>
        <button className={tab === 'groups' ? 'active' : ''} onClick={() => setTab('groups')}>
          Groups
        </button>
        <button className={tab === 'policies' ? 'active' : ''} onClick={() => setTab('policies')}>
          Policies
        </button>
        <button className={tab === 'nodes' ? 'active' : ''} onClick={() => setTab('nodes')}>
          Nodes
        </button>
      </nav>
      <main>
        {tab === 'agents' && <Agents />}
        {tab === 'groups' && <Groups />}
        {tab === 'policies' && <Policies />}
        {tab === 'nodes' && <Nodes />}
      </main>
    </div>
  )
}
