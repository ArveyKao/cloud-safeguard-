/** The console: session gate, shell and pages (CONTRACT §17). */
import { useCallback, useEffect, useState } from 'react'
import { api, setCsrf, setSignedOutHandler } from './api'
import type { Person, SessionInfo } from './types'
import { navigate, useLocation } from './router'
import { Shell } from './Shell'
import { useLoad } from './ui'
import { LoginPage } from './pages/Login'
import { SetupPage } from './pages/Setup'
import { InboxPage } from './pages/Inbox'
import { SignInApprovalPage } from './pages/SignInApproval'
import { AgentsPage } from './pages/Agents'
import { AccountsPage } from './pages/Accounts'
import { AddAccountPage } from './pages/AddAccount'
import { ActivityPage } from './pages/Activity'
import { PeoplePage } from './pages/People'
import { SettingsPage } from './pages/Settings'

// A sign-in link (/?signin=CODE) survives the login screen.
const SIGNIN_KEY = 'csg.pendingSignIn'

export function App() {
  const { path, query } = useLocation()
  const [session, setSession] = useState<SessionInfo | null>(null)
  const [checked, setChecked] = useState(false)

  const signedIn = useCallback((s: SessionInfo) => {
    setCsrf(s.csrf_token)
    setSession(s)
    const code = sessionStorage.getItem(SIGNIN_KEY)
    sessionStorage.removeItem(SIGNIN_KEY)
    navigate(code ? `/signin?code=${encodeURIComponent(code)}` : (path === '/login' || path === '/setup' || path === '/' ? '/inbox' : path))
  }, [path])

  useEffect(() => {
    const code = query.get('signin')
    if (code) sessionStorage.setItem(SIGNIN_KEY, code)
    setSignedOutHandler(() => { setCsrf(''); setSession(null) })
    api.me()
      .then((s) => { setCsrf(s.csrf_token); setSession(s); if (code) navigate(`/signin?code=${encodeURIComponent(code)}`) })
      .catch(() => setSession(null))
      .finally(() => setChecked(true))
    return () => setSignedOutHandler(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!checked) return null
  if (!session) {
    return path === '/setup' ? <SetupPage onSignedIn={signedIn} /> : <LoginPage onSignedIn={signedIn} />
  }
  return <SignedIn session={session} path={path} query={query} setSession={setSession} />
}

function SignedIn({ session, path, query, setSession }: {
  session: SessionInfo; path: string; query: URLSearchParams; setSession: (s: SessionInfo | null) => void
}) {
  const person = session.person
  const pending = useLoad(() => api.myRequests('pending'), [], 10000)
  const setPerson = (p: Person) => setSession({ ...session, person: p })

  useEffect(() => {
    if (path === '/' || path === '/login' || path === '/setup') navigate('/inbox')
  }, [path])

  async function logout() {
    try { await api.logout() } catch { /* the session may already be gone */ }
    setCsrf('')
    setSession(null)
    navigate('/login')
  }

  let page
  if (path === '/signin') page = <SignInApprovalPage code={query.get('code') ?? ''} />
  else if (path === '/agents') page = <AgentsPage />
  else if (path === '/accounts/new' && person.supervisor) page = <AddAccountPage />
  else if (path.startsWith('/accounts')) page = <AccountsPage person={person} />
  else if (path === '/activity') page = <ActivityPage person={person} />
  else if (path === '/people' && person.supervisor) page = <PeoplePage me={person} />
  else if (path === '/settings') page = <SettingsPage person={person} onPersonChange={setPerson} />
  else page = <InboxPage person={person} onChange={pending.reload} />

  return (
    <Shell person={person} path={path} pending={pending.data?.total ?? 0} onLogout={logout}>
      {page}
    </Shell>
  )
}
