import type { ReactNode } from 'react'
import type { Person } from './types'
import { navigate } from './router'

export function Logo() {
  return (
    <div className="logo">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" /><path d="M9 12l2 2 4-4" />
      </svg>
      <span>Cloud Safeguard</span>
    </div>
  )
}

interface NavItem { path: string; label: string; badge?: number }

export function Shell({ person, path, pending, onLogout, children }: {
  person: Person; path: string; pending: number; onLogout: () => void; children: ReactNode
}) {
  const items: NavItem[] = [
    { path: '/inbox', label: 'Inbox', badge: pending },
    { path: '/agents', label: 'Agents' },
    { path: '/accounts', label: 'Cloud accounts' },
    { path: '/activity', label: 'Activity' },
  ]
  if (person.supervisor) items.push({ path: '/people', label: 'People' })
  const link = (item: NavItem) => (
    <a key={item.path} href={item.path} aria-current={path.startsWith(item.path) ? 'page' : undefined}
      onClick={(e) => { e.preventDefault(); navigate(item.path) }}>
      <span>{item.label}</span>
      {item.badge ? <span className="nav-badge">{item.badge}</span> : null}
    </a>
  )
  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Main">
        <Logo />
        <div className="nav-links">{items.map(link)}</div>
        <div className="nav-foot">
          <a href="/settings" aria-current={path.startsWith('/settings') ? 'page' : undefined}
            onClick={(e) => { e.preventDefault(); navigate('/settings') }}>Settings</a>
          <div className="me">
            <span className="avatar">{(person.display_name || person.username).slice(0, 1).toUpperCase()}</span>
            <span className="me-name">
              {person.display_name || person.username}
              {person.supervisor && <small>Supervisor</small>}
            </span>
            <button type="button" className="btn btn-link" onClick={onLogout}>Sign out</button>
          </div>
        </div>
      </nav>
      <main id="main" className="main">{children}</main>
    </div>
  )
}
