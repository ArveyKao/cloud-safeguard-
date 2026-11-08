/** Application shell: persistent sidebar navigation + live topbar. */
import type { ReactNode } from 'react'
import { cx, formatTime } from '../lib/format'
import type { RouteMeta, RouteId } from '../router'
import { ROUTES, navigate } from '../router'
import {
  IconAgents,
  IconAudit,
  IconCapabilities,
  IconLeases,
  IconLogout,
  IconOverview,
  IconProviders,
  IconRefresh,
  IconSettings,
  IconShield,
} from './icons'
import { IconButton } from './primitives'

const NAV_ICONS: Record<RouteId, ReactNode> = {
  overview: <IconOverview size={18} />,
  agents: <IconAgents size={18} />,
  capabilities: <IconCapabilities size={18} />,
  leases: <IconLeases size={18} />,
  providers: <IconProviders size={18} />,
  audit: <IconAudit size={18} />,
  settings: <IconSettings size={18} />,
}

interface ShellProps {
  route: RouteMeta
  online: boolean
  lastSync: Date | null
  version: string
  pendingCount: number
  onRefresh: () => void
  onLogout: () => void
  children: ReactNode
}

export function Shell({
  route,
  online,
  lastSync,
  version,
  pendingCount,
  onRefresh,
  onLogout,
  children,
}: ShellProps) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a
          className="brand"
          href="/overview"
          onClick={(event) => {
            event.preventDefault()
            navigate('/overview')
          }}
          aria-label="Cloud Safeguard overview"
        >
          <span className="brand__mark" aria-hidden="true">
            <IconShield size={20} />
          </span>
          <span className="brand__text">
            <span className="brand__name">Cloud Safeguard</span>
            <span className="brand__tag">Operator Console</span>
          </span>
        </a>

        <nav className="nav" aria-label="Main navigation">
          <div className="nav__label">Control plane</div>
          {ROUTES.map((item) => {
            const active = item.id === route.id
            return (
              <a
                key={item.id}
                href={item.path}
                className={cx('nav__item', active && 'is-active')}
                aria-current={active ? 'page' : undefined}
                onClick={(event) => {
                  event.preventDefault()
                  navigate(item.path)
                }}
              >
                {NAV_ICONS[item.id]}
                <span>{item.label}</span>
                {item.id === 'overview' && pendingCount > 0 && (
                  <span className="nav__count" aria-label={`${pendingCount} pending approvals`}>
                    {pendingCount > 99 ? '99+' : pendingCount}
                  </span>
                )}
              </a>
            )
          })}
        </nav>

        <div className="sidebar__footer">
          <div className="sidebar__footer-line">
            <span className="row gap-6">
              <span
                className={cx('status-dot', online ? 'status-dot--live' : 'status-dot--offline')}
                aria-hidden="true"
              />
              {online ? 'Control plane live' : 'Offline'}
            </span>
            <span className="sidebar__version">v{version}</span>
          </div>
          <div className="sidebar__motto">
            <strong>Capabilities, not credentials.</strong> Short-lived access, one approval away.
          </div>
        </div>
      </aside>

      <div className="main-col">
        <header className="topbar">
          <div className="topbar__crumbs">
            <span>Cloud Safeguard</span>
            <span aria-hidden="true">/</span>
            <span className="topbar__current">{route.label}</span>
          </div>
          <div className="topbar__spacer" />
          <div className="topbar__meta">
            <span
              className="status-pill"
              role="status"
              aria-label={online ? 'Control plane connected' : 'Control plane unreachable'}
            >
              <span
                className={cx('status-dot', online ? 'status-dot--live' : 'status-dot--offline')}
                aria-hidden="true"
              />
              {online ? 'Live' : 'Disconnected'}
            </span>
            <div className="topbar__sync">
              <span className="topbar__sync-label">Last updated</span>
              <span className="topbar__sync-value">
                {lastSync ? formatTime(lastSync.toISOString()) : '—'}
              </span>
            </div>
            <IconButton label="Refresh data" onClick={onRefresh}>
              <IconRefresh size={17} />
            </IconButton>
            <span className="topbar__divider" aria-hidden="true" />
            <div className="topbar__user">
              <span className="topbar__avatar" aria-hidden="true">
                OP
              </span>
              <span className="topbar__user-meta">
                <span className="topbar__user-name">operator</span>
                <span className="topbar__user-role">admin</span>
              </span>
            </div>
            <IconButton label="Log out" onClick={onLogout}>
              <IconLogout size={17} />
            </IconButton>
          </div>
        </header>
        <main id="main-content">{children}</main>
      </div>
    </div>
  )
}
