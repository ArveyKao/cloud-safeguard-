/** App root: auth gate, shell, routing, global live status. */
import { Component, useEffect, useState } from 'react'
import type { ErrorInfo, ReactNode } from 'react'
import { fetchHealth, setUnauthorizedHandler } from './api/client'
import { usePolling } from './api/hooks'
import { clearToken, readToken } from './auth'
import { Shell } from './components/Shell'
import { LoginPage } from './pages/Login'
import { OverviewPage } from './pages/Overview'
import { AgentsPage } from './pages/Agents'
import { CapabilitiesPage } from './pages/Capabilities'
import { LeasesPage } from './pages/Leases'
import { ProvidersPage } from './pages/Providers'
import { AuditPage } from './pages/Audit'
import { SettingsPage } from './pages/Settings'
import { navigate, useRoute } from './router'
import { Button } from './components/primitives'
import { IconAlert } from './components/icons'

const VERSION = '0.1.0'

export function App() {
  const route = useRoute()
  const [authenticated, setAuthenticated] = useAuthState()
  const [refreshKey, bumpRefresh] = useRefreshKey()
  const [pendingCount, setPendingCount] = usePendingCount()
  const [lastSync, setLastSync] = useLastSync()

  const health = usePolling(fetchHealth, 10_000, { enabled: authenticated })
  const online = Boolean(health.data) && !health.error

  // A 401 from any API call clears the session and returns to the login screen.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setAuthenticated(false)
      setPendingCount(0)
      window.dispatchEvent(new CustomEvent('csg:unauthorized'))
    })
    return () => setUnauthorizedHandler(null)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function handleAuthenticated() {
    setAuthenticated(true)
    setLastSync(new Date())
    navigate('/overview')
  }

  function handleLogout() {
    clearToken()
    setAuthenticated(false)
    setPendingCount(0)
    navigate('/overview')
  }

  if (!authenticated) {
    return <LoginPage onAuthenticated={handleAuthenticated} />
  }

  const pages: Record<string, ReactNode> = {
    overview: <OverviewPage refreshKey={refreshKey} onPendingCount={setPendingCount} />,
    agents: <AgentsPage refreshKey={refreshKey} />,
    capabilities: <CapabilitiesPage refreshKey={refreshKey} />,
    leases: <LeasesPage refreshKey={refreshKey} />,
    providers: <ProvidersPage refreshKey={refreshKey} />,
    audit: <AuditPage refreshKey={refreshKey} />,
    settings: <SettingsPage refreshKey={refreshKey} />,
  }

  return (
    <Shell
      route={route}
      online={online}
      lastSync={lastSync}
      version={VERSION}
      pendingCount={pendingCount}
      onRefresh={bumpRefresh}
      onLogout={handleLogout}
    >
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      {pages[route.id] ?? pages.overview}
    </Shell>
  )
}

/* Small hooks keep App readable; each owns one piece of shell state. */

function useAuthState() {
  return useState<boolean>(() => readToken() !== null)
}

function useRefreshKey() {
  const [refreshKey, setRefreshKey] = useState(0)
  const bump = () => setRefreshKey((key) => key + 1)
  return [refreshKey, bump] as const
}

function usePendingCount() {
  return useState(0)
}

function useLastSync() {
  const [lastSync, setLastSync] = useState<Date | null>(null)

  useEffect(() => {
    const onActivity = (event: Event) => {
      const detail = (event as CustomEvent<{ at?: number }>).detail
      if (detail?.at) setLastSync(new Date(detail.at))
    }
    const onUnauthorized = () => setLastSync(null)
    window.addEventListener('csg:api-ok', onActivity)
    window.addEventListener('csg:unauthorized', onUnauthorized)
    return () => {
      window.removeEventListener('csg:api-ok', onActivity)
      window.removeEventListener('csg:unauthorized', onUnauthorized)
    }
  }, [])

  return [lastSync, setLastSync] as const
}

/** Render-error boundary: never leave a blank screen in front of an operator. */
interface ErrorBoundaryState {
  error: Error | null
}

export class ErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Keep diagnostics in the browser console only; never send to a third party.
    console.error('Cloud Safeguard console render error:', error, info.componentStack)
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="fatal">
        <div className="fatal__card">
          <div className="fatal__icon">
            <IconAlert size={22} />
          </div>
          <h1 className="fatal__title">The console hit an unexpected error</h1>
          <p className="fatal__message">{this.state.error.message}</p>
          <div className="fatal__actions">
            <Button variant="secondary" onClick={() => this.setState({ error: null })}>
              Try again
            </Button>
            <Button variant="primary" onClick={() => window.location.reload()}>
              Reload console
            </Button>
          </div>
        </div>
      </div>
    )
  }
}
