/** Tiny History-API router — the Go server serves index.html for unknown
 *  non-API GET paths (SPA fallback), so clean URLs work in production. */
import { useCallback, useEffect, useState } from 'react'

export type RouteId =
  | 'overview'
  | 'agents'
  | 'capabilities'
  | 'leases'
  | 'providers'
  | 'audit'
  | 'settings'

export interface RouteMeta {
  id: RouteId
  label: string
  path: string
  eyebrow: string
}

export const ROUTES: RouteMeta[] = [
  { id: 'overview', label: 'Overview', path: '/overview', eyebrow: 'Operations' },
  { id: 'agents', label: 'Agents', path: '/agents', eyebrow: 'Identities' },
  { id: 'capabilities', label: 'Capabilities', path: '/capabilities', eyebrow: 'Permission bundles' },
  { id: 'leases', label: 'Leases', path: '/leases', eyebrow: 'Access' },
  { id: 'providers', label: 'Providers', path: '/providers', eyebrow: 'Infrastructure' },
  { id: 'audit', label: 'Audit log', path: '/audit', eyebrow: 'Accountability' },
  { id: 'settings', label: 'Settings', path: '/settings', eyebrow: 'Guardrails' },
]

const ROUTE_BY_PATH = new Map<string, RouteMeta>(
  ROUTES.map((route) => [route.path, route]),
)

export function routeFromPath(pathname: string): RouteMeta {
  const normalized = pathname.replace(/\/+$/, '') || '/'
  return ROUTE_BY_PATH.get(normalized) ?? ROUTES[0]
}

const NAVIGATE_EVENT = 'csg:navigate'

export function navigate(path: string): void {
  if (window.location.pathname + window.location.search === path) return
  window.history.pushState({}, '', path)
  window.dispatchEvent(new CustomEvent(NAVIGATE_EVENT))
  window.scrollTo({ top: 0, behavior: 'instant' as ScrollBehavior })
}

export function useRoute(): RouteMeta {
  const [route, setRoute] = useState(() => routeFromPath(window.location.pathname))

  const sync = useCallback(() => {
    setRoute(routeFromPath(window.location.pathname))
  }, [])

  useEffect(() => {
    window.addEventListener('popstate', sync)
    window.addEventListener(NAVIGATE_EVENT, sync)
    return () => {
      window.removeEventListener('popstate', sync)
      window.removeEventListener(NAVIGATE_EVENT, sync)
    }
  }, [sync])

  return route
}

/** Read a query parameter once (used for deep links such as `/audit?action=…`). */
export function initialQueryParam(name: string): string {
  try {
    return new URLSearchParams(window.location.search).get(name) ?? ''
  } catch {
    return ''
  }
}
