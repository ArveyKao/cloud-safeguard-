/** Minimal History-API routing; the server answers unknown paths with the app. */
import { useEffect, useState } from 'react'

const EVENT = 'csg:navigate'

export function navigate(path: string) {
  if (window.location.pathname + window.location.search === path) return
  window.history.pushState({}, '', path)
  window.dispatchEvent(new Event(EVENT))
  window.scrollTo(0, 0)
}

export function useLocation() {
  const read = () => ({ path: window.location.pathname.replace(/\/+$/, '') || '/', query: new URLSearchParams(window.location.search) })
  const [loc, setLoc] = useState(read)
  useEffect(() => {
    const sync = () => setLoc(read())
    window.addEventListener('popstate', sync)
    window.addEventListener(EVENT, sync)
    return () => {
      window.removeEventListener('popstate', sync)
      window.removeEventListener(EVENT, sync)
    }
  }, [])
  return loc
}
