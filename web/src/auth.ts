/**
 * Admin token storage.
 *
 * The token lives only in localStorage under the frozen key `csg.adminToken`
 * (docs/CONTRACT.md §12) and is attached as `Authorization: Bearer` by the API
 * client. It is never rendered after login, never put in a URL, and never
 * written to the audit or toast layers.
 */
const TOKEN_KEY = 'csg.adminToken'

let memoryToken: string | null = null

export function readToken(): string | null {
  if (memoryToken !== null) return memoryToken
  try {
    const stored = window.localStorage.getItem(TOKEN_KEY)
    memoryToken = stored && stored.trim() !== '' ? stored : null
    return memoryToken
  } catch {
    return null
  }
}

export function writeToken(token: string): void {
  memoryToken = token
  try {
    window.localStorage.setItem(TOKEN_KEY, token)
  } catch {
    /* localStorage can be unavailable in hardened browsers; memory fallback */
  }
}

export function clearToken(): void {
  memoryToken = null
  try {
    window.localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* ignore */
  }
}
