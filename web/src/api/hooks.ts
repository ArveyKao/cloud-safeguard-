/**
 * Data-fetching primitives: visibility-aware polling, manual resources and
 * mutation state. Deliberately dependency-free (no react-query) — the console
 * talks to one same-origin API and only needs a handful of behaviours.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import type { DependencyList } from 'react'
import { ApiError } from './client'

export function toApiError(cause: unknown): ApiError {
  if (cause instanceof ApiError) return cause
  if (cause instanceof DOMException && cause.name === 'AbortError') {
    return new ApiError(0, 'aborted', 'Request cancelled.')
  }
  if (cause instanceof Error) return new ApiError(0, 'network_error', cause.message)
  return new ApiError(0, 'network_error', 'Unexpected error.')
}

export interface PollState<T> {
  data: T | null
  error: ApiError | null
  /** First load with no data yet (drives skeletons). */
  loading: boolean
  /** Any request currently in flight (drives refresh spinners). */
  refreshing: boolean
  lastUpdated: Date | null
  refresh: () => Promise<void>
}

interface PollOptions {
  enabled?: boolean
  /** Extra dependencies that should trigger a full re-fetch. */
  deps?: DependencyList
}

/**
 * Fetch immediately, then every `intervalMs` **while the tab is visible**
 * (poll pauses in background tabs and catches up on focus). `intervalMs = 0`
 * disables the timer, giving manual-refresh semantics.
 */
export function usePolling<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  intervalMs: number,
  options: PollOptions = {},
): PollState<T> {
  const { enabled = true } = options
  const deps = options.deps ?? []
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher
  const aliveRef = useRef(true)
  const inFlightRef = useRef<AbortController | null>(null)

  const run = useCallback(async (initial: boolean) => {
    if (!aliveRef.current || inFlightRef.current) return
    const controller = new AbortController()
    inFlightRef.current = controller
    setRefreshing(true)
    if (initial) setLoading(true)
    try {
      const result = await fetcherRef.current(controller.signal)
      if (!aliveRef.current) return
      setData(result)
      setError(null)
      setLastUpdated(new Date())
    } catch (cause) {
      if (controller.signal.aborted || !aliveRef.current) return
      setError(toApiError(cause))
    } finally {
      if (inFlightRef.current === controller) inFlightRef.current = null
      if (aliveRef.current) {
        setRefreshing(false)
        setLoading(false)
      }
    }
  }, [])

  const refresh = useCallback(async () => {
    await run(false)
  }, [run])

  useEffect(() => {
    if (!enabled) return
    aliveRef.current = true
    void run(true)
    const timer =
      intervalMs > 0
        ? window.setInterval(() => {
            if (document.visibilityState === 'visible') void run(false)
          }, intervalMs)
        : undefined
    const onVisibility = () => {
      if (document.visibilityState === 'visible') void run(false)
    }
    document.addEventListener('visibilitychange', onVisibility)
    return () => {
      aliveRef.current = false
      if (timer !== undefined) window.clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisibility)
      inFlightRef.current?.abort()
      inFlightRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, intervalMs, ...deps])

  return { data, error, loading, refreshing, lastUpdated, refresh }
}

/** Manual-refresh resource (no polling timer). */
export function useResource<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  deps: DependencyList = [],
  enabled = true,
): PollState<T> {
  return usePolling(fetcher, 0, { deps, enabled })
}

interface MutationState<TArgs extends unknown[], TResult> {
  run: (...args: TArgs) => Promise<TResult>
  busy: boolean
  error: ApiError | null
  reset: () => void
}

/** Minimal async-action state for forms and inline buttons. */
export function useMutation<TArgs extends unknown[], TResult>(
  action: (...args: TArgs) => Promise<TResult>,
): MutationState<TArgs, TResult> {
  const actionRef = useRef(action)
  actionRef.current = action
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

  const run = useCallback(async (...args: TArgs) => {
    setBusy(true)
    setError(null)
    try {
      return await actionRef.current(...args)
    } catch (cause) {
      const apiError = toApiError(cause)
      setError(apiError)
      throw apiError
    } finally {
      setBusy(false)
    }
  }, [])

  const reset = useCallback(() => setError(null), [])
  return { run, busy, error, reset }
}

/** Current time, ticking every `intervalMs`, for countdowns / relative ages. */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(timer)
  }, [intervalMs])
  return now
}

/**
 * Server clock offset. The control plane is the authority for lease expiry, so
 * countdowns are computed against `server_time` once the overview has loaded.
 */
let clockOffsetMs = 0

export function syncServerClock(serverTimeIso: string | null | undefined): void {
  if (!serverTimeIso) return
  const server = Date.parse(serverTimeIso)
  if (Number.isNaN(server)) return
  const delta = server - Date.now()
  // Ignore absurd skew (> 1 day) — likely a malformed timestamp.
  if (Math.abs(delta) < 86_400_000) clockOffsetMs = delta
}

export function serverNow(): number {
  return Date.now() + clockOffsetMs
}

export function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delayMs)
    return () => window.clearTimeout(timer)
  }, [value, delayMs])
  return debounced
}
