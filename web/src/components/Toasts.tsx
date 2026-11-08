/** Toast notifications: imperative API via context, aria-live region. */
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { ApiError } from '../api/client'
import { cx } from '../lib/format'
import { IconAlert, IconCheck, IconInfo, IconX } from './icons'

type ToastKind = 'success' | 'error' | 'info' | 'warning'

interface ToastItem {
  id: number
  kind: ToastKind
  title: string
  message?: string
}

interface ToastApi {
  push: (kind: ToastKind, title: string, message?: string) => void
  success: (title: string, message?: string) => void
  error: (title: string, message?: string) => void
  info: (title: string, message?: string) => void
  warning: (title: string, message?: string) => void
}

const ToastContext = createContext<ToastApi | null>(null)

let nextId = 1

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const timers = useRef(new Map<number, number>())

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id))
    const timer = timers.current.get(id)
    if (timer !== undefined) {
      window.clearTimeout(timer)
      timers.current.delete(id)
    }
  }, [])

  const push = useCallback(
    (kind: ToastKind, title: string, message?: string) => {
      const id = nextId++
      setToasts((current) => [...current.slice(-4), { id, kind, title, message }])
      const timeout = window.setTimeout(() => dismiss(id), kind === 'error' ? 8000 : 5000)
      timers.current.set(id, timeout)
    },
    [dismiss],
  )

  useEffect(
    () => () => {
      for (const timer of timers.current.values()) window.clearTimeout(timer)
      timers.current.clear()
    },
    [],
  )

  const api = useMemo<ToastApi>(
    () => ({
      push,
      success: (title, message) => push('success', title, message),
      error: (title, message) => push('error', title, message),
      info: (title, message) => push('info', title, message),
      warning: (title, message) => push('warning', title, message),
    }),
    [push],
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toast-stack" aria-live="polite" aria-atomic="false">
        {toasts.map((toast) => (
          <div key={toast.id} className={cx('toast', `toast--${toast.kind}`)} role="status">
            <span className="toast__icon" aria-hidden="true">
              {toast.kind === 'success' ? (
                <IconCheck size={15} />
              ) : toast.kind === 'error' ? (
                <IconAlert size={15} />
              ) : toast.kind === 'warning' ? (
                <IconAlert size={15} />
              ) : (
                <IconInfo size={15} />
              )}
            </span>
            <div className="toast__body">
              <div className="toast__title">{toast.title}</div>
              {toast.message && <div>{toast.message}</div>}
            </div>
            <button
              type="button"
              className="toast__close"
              onClick={() => dismiss(toast.id)}
              aria-label="Dismiss notification"
            >
              <IconX size={13} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): ToastApi {
  const context = useContext(ToastContext)
  if (!context) throw new Error('useToast must be used inside <ToastProvider>')
  return context
}

/** Turn an API failure into a toast-friendly message without leaking internals. */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) return error.message
  if (error instanceof Error) return error.message
  return 'Unexpected error.'
}
