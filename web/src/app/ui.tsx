/** Small shared building blocks for the console. */
import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import qrcode from 'qrcode-generator'
import { ApiError } from './api'

export function Button(props: {
  children: ReactNode; onClick?: () => void; kind?: 'primary' | 'secondary' | 'danger' | 'link'
  type?: 'button' | 'submit'; disabled?: boolean; busy?: boolean
}) {
  const { kind = 'secondary', type = 'button' } = props
  return (
    <button type={type} className={`btn btn-${kind}`} onClick={props.onClick} disabled={props.disabled || props.busy}>
      {props.busy ? 'Working…' : props.children}
    </button>
  )
}

export function Badge({ children, tone = 'grey' }: { children: ReactNode; tone?: 'grey' | 'blue' | 'green' | 'amber' | 'red' }) {
  return <span className={`badge badge-${tone}`}>{children}</span>
}

export function Card({ children, title, actions }: { children: ReactNode; title?: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      {(title || actions) && (
        <header className="card-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  )
}

export function PageHead({ title, lead, actions }: { title: string; lead?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {lead && <p className="lead">{lead}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  )
}

export function Field(props: {
  label: string; value: string; onChange: (v: string) => void; type?: string; hint?: ReactNode
  autoComplete?: string; inputMode?: 'numeric' | 'text'; placeholder?: string; autoFocus?: boolean
}) {
  return (
    <label className="field">
      <span>{props.label}</span>
      <input
        type={props.type ?? 'text'} value={props.value} placeholder={props.placeholder}
        onChange={(e) => props.onChange(e.target.value)} autoComplete={props.autoComplete}
        inputMode={props.inputMode} autoFocus={props.autoFocus} spellCheck={false}
      />
      {props.hint && <small>{props.hint}</small>}
    </label>
  )
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null
  const message = error instanceof ApiError || error instanceof Error ? error.message : String(error)
  return <p className="note note-error" role="alert">{message}</p>
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>
}

/** Loads data and reloads it on demand or every `everyMs`. */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[] = [], everyMs = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<unknown>(null)
  const loadRef = useRef(load)
  loadRef.current = load
  const reload = useCallback(async () => {
    try {
      setData(await loadRef.current())
      setError(null)
    } catch (e) {
      setError(e)
    }
  }, [])
  useEffect(() => {
    reload()
    if (!everyMs) return
    const t = window.setInterval(reload, everyMs)
    return () => window.clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return { data, error, reload }
}

/** Runs an action, tracking busy and error state. */
export function useAction() {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const run = useCallback(async (fn: () => Promise<unknown>) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
      return true
    } catch (e) {
      setError(e)
      return false
    } finally {
      setBusy(false)
    }
  }, [])
  return { busy, error, run, setError }
}

export function Modal({ title, children, onClose, closable = true }: {
  title: string; children: ReactNode; onClose: () => void; closable?: boolean
}) {
  useEffect(() => {
    if (!closable) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [closable, onClose])
  return (
    <div className="modal-backdrop" onClick={closable ? onClose : undefined}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title} onClick={(e) => e.stopPropagation()}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  )
}

/** Shows a one-time secret with a copy button. */
export function Secret({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="secret">
      <span className="secret-label">{label}</span>
      <code>{value}</code>
      <Button onClick={async () => {
        try { await navigator.clipboard.writeText(value); setCopied(true) } catch { setCopied(false) }
      }}>{copied ? 'Copied' : 'Copy'}</Button>
    </div>
  )
}

export function QRCode({ text }: { text: string }) {
  const qr = qrcode(0, 'M')
  qr.addData(text)
  qr.make()
  return <div className="qr" aria-label="QR code for your authenticator app" dangerouslySetInnerHTML={{ __html: qr.createSvgTag({ cellSize: 5, margin: 2, scalable: true }) }} />
}

// ---- confirmation ----

export interface ConfirmRequest {
  title: string
  body: ReactNode
  confirmLabel: string
  danger?: boolean
  run: () => Promise<unknown>
}

/** Asks before an action that changes authority or cannot be undone. The
 *  action runs only after the person confirms. */
export function useConfirm() {
  const [ask, setAsk] = useState<ConfirmRequest | null>(null)
  const action = useAction()
  const confirm = useCallback((req: ConfirmRequest) => { action.setError(null); setAsk(req) }, [action])
  const element = ask && (
    <Modal title={ask.title} onClose={() => setAsk(null)}>
      <div className="confirm-body">{ask.body}</div>
      <ErrorNote error={action.error} />
      <div className="row-actions">
        <Button onClick={() => setAsk(null)}>Cancel</Button>
        <Button kind={ask.danger ? 'danger' : 'primary'} busy={action.busy}
          onClick={async () => { if (await action.run(ask.run)) setAsk(null) }}>{ask.confirmLabel}</Button>
      </div>
    </Modal>
  )
  return { confirm, element }
}

// ---- toasts ----

type Toast = { id: number; text: string; tone: 'ok' | 'error' }
const ToastContext = createContext<(text: string, tone?: Toast['tone']) => void>(() => {})

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const push = useCallback((text: string, tone: Toast['tone'] = 'ok') => {
    const id = Date.now() + Math.random()
    setToasts((t) => [...t, { id, text, tone }])
    window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4000)
  }, [])
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => <div key={t.id} className={`toast toast-${t.tone}`}>{t.text}</div>)}
      </div>
    </ToastContext.Provider>
  )
}

export const useToast = () => useContext(ToastContext)

// ---- formatting ----

export function ago(iso?: string): string {
  if (!iso) return 'never'
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 0) return 'in ' + duration(-s)
  if (s < 60) return 'just now'
  return duration(s) + ' ago'
}

export function duration(seconds: number): string {
  if (seconds < 60) return `${seconds} s`
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h`
  return `${Math.round(seconds / 86400)} days`
}

export function when(iso?: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export const roleLabel: Record<string, string> = { guest: 'Guest', member: 'Member', administrator: 'Administrator' }
export const roleHint: Record<string, string> = {
  guest: 'read only', member: 'read, change existing', administrator: 'read, change, create, delete',
}
export const permissionTone = (p: string) => (p === 'full' ? 'amber' : p === 'write' ? 'blue' : 'grey') as 'amber' | 'blue' | 'grey'

/**
 * Revoking stops Cloud Safeguard handing a key out, but a real cloud cannot
 * cancel an STS key it already issued: it works until it expires (SECURITY.md
 * §6.3). Long-lived keys are different: revoking deletes the cloud user.
 */
export const STILL_VALID = 'A short-lived key already handed out keeps working in the cloud until it expires: the cloud cannot cancel it early.'
