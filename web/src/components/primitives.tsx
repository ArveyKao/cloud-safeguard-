/** Shared presentation primitives for the console. */
import { useEffect, useId, useRef, useState } from 'react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { ApiError } from '../api/client'
import type { Capability, Lease, LeaseStatus, ProviderMode, RiskTier, Severity } from '../api/types'
import { RISK_ORDER } from '../api/types'
import { cx, titleCase } from '../lib/format'
import { IconAlert, IconCheck, IconCopy, IconInfo, IconX } from './icons'

/* ------------------------------------------------------------------ */
/* Button                                                              */
/* ------------------------------------------------------------------ */

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-solid'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: 'sm' | 'md' | 'lg'
  icon?: ReactNode
  loading?: boolean
  block?: boolean
}

export function Button({
  variant = 'secondary',
  size = 'md',
  icon,
  loading = false,
  block = false,
  className,
  children,
  disabled,
  type = 'button',
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type}
      className={cx(
        'btn',
        `btn--${variant}`,
        size === 'sm' && 'btn--sm',
        size === 'lg' && 'btn--lg',
        block && 'btn--block',
        className,
      )}
      disabled={disabled || loading}
      {...rest}
    >
      {loading ? <span className="spinner btn__spinner" aria-hidden="true" /> : icon}
      {children}
    </button>
  )
}

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string
  size?: 'sm' | 'md'
  variant?: 'ghost' | 'secondary' | 'danger'
}

export function IconButton({
  label,
  size = 'md',
  variant = 'ghost',
  className,
  children,
  type = 'button',
  ...rest
}: IconButtonProps) {
  return (
    <button
      type={type}
      aria-label={label}
      title={label}
      className={cx('btn', 'btn--icon', `btn--${variant}`, size === 'sm' && 'btn--sm', className)}
      {...rest}
    >
      {children}
    </button>
  )
}

/* ------------------------------------------------------------------ */
/* Panels                                                              */
/* ------------------------------------------------------------------ */

interface PanelProps {
  title?: ReactNode
  subtitle?: ReactNode
  icon?: ReactNode
  actions?: ReactNode
  footer?: ReactNode
  children: ReactNode
  className?: string
  bodyClassName?: string
  flush?: boolean
}

export function Panel({
  title,
  subtitle,
  icon,
  actions,
  footer,
  children,
  className,
  bodyClassName,
  flush = false,
}: PanelProps) {
  return (
    <section className={cx('panel', flush && 'panel--flush', className)}>
      {(title || actions) && (
        <header className="panel__header">
          <div>
            <div className="panel__title">
              {icon}
              {title}
            </div>
            {subtitle && <div className="panel__subtitle">{subtitle}</div>}
          </div>
          {actions && <div className="row gap-8">{actions}</div>}
        </header>
      )}
      <div className={cx('panel__body', bodyClassName)}>{children}</div>
      {footer && <footer className="panel__footer">{footer}</footer>}
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* Badges                                                              */
/* ------------------------------------------------------------------ */

const LEASE_STATUS_LABEL: Record<LeaseStatus, string> = {
  pending: 'Pending',
  active: 'Active',
  denied: 'Denied',
  expired: 'Expired',
  revoked: 'Revoked',
  failed: 'Failed',
}

const LEASE_STATUS_CLASS: Record<LeaseStatus, string> = {
  pending: 'pending',
  active: 'active',
  denied: 'denied',
  expired: 'expired',
  revoked: 'revoked',
  failed: 'failed',
}

export function RiskBadge({ risk }: { risk: RiskTier }) {
  return (
    <span className={cx('badge', 'badge--dot', `badge--${risk}`)} title={`Risk tier: ${risk}`}>
      {risk}
    </span>
  )
}

export function LeaseStatusBadge({ status }: { status: LeaseStatus }) {
  return (
    <span className={cx('badge', 'badge--dot', `badge--${LEASE_STATUS_CLASS[status]}`)}>
      {LEASE_STATUS_LABEL[status]}
    </span>
  )
}

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const known: Severity =
    severity === 'critical' || severity === 'warning' || severity === 'info'
      ? severity
      : 'info'
  return (
    <span className={cx('badge', `badge--${known === 'info' ? 'sky' : known}`)}>
      {titleCase(severity)}
    </span>
  )
}

export function DecisionBadge({ outcome }: { outcome: string }) {
  const labels: Record<string, string> = {
    auto_approve: 'Auto-approved',
    require_approval: 'Needs approval',
    deny: 'Denied',
  }
  const cls: Record<string, string> = {
    auto_approve: 'badge--active',
    require_approval: 'badge--pending',
    deny: 'badge--denied',
  }
  return (
    <span className={cx('badge', cls[outcome] ?? 'badge--neutral')}>
      {labels[outcome] ?? titleCase(outcome)}
    </span>
  )
}

export function ModeBadge({ mode }: { mode: ProviderMode }) {
  return (
    <span className={cx('badge', mode === 'mock' ? 'badge--purple' : 'badge--sky')}>
      {mode === 'mock' ? 'mock cloud' : 'aliyun sts'}
    </span>
  )
}

export function StatusBadge({ status }: { status: string }) {
  const allowed = ['active', 'suspended', 'revoked', 'disabled']
  const cls = allowed.includes(status) ? status : 'neutral'
  return <span className={cx('badge', 'badge--dot', `badge--${cls}`)}>{titleCase(status)}</span>
}

export function OutcomeIcon({ outcome }: { outcome: string }) {
  if (outcome === 'allow') return <IconCheck size={13} />
  if (outcome === 'deny') return <IconX size={13} />
  return <IconAlert size={13} />
}

/* ------------------------------------------------------------------ */
/* Form field                                                          */
/* ------------------------------------------------------------------ */

interface FieldProps {
  label: ReactNode
  htmlFor?: string
  hint?: ReactNode
  error?: ReactNode
  required?: boolean
  children: ReactNode
  className?: string
}

export function Field({ label, htmlFor, hint, error, required, children, className }: FieldProps) {
  return (
    <div className={cx('field', className)}>
      <label className="field__label" htmlFor={htmlFor}>
        {label}
        {required && (
          <span className="req" aria-hidden="true">
            required
          </span>
        )}
      </label>
      {children}
      {error ? (
        <div className="field__error" role="alert">
          {error}
        </div>
      ) : (
        hint && <div className="field__hint">{hint}</div>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Switch                                                              */
/* ------------------------------------------------------------------ */

interface SwitchProps {
  checked: boolean
  onChange: (checked: boolean) => void
  label?: ReactNode
  disabled?: boolean
  ariaLabel?: string
}

export function Switch({ checked, onChange, label, disabled, ariaLabel }: SwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      className="switch"
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span className="switch__track">
        <span className="switch__thumb" />
      </span>
      {label && <span className="switch__label">{label}</span>}
    </button>
  )
}

/* ------------------------------------------------------------------ */
/* Skeleton / empty / error states                                     */
/* ------------------------------------------------------------------ */

export function Skeleton({
  width,
  height = 12,
  className,
  style,
}: {
  width?: number | string
  height?: number | string
  className?: string
  style?: React.CSSProperties
}) {
  return (
    <span
      className={cx('skeleton', className)}
      style={{ width: width ?? '100%', height, ...style }}
      aria-hidden="true"
    />
  )
}

export function SkeletonText({ lines = 3 }: { lines?: number }) {
  return (
    <div>
      {Array.from({ length: lines }).map((_, index) => (
        <Skeleton
          key={index}
          className="sk-line"
          width={index === lines - 1 ? '62%' : '100%'}
        />
      ))}
    </div>
  )
}

export function EmptyState({
  icon,
  title,
  hint,
  action,
}: {
  icon?: ReactNode
  title: string
  hint?: ReactNode
  action?: ReactNode
}) {
  return (
    <div className="empty">
      {icon && <div className="empty__icon">{icon}</div>}
      <div className="empty__title">{title}</div>
      {hint && <div className="empty__hint">{hint}</div>}
      {action && <div className="empty__action">{action}</div>}
    </div>
  )
}

export function ErrorBanner({
  error,
  onRetry,
  title = 'Could not load data',
}: {
  error: ApiError | Error | string | null | undefined
  onRetry?: () => void
  title?: string
}) {
  if (!error) return null
  const message = typeof error === 'string' ? error : error.message
  const code = error instanceof ApiError ? error.code : null
  return (
    <div className="banner banner--error" role="alert">
      <IconAlert size={16} />
      <div className="grow">
        <div className="banner__title">
          {title}
          {code && error instanceof ApiError && error.status > 0 ? (
            <span className="mono" style={{ marginLeft: 8, opacity: 0.7, fontWeight: 400 }}>
              {code} · HTTP {error.status}
            </span>
          ) : null}
        </div>
        <div>{message}</div>
      </div>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  )
}

export function InlineNotice({
  kind = 'info',
  title,
  children,
}: {
  kind?: 'info' | 'warning' | 'success' | 'error'
  title?: ReactNode
  children: ReactNode
}) {
  const icon =
    kind === 'success' ? (
      <IconCheck size={16} />
    ) : kind === 'warning' || kind === 'error' ? (
      <IconAlert size={16} />
    ) : (
      <IconInfo size={16} />
    )
  return (
    <div className={cx('banner', `banner--${kind}`)}>
      {icon}
      <div className="grow">
        {title && <div className="banner__title">{title}</div>}
        <div>{children}</div>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Copy button                                                         */
/* ------------------------------------------------------------------ */

export function CopyButton({
  value,
  label = 'Copy',
  className,
  onCopied,
}: {
  value: string
  label?: string
  className?: string
  onCopied?: () => void
}) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<number | undefined>(undefined)

  useEffect(() => () => window.clearTimeout(timer.current), [])

  async function copy() {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value)
      } else {
        const area = document.createElement('textarea')
        area.value = value
        area.style.position = 'fixed'
        area.style.opacity = '0'
        document.body.appendChild(area)
        area.select()
        document.execCommand('copy')
        document.body.removeChild(area)
      }
      setCopied(true)
      onCopied?.()
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(() => setCopied(false), 1800)
    } catch {
      /* Clipboard can be blocked by browser policy; the value stays selectable. */
    }
  }

  return (
    <button
      type="button"
      className={cx('copy-btn', copied && 'copy-btn--copied', className)}
      onClick={() => void copy()}
      aria-live="polite"
    >
      {copied ? <IconCheck size={12} /> : <IconCopy size={12} />}
      {copied ? 'Copied' : label}
    </button>
  )
}

/* ------------------------------------------------------------------ */
/* Page header                                                         */
/* ------------------------------------------------------------------ */

export function PageHeader({
  eyebrow,
  title,
  subtitle,
  actions,
  metaLabel,
  metaValue,
}: {
  eyebrow: string
  title: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  metaLabel?: string
  metaValue?: ReactNode
}) {
  return (
    <header className="page-header">
      <div className="page-header__text">
        <div className="page-eyebrow">{eyebrow}</div>
        <h1 className="page-title">{title}</h1>
        {subtitle && <div className="page-subtitle">{subtitle}</div>}
      </div>
      {(actions || metaValue) && (
        <div className="page-actions">
          {metaValue && (
            <div className="page-actions__meta">
              <span className="page-actions__meta-label">{metaLabel ?? 'Updated'}</span>
              <span className="page-actions__meta-value">{metaValue}</span>
            </div>
          )}
          {actions}
        </div>
      )}
    </header>
  )
}

/* ------------------------------------------------------------------ */
/* Misc                                                                */
/* ------------------------------------------------------------------ */

export function StatCard({
  label,
  value,
  suffix,
  sub,
  icon,
  tone = 'accent',
  attention = false,
  loading = false,
}: {
  label: string
  value: ReactNode
  suffix?: ReactNode
  sub?: ReactNode
  icon?: ReactNode
  tone?: 'accent' | 'amber' | 'rose' | 'sky' | 'violet'
  attention?: boolean
  loading?: boolean
}) {
  return (
    <div className={cx('stat-card', tone !== 'accent' && `stat-card--${tone}`, attention && 'stat-card--attention')}>
      <div className="stat-card__top">
        <span className="stat-card__label">{label}</span>
        {icon && <span className="stat-card__icon">{icon}</span>}
      </div>
      <div className="stat-card__value">
        {loading ? <Skeleton width={56} height={30} /> : value}
        {suffix && <small>{suffix}</small>}
      </div>
      <div className="stat-card__sub">{sub}</div>
    </div>
  )
}

/** Ordered risk legend used by the overview distribution panel. */
export function riskEntries(risk: { low: number; medium: number; high: number; critical: number }) {
  return RISK_ORDER.map((tier) => ({ tier, count: risk[tier] }))
}

export function capabilityMaxTtl(
  capabilities: Capability[] | null | undefined,
  capabilityId: string,
): number | null {
  const found = capabilities?.find((cap) => cap.id === capabilityId)
  return found ? found.max_ttl_seconds : null
}

export function leaseIsPending(lease: Lease): boolean {
  return lease.status === 'pending'
}

export function useAutoFocus<T extends HTMLElement>(active: boolean): React.RefObject<T> {
  const ref = useRef<T>(null)
  useEffect(() => {
    if (active) {
      const timer = window.setTimeout(() => ref.current?.focus(), 30)
      return () => window.clearTimeout(timer)
    }
  }, [active])
  return ref
}

export function useElementId(prefix: string): string {
  const id = useId()
  return `${prefix}-${id.replace(/[^a-zA-Z0-9_-]/g, '')}`
}
