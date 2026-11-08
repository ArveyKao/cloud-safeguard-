/** Read-only display widgets: JSON viewer, risk distribution, countdowns. */
import { Fragment } from 'react'
import type { ReactNode } from 'react'
import type { RiskBreakdown, RiskTier } from '../api/types'
import { RISK_ORDER } from '../api/types'
import { serverNow, useNow } from '../api/hooks'
import { cx, formatCountdown, formatRelative, prettyJson, formatDateTime } from '../lib/format'

/* ------------------------------------------------------------------ */
/* JSON viewer                                                         */
/* ------------------------------------------------------------------ */

const JSON_TOKEN = /("(?:\\.|[^"\\])*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b|([{}[\],:])/g

function highlightJson(text: string): ReactNode {
  const nodes: ReactNode[] = []
  let lastIndex = 0
  let key = 0
  for (const match of text.matchAll(JSON_TOKEN)) {
    const index = match.index ?? 0
    if (index > lastIndex) nodes.push(<Fragment key={`t${key++}`}>{text.slice(lastIndex, index)}</Fragment>)
    const [token, str, num, bool, punct] = match
    if (str !== undefined) {
      const rest = text.slice(index + token.length)
      const isKey = /^\s*:/.test(rest)
      nodes.push(
        <span key={`k${key++}`} className={isKey ? 'json-key' : 'json-string'}>
          {token}
        </span>,
      )
    } else if (num !== undefined) {
      nodes.push(
        <span key={`n${key++}`} className="json-number">
          {token}
        </span>,
      )
    } else if (bool !== undefined) {
      const cls = bool === 'null' ? 'json-null' : 'json-boolean'
      nodes.push(
        <span key={`b${key++}`} className={cls}>
          {token}
        </span>,
      )
    } else if (punct !== undefined) {
      nodes.push(
        <span key={`p${key++}`} className="json-punct">
          {token}
        </span>,
      )
    }
    lastIndex = index + token.length
  }
  if (lastIndex < text.length) nodes.push(<Fragment key={`t${key++}`}>{text.slice(lastIndex)}</Fragment>)
  return <>{nodes}</>
}

export function JsonView({
  value,
  raw,
  maxHeight,
}: {
  value?: unknown
  raw?: string
  maxHeight?: number
}) {
  const text = raw ?? prettyJson(value)
  return (
    <pre
      className="json-view"
      style={maxHeight ? { maxHeight } : undefined}
      aria-label="JSON document"
      tabIndex={0}
    >
      {highlightJson(text)}
    </pre>
  )
}

/* ------------------------------------------------------------------ */
/* Risk distribution                                                   */
/* ------------------------------------------------------------------ */

const RISK_LABEL: Record<RiskTier, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
}

export function RiskBar({ risk }: { risk: RiskBreakdown }) {
  const total = Math.max(risk.low + risk.medium + risk.high + risk.critical, 0)
  return (
    <div className="risk-panel">
      <div className="risk-panel__total">
        <div>
          <div className="risk-panel__total-value">{total}</div>
          <div className="risk-panel__total-label">leases in flight (active + pending)</div>
        </div>
        <div className="row gap-6" style={{ flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {total > 0 &&
            RISK_ORDER.filter((tier) => risk[tier] > 0).map((tier) => (
              <span key={tier} className={cx('badge', `badge--${tier}`)}>
                {risk[tier]} {RISK_LABEL[tier]}
              </span>
            ))}
        </div>
      </div>
      <div
        className="risk-bar"
        role="img"
        aria-label={`Risk distribution: ${RISK_ORDER.map((tier) => `${risk[tier]} ${tier}`).join(', ')}`}
      >
        {RISK_ORDER.map((tier) =>
          risk[tier] > 0 ? (
            <span
              key={tier}
              className={cx('risk-bar__seg', `risk-bar__seg--${tier}`)}
              style={{ width: `${(risk[tier] / total) * 100}%` }}
            />
          ) : null,
        )}
      </div>
      <div className="risk-legend">
        {RISK_ORDER.map((tier) => (
          <div key={tier} className="risk-legend__item">
            <span className={cx('risk-legend__dot', `risk-legend__dot--${tier}`)} />
            {RISK_LABEL[tier]}
            <span className="risk-legend__value">{risk[tier]}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Time displays                                                       */
/* ------------------------------------------------------------------ */

export function LeaseCountdown({
  expiresAt,
  className,
  title,
}: {
  expiresAt?: string | null
  className?: string
  title?: string
}) {
  const now = useNow(1000)
  if (!expiresAt) return <span className={cx('countdown', className)}>—</span>
  const target = Date.parse(expiresAt)
  if (Number.isNaN(target)) return <span className={cx('countdown', className)}>—</span>
  // `now` drives the per-second re-render; the server clock offset is applied here.
  void now
  const remaining = target - serverNow()
  const urgent = remaining <= 30_000
  const warn = remaining <= 120_000
  return (
    <span
      className={cx('countdown', urgent && 'countdown--urgent', !urgent && warn && 'countdown--warn', className)}
      title={title ?? `Expires ${formatDateTime(expiresAt)}`}
    >
      {formatCountdown(remaining)}
    </span>
  )
}

export function RelativeTime({ iso, className }: { iso?: string | null; className?: string }) {
  const now = useNow(15_000)
  return (
    <span className={className} title={iso ? formatDateTime(iso) : undefined}>
      {formatRelative(iso, now)}
    </span>
  )
}
