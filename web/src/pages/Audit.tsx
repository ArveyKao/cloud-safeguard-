/** Audit log: filterable hash-chained events, chain verification, JSON detail. */
import { useEffect, useMemo, useState } from 'react'
import { listAudit, verifyAuditChain } from '../api/client'
import { useDebouncedValue, usePolling } from '../api/hooks'
import type { AuditEvent, AuditVerifyResult, ListResponse } from '../api/types'
import { cx, formatDateTime, formatRelative } from '../lib/format'
import { Modal } from '../components/overlays'
import {
  Button,
  CopyButton,
  EmptyState,
  ErrorBanner,
  Field,
  PageHeader,
  SeverityBadge,
  Skeleton,
  Switch,
} from '../components/primitives'
import { JsonView } from '../components/display'
import { useToast, describeError } from '../components/Toasts'
import {
  IconAudit,
  IconCheck,
  IconChevronDown,
  IconRefresh,
  IconSearch,
  IconShield,
  IconAlert,
} from '../components/icons'

interface AuditPageProps {
  refreshKey: number
}

const PAGE_SIZE = 50

const COMMON_ACTIONS = [
  'auth.admin_login',
  'auth.admin_auth_failed',
  'auth.agent_auth_failed',
  'provider.created',
  'provider.updated',
  'provider.credential_rotated',
  'provider.tested',
  'capability.created',
  'capability.updated',
  'agent.created',
  'agent.updated',
  'agent.suspended',
  'agent.activated',
  'agent.token_rotated',
  'lease.requested',
  'lease.auto_approved',
  'lease.approved',
  'lease.denied',
  'lease.credential_issued',
  'lease.credential_fetched',
  'lease.revoked',
  'lease.expired',
  'lease.failed',
  'policy.updated',
  'cloud.api_called',
  'cloud.api_denied',
]

const SINCE_OPTIONS = [
  { value: '', label: 'All time' },
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
]

function sinceIso(value: string): string | undefined {
  if (!value) return undefined
  const units: Record<string, number> = { h: 3_600_000, d: 86_400_000 }
  const match = /^(\d+)([hd])$/.exec(value)
  if (!match) return undefined
  const amount = Number(match[1])
  const unit = units[match[2]]
  return new Date(Date.now() - amount * unit).toISOString()
}

export function AuditPage({ refreshKey }: AuditPageProps) {
  const toast = useToast()
  const [action, setAction] = useState('')
  const [actorType, setActorType] = useState('')
  const [severity, setSeverity] = useState('')
  const [since, setSince] = useState('')
  const [offset, setOffset] = useState(0)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [selected, setSelected] = useState<AuditEvent | null>(null)
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [verifiedAt, setVerifiedAt] = useState<Date | null>(null)

  const debouncedAction = useDebouncedValue(action.trim(), 300)

  const audit = usePolling<ListResponse<AuditEvent>>(
    (signal) =>
      listAudit(
        {
          action: debouncedAction || undefined,
          actor_type: actorType || undefined,
          severity: severity || undefined,
          since: sinceIso(since),
          limit: PAGE_SIZE,
          offset,
        },
        signal,
      ),
    autoRefresh ? 5000 : 0,
    { deps: [refreshKey, debouncedAction, actorType, severity, since, offset] },
  )

  useEffect(() => {
    setOffset(0)
  }, [debouncedAction, actorType, severity, since])

  const items = audit.data?.items ?? []
  const total = audit.data?.total ?? 0

  async function verifyChain() {
    setVerifying(true)
    try {
      const result = await verifyAuditChain()
      setVerifyResult(result)
      setVerifiedAt(new Date())
      if (result.ok) toast.success('Audit chain verified', `${result.events} events linked and intact.`)
      else toast.error('Audit chain verification failed', result.message)
    } catch (cause) {
      toast.error('Verification failed', describeError(cause))
    } finally {
      setVerifying(false)
    }
  }

  const actorTypes = useMemo(() => ['agent', 'admin', 'system'], [])
  const hasFilters = Boolean(debouncedAction || actorType || severity || since)

  function clearFilters() {
    setAction('')
    setActorType('')
    setSeverity('')
    setSince('')
  }

  return (
    <div className="page">
      <PageHeader
        eyebrow="Accountability"
        title="Audit log"
        subtitle="Append-only, hash-chained record of every security-relevant action. Verify the chain at any time — a single mutated row breaks verification."
        metaLabel="Updated"
        metaValue={audit.lastUpdated ? formatDateTime(audit.lastUpdated.toISOString()) : '—'}
        actions={
          <>
            <Button
              variant="secondary"
              icon={<IconRefresh size={15} />}
              onClick={() => void audit.refresh()}
              disabled={audit.refreshing}
            >
              Refresh
            </Button>
            <Button
              variant="primary"
              icon={<IconShield size={15} />}
              loading={verifying}
              onClick={() => void verifyChain()}
            >
              Verify chain
            </Button>
          </>
        }
      />

      {audit.error && (
        <div style={{ marginBottom: 16 }}>
          <ErrorBanner
            error={audit.error}
            onRetry={() => void audit.refresh()}
            title="Audit events could not load"
          />
        </div>
      )}

      {verifyResult && (
        <div
          className={cx(
            'verify-panel',
            verifyResult.ok ? 'verify-panel--ok' : 'verify-panel--fail',
            'mb-16',
          )}
          style={{ marginBottom: 16 }}
          role="status"
        >
          <span className="verify-panel__icon" aria-hidden="true">
            {verifyResult.ok ? <IconCheck size={19} /> : <IconAlert size={19} />}
          </span>
          <div className="grow">
            <div className="verify-panel__title">
              {verifyResult.ok ? 'Audit chain verified' : 'Audit chain verification failed'}
              <span className={verifyResult.ok ? 'badge badge--active' : 'badge badge--denied'}>
                {verifyResult.ok ? 'intact' : 'tampered'}
              </span>
            </div>
            <div className="verify-panel__message">{verifyResult.message}</div>
            <div className="verify-panel__meta">
              <span>events: {verifyResult.events}</span>
              {!verifyResult.ok && verifyResult.first_invalid_seq ? (
                <span>first invalid seq: {verifyResult.first_invalid_seq}</span>
              ) : null}
              {verifiedAt && <span>verified: {formatDateTime(verifiedAt.toISOString())}</span>}
            </div>
          </div>
          <Button size="sm" variant="ghost" onClick={() => setVerifyResult(null)}>
            Dismiss
          </Button>
        </div>
      )}

      <div className="filter-bar" style={{ marginBottom: 16 }}>
        <div className="input-group" style={{ flex: 1, minWidth: 200, maxWidth: 320 }}>
          <span className="input-group__icon">
            <IconSearch size={15} />
          </span>
          <input
            className="input"
            placeholder="Exact action, e.g. lease.approved"
            value={action}
            onChange={(event) => setAction(event.target.value)}
            aria-label="Filter by action"
            list="audit-action-suggestions"
            autoComplete="off"
            spellCheck={false}
            title="Server-side filter: the action name must match exactly."
          />
          <datalist id="audit-action-suggestions">
            {COMMON_ACTIONS.map((name) => (
              <option key={name} value={name} />
            ))}
          </datalist>
        </div>
        <select
          className="select"
          value={actorType}
          onChange={(event) => setActorType(event.target.value)}
          aria-label="Filter by actor type"
        >
          <option value="">All actors</option>
          {actorTypes.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>
        <select
          className="select"
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          aria-label="Filter by severity"
        >
          <option value="">All severities</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="critical">Critical</option>
        </select>
        <select
          className="select"
          value={since}
          onChange={(event) => setSince(event.target.value)}
          aria-label="Filter by time"
        >
          {SINCE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        {hasFilters && (
          <Button variant="ghost" size="sm" onClick={clearFilters}>
            Clear
          </Button>
        )}
        <span className="toolbar__spacer" />
        <div className="auto-refresh">
          <Switch
            checked={autoRefresh}
            onChange={setAutoRefresh}
            label="Auto-refresh"
            ariaLabel="Auto-refresh audit events"
          />
        </div>
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col" style={{ width: 64 }}>
                Seq
              </th>
              <th scope="col">Time</th>
              <th scope="col">Action</th>
              <th scope="col">Actor</th>
              <th scope="col">Target</th>
              <th scope="col">Severity</th>
              <th scope="col">Hash</th>
            </tr>
          </thead>
          <tbody>
            {audit.loading && items.length === 0 ? (
              Array.from({ length: 8 }).map((_, index) => (
                <tr key={`skeleton-${index}`}>
                  {Array.from({ length: 7 }).map((__, cell) => (
                    <td key={cell}>
                      <Skeleton width={cell === 2 ? 150 : 80} />
                    </td>
                  ))}
                </tr>
              ))
            ) : items.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: 0, border: 'none' }}>
                  <div style={{ padding: 20 }}>
                    <EmptyState
                      icon={<IconAudit size={18} />}
                      title={hasFilters ? 'No events match these filters' : 'Audit log is empty'}
                      hint={
                        hasFilters
                          ? 'Action names must match exactly (start typing and pick a suggestion). Or clear the filters / widen the time window.'
                          : 'Requests, approvals, credential fetches and cloud API calls appear here as soon as they happen.'
                      }
                    />
                  </div>
                </td>
              </tr>
            ) : (
              items.map((event) => (
                <tr
                  key={event.id || event.seq}
                  className="is-clickable"
                  onClick={() => setSelected(event)}
                >
                  <td>
                    <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
                      {event.seq}
                    </span>
                  </td>
                  <td>
                    <div style={{ fontSize: 12.3 }}>{formatRelative(event.time)}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-faint)' }}>
                      {formatDateTime(event.time)}
                    </div>
                  </td>
                  <td>
                    <span className="audit-action">{event.action}</span>
                    {event.status !== 'ok' && (
                      <div style={{ marginTop: 3 }}>
                        <span
                          className={cx(
                            'badge',
                            event.status === 'denied' ? 'badge--denied' : 'badge--failed',
                          )}
                        >
                          {event.status}
                        </span>
                      </div>
                    )}
                  </td>
                  <td>
                    <div className="audit-actor">
                      <span>{event.actor_type}</span>
                      <span className="audit-actor__id">
                        {event.actor_name || event.actor_id || 'system'}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                      {event.target_type || '—'}
                    </div>
                    <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-faint)' }}>
                      {event.target_id || ''}
                    </div>
                  </td>
                  <td>
                    <SeverityBadge severity={event.severity} />
                  </td>
                  <td>
                    <span className="hash-cell" title={event.hash}>
                      {event.hash ? `${event.hash.slice(0, 10)}…` : '—'}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        <div className="pagination">
          <span>
            {total === 0
              ? 'No events'
              : `Showing ${offset + 1}–${Math.min(offset + items.length, total)} of ${total} events`}
            {autoRefresh && <span className="muted"> · refreshing every 5s while visible</span>}
          </span>
          <div className="pagination__actions">
            <Button
              size="sm"
              variant="secondary"
              disabled={offset === 0}
              onClick={() => setOffset((current) => Math.max(0, current - PAGE_SIZE))}
            >
              Previous
            </Button>
            <Button
              size="sm"
              variant="secondary"
              disabled={offset + PAGE_SIZE >= total}
              onClick={() => setOffset((current) => current + PAGE_SIZE)}
            >
              Next <IconChevronDown size={13} style={{ transform: 'rotate(-90deg)' }} />
            </Button>
          </div>
        </div>
      </div>

      <div className="row gap-8 muted" style={{ fontSize: 11.5, marginTop: 12 }}>
        <IconShield size={13} />
        Each event commits to the previous hash: sha256("csg-audit-v1\n" + prev_hash + "\n" +
        canonical_event). Click a row to inspect the full record.
      </div>

      <AuditEventModal event={selected} onClose={() => setSelected(null)} />
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Event detail modal                                                  */
/* ------------------------------------------------------------------ */

function AuditEventModal({ event, onClose }: { event: AuditEvent | null; onClose: () => void }) {
  if (!event) return null
  const raw = JSON.stringify(event, null, 2)
  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title={
        <span className="row gap-8" style={{ flexWrap: 'wrap' }}>
          Audit event <span className="mono" style={{ fontSize: 13 }}>#{event.seq}</span>
          <SeverityBadge severity={event.severity} />
        </span>
      }
      subtitle={event.action}
      footer={
        <>
          <CopyButton value={raw} label="Copy event JSON" />
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
        </>
      }
    >
      <div className="stack" style={{ gap: 14 }}>
        <div className="meta-list">
          <div className="meta-item">
            <div className="meta-item__label">Time</div>
            <div className="meta-item__value">{formatDateTime(event.time)}</div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Event ID</div>
            <div className="meta-item__value mono">{event.id}</div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Actor</div>
            <div className="meta-item__value">
              {event.actor_type} · {event.actor_name || event.actor_id}
            </div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Status</div>
            <div className="meta-item__value">{event.status}</div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Target</div>
            <div className="meta-item__value mono">
              {event.target_type}
              {event.target_id ? `/${event.target_id}` : ''}
            </div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Prev hash</div>
            <div className="meta-item__value mono" style={{ fontSize: 10.5, wordBreak: 'break-all' }}>
              {event.prev_hash}
            </div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Hash</div>
            <div className="meta-item__value mono" style={{ fontSize: 10.5, wordBreak: 'break-all' }}>
              {event.hash}
            </div>
          </div>
        </div>

        <Field label="Metadata">
          <JsonView value={event.metadata ?? {}} maxHeight={220} />
        </Field>

        <details>
          <summary
            className="field__label"
            style={{ cursor: 'pointer', padding: '4px 0', listStyle: 'none' }}
          >
            Full event JSON
          </summary>
          <div style={{ marginTop: 8 }}>
            <JsonView raw={raw} maxHeight={320} />
          </div>
        </details>
      </div>
    </Modal>
  )
}
