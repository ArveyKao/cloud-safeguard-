/** Full lease detail modal: decision trail, params, timeline, operator actions. */
import type { Capability, Lease, PolicySettings } from '../api/types'
import { formatDateTime, formatTTL, titleCase } from '../lib/format'
import { Modal } from './overlays'
import {
  CopyButton,
  EmptyState,
  LeaseStatusBadge,
  OutcomeIcon,
  RiskBadge,
} from './primitives'
import { JsonView } from './display'
import { LeaseCountdown } from './display'
import { LeaseDecisionActions } from './LeaseDecision'
import { IconActivity, IconCheck, IconClock, IconKey, IconLeases, IconX } from './icons'

interface LeaseDetailModalProps {
  lease: Lease | null
  capabilities: Capability[] | null
  policy: PolicySettings | null
  onClose: () => void
  onUpdated: (lease: Lease) => void
}

interface TimelineEntry {
  label: string
  time: string
  tone: 'accent' | 'amber' | 'rose' | 'muted'
}

function buildTimeline(lease: Lease): TimelineEntry[] {
  const entries: TimelineEntry[] = [
    { label: 'Requested by agent', time: lease.created_at, tone: 'accent' },
  ]
  const outcome = lease.decision?.outcome
  if (outcome === 'auto_approve') {
    entries.push({ label: 'Policy auto-approved', time: lease.created_at, tone: 'accent' })
  } else if (outcome === 'deny') {
    entries.push({ label: 'Denied by policy', time: lease.created_at, tone: 'rose' })
  }
  if (lease.approved_at) {
    entries.push({
      label: `Approved by ${lease.approved_by || 'operator'}`,
      time: lease.approved_at,
      tone: 'accent',
    })
  }
  if (lease.issued_at) {
    entries.push({ label: 'Credential issued', time: lease.issued_at, tone: 'accent' })
  }
  if (lease.expires_at) {
    entries.push({ label: 'Expiry (TTL)', time: lease.expires_at, tone: 'amber' })
  }
  if (lease.revoked_at) {
    entries.push({ label: 'Revoked', time: lease.revoked_at, tone: 'rose' })
  }
  if (lease.status === 'failed') {
    entries.push({ label: 'Credential minting failed', time: lease.created_at, tone: 'rose' })
  }
  return entries
}

const TIMELINE_DOT: Record<TimelineEntry['tone'], string> = {
  accent: 'timeline-item__dot--accent',
  amber: 'timeline-item__dot--amber',
  rose: 'timeline-item__dot--rose',
  muted: '',
}

export function LeaseDetailModal({
  lease,
  capabilities,
  policy,
  onClose,
  onUpdated,
}: LeaseDetailModalProps) {
  if (!lease) return null
  const params = lease.params ?? {}
  const timeline = buildTimeline(lease)
  const reasons = lease.decision?.reasons ?? []
  const isOpen = lease.status === 'pending'

  return (
    <Modal
      open
      onClose={onClose}
      size="xl"
      title={
        <span className="row gap-8" style={{ flexWrap: 'wrap' }}>
          Lease
          <span className="mono" style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            {lease.id}
          </span>
          <LeaseStatusBadge status={lease.status} />
        </span>
      }
      subtitle={
        isOpen
          ? 'This request is waiting for a human decision. Approving mints a scoped credential now.'
          : 'Immutable record of the request, policy decision and credential lifecycle.'
      }
      footer={
        <>
          <span className="muted" style={{ fontSize: 11.5, marginRight: 'auto' }}>
            Lease data refreshes with the console; credential material is never displayed here.
          </span>
          <button type="button" className="btn btn--secondary" onClick={onClose}>
            Close
          </button>
        </>
      }
    >
      <div className="stack" style={{ gap: 18 }}>
        <div className="lease-hero">
          <span className="lease-hero__mark" aria-hidden="true">
            <IconLeases size={20} />
          </span>
          <div className="lease-hero__main">
            <div className="lease-hero__title">
              {lease.capability_name || lease.capability_id}
              <RiskBadge risk={lease.risk} />
              {lease.break_glass && <span className="badge badge--critical">break-glass</span>}
            </div>
            <div className="lease-hero__sub">{lease.capability_id}</div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div className="meta-item__label">Requested</div>
            <div style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>
              {formatDateTime(lease.created_at)}
            </div>
          </div>
        </div>

        {isOpen && (
          <LeaseDecisionActions
            lease={lease}
            capabilities={capabilities}
            policy={policy}
            onUpdated={onUpdated}
          />
        )}

        <div className="lease-detail-grid">
          <div className="stack" style={{ gap: 18 }}>
            <div className="meta-list">
              <div className="meta-item">
                <div className="meta-item__label">Agent</div>
                <div className="meta-item__value">
                  {lease.agent_name}
                  <div className="mono muted" style={{ fontSize: 10.5, marginTop: 1 }}>
                    {lease.agent_id}
                  </div>
                </div>
              </div>
              <div className="meta-item">
                <div className="meta-item__label">Provider</div>
                <div className="meta-item__value">
                  {lease.provider_name || lease.provider_id}
                  <div className="mono muted" style={{ fontSize: 10.5, marginTop: 1 }}>
                    {lease.provider_mode} · {lease.provider_id}
                  </div>
                </div>
              </div>
              <div className="meta-item">
                <div className="meta-item__label">Requested TTL</div>
                <div className="meta-item__value">{formatTTL(lease.requested_ttl_seconds)}</div>
              </div>
              <div className="meta-item">
                <div className="meta-item__label">Effective TTL</div>
                <div className="meta-item__value">{formatTTL(lease.effective_ttl_seconds)}</div>
              </div>
              <div className="meta-item">
                <div className="meta-item__label">Decision</div>
                <div className="meta-item__value">{titleCase(lease.decision?.outcome ?? '—')}</div>
              </div>
              <div className="meta-item">
                <div className="meta-item__label">Approved by</div>
                <div className="meta-item__value">{lease.approved_by || '—'}</div>
              </div>
              {lease.expires_at && (
                <div className="meta-item">
                  <div className="meta-item__label">Expires</div>
                  <div className="meta-item__value">
                    {formatDateTime(lease.expires_at)}
                    {lease.status === 'active' && (
                      <span style={{ marginLeft: 8 }}>
                        <LeaseCountdown expiresAt={lease.expires_at} />
                      </span>
                    )}
                  </div>
                </div>
              )}
              <div className="meta-item">
                <div className="meta-item__label">Session name</div>
                <div className="meta-item__value mono">{lease.session_name || '—'}</div>
              </div>
            </div>

            {Object.keys(params).length > 0 && (
              <div className="drawer-section">
                <div className="drawer-section__title">Parameters</div>
                <div className="row wrap gap-6">
                  {Object.entries(params).map(([key, value]) => (
                    <span className="chip chip--key" key={key}>
                      <span className="chip__label">{key}</span>
                      {value}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {lease.reason && (
              <div className="drawer-section">
                <div className="drawer-section__title">Stated reason</div>
                <div className="approval-item__reason" style={{ fontStyle: 'normal' }}>
                  {lease.reason}
                </div>
              </div>
            )}

            {(lease.approval_note || lease.denied_reason || lease.revoke_reason || lease.failure_reason) && (
              <div className="drawer-section">
                <div className="drawer-section__title">Operator / provider notes</div>
                <div className="stack gap-8">
                  {lease.approval_note && (
                    <div className="banner banner--success">
                      <IconCheck size={15} />
                      <div>
                        <div className="banner__title">Approval note</div>
                        {lease.approval_note}
                      </div>
                    </div>
                  )}
                  {lease.denied_reason && (
                    <div className="banner banner--error">
                      <IconX size={15} />
                      <div>
                        <div className="banner__title">Denied</div>
                        {lease.denied_reason}
                      </div>
                    </div>
                  )}
                  {lease.revoke_reason && (
                    <div className="banner banner--error">
                      <IconX size={15} />
                      <div>
                        <div className="banner__title">Revoked</div>
                        {lease.revoke_reason}
                      </div>
                    </div>
                  )}
                  {lease.failure_reason && (
                    <div className="banner banner--warning">
                      <IconActivity size={15} />
                      <div>
                        <div className="banner__title">Provider failure</div>
                        {lease.failure_reason}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            <div className="drawer-section">
              <div className="drawer-section__title">Policy decision trail</div>
              {reasons.length === 0 ? (
                <EmptyState title="No decision reasons recorded" hint="The policy engine returned no rule evaluations." />
              ) : (
                <div className="decision-list">
                  {reasons.map((reason, index) => (
                    <div className="decision-rule" key={`${reason.rule}-${index}`}>
                      <span className={`decision-rule__icon decision-rule__icon--${reason.outcome}`}>
                        <OutcomeIcon outcome={reason.outcome} />
                      </span>
                      <div>
                        <div className="decision-rule__rule">
                          {reason.rule}
                          <span className="mono muted" style={{ fontSize: 10 }}>
                            {reason.outcome.replace('_', ' ')}
                          </span>
                        </div>
                        <div className="decision-rule__detail">{reason.detail}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="stack" style={{ gap: 18 }}>
            <div className="drawer-section">
              <div className="drawer-section__title">Timeline</div>
              <div className="lease-timeline">
                {timeline.map((entry, index) => (
                  <div className="timeline-item" key={`${entry.label}-${index}`}>
                    <span className={`timeline-item__dot ${TIMELINE_DOT[entry.tone]}`} />
                    <div>
                      <div className="timeline-item__label">{entry.label}</div>
                      <div className="timeline-item__time">{formatDateTime(entry.time)}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel" style={{ boxShadow: 'none' }}>
              <div className="panel__body" style={{ padding: 14 }}>
                <div className="row-between" style={{ marginBottom: 10 }}>
                  <div className="drawer-section__title" style={{ margin: 0 }}>
                    Credential
                  </div>
                  {lease.credential_available ? (
                    <span className="badge badge--active">fetchable</span>
                  ) : (
                    <span className="badge badge--neutral">not available</span>
                  )}
                </div>
                <div className="meta-item__label">Masked fingerprint</div>
                <div className="mono" style={{ fontSize: 12.5, color: 'var(--text)', marginTop: 2 }}>
                  {lease.credential_fingerprint || '—'}
                </div>
                <hr className="divider" style={{ margin: '12px 0' }} />
                <div className="row gap-8" style={{ alignItems: 'flex-start' }}>
                  <IconKey size={14} style={{ color: 'var(--text-muted)', marginTop: 2 }} />
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                    The STS credential itself is stored encrypted and never returned to this
                    console. Agents fetch it through their scoped credential endpoint.
                  </div>
                </div>
              </div>
            </div>

            {lease.status === 'active' && (
              <div className="drawer-section">
                <div className="drawer-section__title">Operator actions</div>
                <LeaseDecisionActions
                  lease={lease}
                  capabilities={capabilities}
                  policy={policy}
                  onUpdated={onUpdated}
                />
              </div>
            )}

            {lease.decision?.reasons && lease.decision.reasons.length > 0 && (
              <div className="drawer-section">
                <div className="drawer-section__title">
                  <span>Raw decision</span>
                  <CopyButton value={JSON.stringify(lease.decision, null, 2)} label="Copy JSON" />
                </div>
                <JsonView value={lease.decision} maxHeight={210} />
              </div>
            )}

            <div className="row gap-6 muted" style={{ fontSize: 11 }}>
              <IconClock size={13} />
              All timestamps are rendered in your local timezone.
            </div>
          </div>
        </div>
      </div>
    </Modal>
  )
}
