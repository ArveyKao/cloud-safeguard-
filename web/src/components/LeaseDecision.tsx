/**
 * Approve / deny / revoke controls shared by the overview queue, the leases
 * table and the lease detail modal. All mutations go through the typed client;
 * the server remains the authority for limits and policy.
 */
import { useState } from 'react'
import type { Capability, Lease, PolicySettings } from '../api/types'
import { approveLease, denyLease, revokeLease } from '../api/client'
import { useMutation } from '../api/hooks'
import { cx, formatTTL, parseDurationInput } from '../lib/format'
import { Button } from './primitives'
import { ConfirmDialog } from './ConfirmDialog'
import { useToast, describeError } from './Toasts'
import { IconBan, IconCheck, IconX } from './icons'

interface BaseProps {
  lease: Lease
  capabilities?: Capability[] | null
  policy?: PolicySettings | null
  onUpdated: (lease: Lease) => void
}

export function leaseMaxTtl(
  lease: Lease,
  capabilities: Capability[] | null | undefined,
  policy: PolicySettings | null | undefined,
): number | null {
  const cap = capabilities?.find((item) => item.id === lease.capability_id)
  const limits = [cap?.max_ttl_seconds, policy?.max_lease_ttl_seconds].filter(
    (value): value is number => typeof value === 'number' && value > 0,
  )
  return limits.length > 0 ? Math.min(...limits) : null
}

/* ------------------------------------------------------------------ */
/* Approve form                                                        */
/* ------------------------------------------------------------------ */

export function ApproveLeaseForm({
  lease,
  capabilities,
  policy,
  onCancel,
  onUpdated,
}: BaseProps & { onCancel: () => void }) {
  const toast = useToast()
  const maxTtl = leaseMaxTtl(lease, capabilities, policy)
  const [ttlInput, setTtlInput] = useState(() => formatTTL(lease.effective_ttl_seconds || lease.requested_ttl_seconds))
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | null>(null)

  const mutation = useMutation(async () => {
    const trimmed = ttlInput.trim()
    let ttlSeconds = 0
    if (trimmed !== '') {
      const parsed = parseDurationInput(trimmed)
      if (parsed === null) throw new Error('Enter a duration such as 10m, 30m or 900.')
      if (parsed <= 0) throw new Error('TTL must be greater than zero.')
      if (maxTtl !== null && parsed > maxTtl) {
        throw new Error(`TTL must be at most ${formatTTL(maxTtl)} for this lease.`)
      }
      ttlSeconds = parsed
    }
    return approveLease(lease.id, { ttl_seconds: ttlSeconds, note: note.trim() })
  })

  async function submit() {
    setError(null)
    try {
      const updated = await mutation.run()
      if (updated.status === 'failed') {
        toast.warning(
          'Approved, but credential minting failed',
          updated.failure_reason ?? 'The provider could not mint a credential. See the lease for details.',
        )
      } else {
        toast.success('Lease approved', `Credential issued to ${lease.agent_name}.`)
      }
      onUpdated(updated)
    } catch (cause) {
      setError(describeError(cause))
    }
  }

  const quickTtls = [300, 600, 900, 1800, 3600].filter(
    (seconds) => maxTtl === null || seconds <= maxTtl,
  )

  return (
    <div className="approval-form">
      <div className="approval-form__title">
        <IconCheck size={14} />
        Approve this lease
        {maxTtl !== null && (
          <span className="muted" style={{ fontWeight: 400, fontSize: 11.5 }}>
            · max {formatTTL(maxTtl)}
          </span>
        )}
      </div>
      <div className="approval-form__row">
        <div className="field" style={{ maxWidth: 170 }}>
          <label className="field__label" htmlFor={`ttl-${lease.id}`}>
            TTL override
          </label>
          <input
            id={`ttl-${lease.id}`}
            className="input input--mono"
            value={ttlInput}
            onChange={(event) => setTtlInput(event.target.value)}
            placeholder={formatTTL(lease.effective_ttl_seconds)}
            autoComplete="off"
            spellCheck={false}
            aria-invalid={error && error.includes('TTL') ? 'true' : undefined}
          />
        </div>
        <div className="field" style={{ flex: 2 }}>
          <label className="field__label" htmlFor={`note-${lease.id}`}>
            Approval note <span className="muted">(optional, audited)</span>
          </label>
          <input
            id={`note-${lease.id}`}
            className="input"
            value={note}
            onChange={(event) => setNote(event.target.value)}
            placeholder="Why this access is approved"
            maxLength={280}
            autoComplete="off"
          />
        </div>
      </div>
      <div className="approval-form__row">
        <div className="row gap-6 wrap">
          {quickTtls.map((seconds) => (
            <button
              key={seconds}
              type="button"
              className={cx('segmented__item', ttlInput === formatTTL(seconds) && 'is-active')}
              style={{ border: '1px solid var(--line)', background: 'rgba(148,163,184,0.04)' }}
              onClick={() => setTtlInput(formatTTL(seconds))}
            >
              {formatTTL(seconds)}
            </button>
          ))}
        </div>
        <div className="approval-form__actions">
          <Button variant="ghost" size="sm" onClick={onCancel} disabled={mutation.busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            size="sm"
            icon={<IconCheck size={14} />}
            loading={mutation.busy}
            onClick={() => void submit()}
          >
            Approve &amp; issue
          </Button>
        </div>
      </div>
      {error && (
        <div className="banner banner--error" role="alert" style={{ padding: '8px 11px' }}>
          {error}
        </div>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Deny form                                                           */
/* ------------------------------------------------------------------ */

export function DenyLeaseForm({
  lease,
  onCancel,
  onUpdated,
}: BaseProps & { onCancel: () => void }) {
  const toast = useToast()
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string | null>(null)
  const mutation = useMutation(() => denyLease(lease.id, { reason: reason.trim() }))

  async function submit() {
    if (reason.trim() === '') {
      setError('A denial reason is required.')
      return
    }
    setError(null)
    try {
      const updated = await mutation.run()
      toast.success('Lease denied', `Recorded for ${lease.agent_name}.`)
      onUpdated(updated)
    } catch (cause) {
      setError(describeError(cause))
    }
  }

  return (
    <div className="approval-form approval-form--deny">
      <div className="approval-form__title">
        <IconX size={14} />
        Deny this lease
      </div>
      <div className="field">
        <label className="field__label" htmlFor={`deny-${lease.id}`}>
          Denial reason <span className="req">required · 1–500 chars</span>
        </label>
        <textarea
          id={`deny-${lease.id}`}
          className="textarea"
          style={{ minHeight: 68 }}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          placeholder="Explain why this request is refused — visible to the agent and audit log"
          maxLength={500}
          aria-invalid={error ? 'true' : undefined}
        />
        <div className="row-between">
          <span className="field__hint">The reason is returned to the requester and audited.</span>
          <span className="field__hint mono">{reason.length}/500</span>
        </div>
      </div>
      <div className="approval-form__actions">
        <Button variant="ghost" size="sm" onClick={onCancel} disabled={mutation.busy}>
          Cancel
        </Button>
        <Button
          variant="danger"
          size="sm"
          icon={<IconBan size={14} />}
          loading={mutation.busy}
          onClick={() => void submit()}
        >
          Deny request
        </Button>
      </div>
      {error && (
        <div className="banner banner--error" role="alert" style={{ padding: '8px 11px' }}>
          {error}
        </div>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Action bar                                                          */
/* ------------------------------------------------------------------ */

export function LeaseDecisionActions({
  lease,
  capabilities,
  policy,
  onUpdated,
  align = 'start',
}: BaseProps & { align?: 'start' | 'end' }) {
  const [mode, setMode] = useState<'approve' | 'deny' | 'revoke' | null>(null)
  const [revoking, setRevoking] = useState(false)
  const toast = useToast()

  function handleUpdated(updated: Lease) {
    setMode(null)
    onUpdated(updated)
  }

  if (lease.status === 'pending') {
    if (mode === 'approve') {
      return (
        <ApproveLeaseForm
          lease={lease}
          capabilities={capabilities}
          policy={policy}
          onCancel={() => setMode(null)}
          onUpdated={handleUpdated}
        />
      )
    }
    if (mode === 'deny') {
      return (
        <DenyLeaseForm
          lease={lease}
          onCancel={() => setMode(null)}
          onUpdated={handleUpdated}
        />
      )
    }
    return (
      <div
        className="approval-item__actions"
        style={{ justifyContent: align === 'end' ? 'flex-end' : 'flex-start' }}
      >
        <Button
          variant="primary"
          size="sm"
          icon={<IconCheck size={14} />}
          onClick={() => setMode('approve')}
        >
          Approve
        </Button>
        <Button
          variant="danger"
          size="sm"
          icon={<IconX size={14} />}
          onClick={() => setMode('deny')}
        >
          Deny
        </Button>
      </div>
    )
  }

  if (lease.status === 'active') {
    return (
      <>
        <div
          className="approval-item__actions"
          style={{ justifyContent: align === 'end' ? 'flex-end' : 'flex-start' }}
        >
          <Button
            variant="danger"
            size="sm"
            icon={<IconBan size={14} />}
            onClick={() => setRevoking(true)}
          >
            Revoke
          </Button>
        </div>
        <ConfirmDialog
          open={revoking}
          title="Revoke this active lease?"
          confirmLabel="Revoke lease"
          reasonLabel="Revocation reason"
          reasonRequired={false}
          reasonPlaceholder="Optional context for the audit trail"
          onCancel={() => setRevoking(false)}
          onConfirm={async (reason) => {
            const updated = await revokeLease(lease.id, {
              reason: reason || 'revoked by operator',
            })
            setRevoking(false)
            toast.success('Lease revoked', 'The credential is scrubbed and can no longer be fetched.')
            onUpdated(updated)
          }}
        >
          <div className="stack gap-8">
            <div>
              Active credentials for <strong>{lease.agent_name}</strong> stop working immediately.
              This is recorded in the tamper-evident audit log.
            </div>
            <div className="meta-list" style={{ gap: 10 }}>
              <div className="meta-item">
                <div className="meta-item__label">Lease</div>
                <div className="meta-item__value mono">{lease.id}</div>
              </div>
              <div className="meta-item">
                <div className="meta-item__label">Capability</div>
                <div className="meta-item__value mono">{lease.capability_id}</div>
              </div>
            </div>
          </div>
        </ConfirmDialog>
      </>
    )
  }

  return null
}
