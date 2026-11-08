/** Settings: guardrail policy editor with server validation + rotation guidance. */
import { useEffect, useMemo, useState } from 'react'
import { fetchOverview, fetchPolicy, updatePolicy } from '../api/client'
import { ApiError } from '../api/client'
import { useResource } from '../api/hooks'
import type { PolicySettings, RiskTier } from '../api/types'
import { RISK_ORDER } from '../api/types'
import { formatDuration, formatTTL, parseDurationInput } from '../lib/format'
import {
  Button,
  ErrorBanner,
  InlineNotice,
  PageHeader,
  Panel,
  Skeleton,
} from '../components/primitives'
import { useToast, describeError } from '../components/Toasts'
import {
  IconAudit,
  IconCheck,
  IconInfo,
  IconLock,
  IconRefresh,
  IconRotate,
  IconShield,
} from '../components/icons'

interface SettingsPageProps {
  refreshKey: number
}

interface FormState {
  autoApproveMaxRisk: RiskTier
  autoApproveMaxTtl: string
  maxLeaseTtl: string
  pendingTimeout: string
  maxConcurrent: string
  leasesPerMinute: string
  requireReasonForRisk: RiskTier
}

function toForm(policy: PolicySettings): FormState {
  return {
    autoApproveMaxRisk: policy.auto_approve_max_risk,
    autoApproveMaxTtl: formatTTL(policy.auto_approve_max_ttl_seconds).replace(' ', ''),
    maxLeaseTtl: formatTTL(policy.max_lease_ttl_seconds).replace(' ', ''),
    pendingTimeout: formatTTL(policy.pending_timeout_seconds).replace(' ', ''),
    maxConcurrent: String(policy.max_concurrent_leases_per_agent),
    leasesPerMinute: String(policy.leases_per_minute_per_agent),
    requireReasonForRisk: policy.require_reason_for_risk,
  }
}

type FieldKey =
  | 'autoApproveMaxTtl'
  | 'maxLeaseTtl'
  | 'pendingTimeout'
  | 'maxConcurrent'
  | 'leasesPerMinute'
  | 'autoApproveMaxRisk'
  | 'requireReasonForRisk'

const FIELD_ALIASES: Record<string, FieldKey> = {
  auto_approve_max_risk: 'autoApproveMaxRisk',
  auto_approve_max_ttl_seconds: 'autoApproveMaxTtl',
  max_lease_ttl_seconds: 'maxLeaseTtl',
  pending_timeout_seconds: 'pendingTimeout',
  max_concurrent_leases_per_agent: 'maxConcurrent',
  leases_per_minute_per_agent: 'leasesPerMinute',
  require_reason_for_risk: 'requireReasonForRisk',
}

export function SettingsPage({ refreshKey }: SettingsPageProps) {
  const toast = useToast()
  const policy = useResource(fetchPolicy, [refreshKey])
  const overview = useResource(fetchOverview, [refreshKey])

  const [form, setForm] = useState<FormState | null>(null)
  const [baseline, setBaseline] = useState<FormState | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Partial<Record<FieldKey, string>>>({})
  const [saveError, setSaveError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (policy.data) {
      const next = toForm(policy.data)
      setForm(next)
      setBaseline(next)
      setFieldErrors({})
    }
  }, [policy.data])

  const dirty = useMemo(() => {
    if (!form || !baseline) return false
    return (Object.keys(form) as Array<keyof FormState>).some((key) => form[key] !== baseline[key])
  }, [form, baseline])

  function set<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => (current ? { ...current, [key]: value } : current))
    setFieldErrors((current) => ({ ...current, [key]: undefined }))
  }

  function reset() {
    if (baseline) setForm(baseline)
    setFieldErrors({})
    setSaveError(null)
  }

  function parseFieldError(cause: unknown): Partial<Record<FieldKey, string>> {
    const errors: Partial<Record<FieldKey, string>> = {}
    if (cause instanceof ApiError) {
      const message = cause.message
      // Server messages look like "max_lease_ttl_seconds must be >= ...".
      for (const [wire, key] of Object.entries(FIELD_ALIASES)) {
        if (message.includes(wire)) errors[key] = message
      }
      if (cause.details) {
        for (const [key, value] of Object.entries(cause.details)) {
          const mapped = FIELD_ALIASES[key]
          if (mapped && typeof value === 'string') errors[mapped] = value
        }
      }
      if (Object.keys(errors).length === 0) {
        for (const key of Object.keys(FIELD_ALIASES)) {
          if (message.toLowerCase().includes(key.split('_')[0])) {
            errors[FIELD_ALIASES[key]] = message
            break
          }
        }
      }
    }
    return errors
  }

  async function save() {
    if (!form) return
    const localErrors: Partial<Record<FieldKey, string>> = {}
    const autoTtl = parseDurationInput(form.autoApproveMaxTtl)
    const maxTtl = parseDurationInput(form.maxLeaseTtl)
    const pending = parseDurationInput(form.pendingTimeout)
    const concurrent = Number(form.maxConcurrent)
    const rate = Number(form.leasesPerMinute)

    if (autoTtl === null || autoTtl <= 0) localErrors.autoApproveMaxTtl = 'Enter a positive duration such as 15m.'
    if (maxTtl === null || maxTtl <= 0) localErrors.maxLeaseTtl = 'Enter a positive duration such as 1h.'
    else if (autoTtl !== null && maxTtl < autoTtl)
      localErrors.maxLeaseTtl = 'Max lease TTL must be >= auto-approve TTL.'
    if (pending === null || pending <= 0) localErrors.pendingTimeout = 'Enter a positive duration.'
    if (!Number.isInteger(concurrent) || concurrent <= 0) localErrors.maxConcurrent = 'Must be a positive whole number.'
    if (!Number.isInteger(rate) || rate <= 0) localErrors.leasesPerMinute = 'Must be a positive whole number.'

    if (Object.keys(localErrors).length > 0 || autoTtl === null || maxTtl === null || pending === null) {
      setFieldErrors(localErrors)
      setSaveError('Fix the highlighted guardrails before saving.')
      return
    }

    const payload: PolicySettings = {
      auto_approve_max_risk: form.autoApproveMaxRisk,
      auto_approve_max_ttl_seconds: autoTtl,
      max_lease_ttl_seconds: maxTtl,
      pending_timeout_seconds: pending,
      max_concurrent_leases_per_agent: concurrent,
      leases_per_minute_per_agent: rate,
      require_reason_for_risk: form.requireReasonForRisk,
    }

    setSaving(true)
    setFieldErrors({})
    setSaveError(null)
    try {
      const updated = await updatePolicy(payload)
      const next = toForm(updated)
      setForm(next)
      setBaseline(next)
      toast.success('Guardrails saved', 'The new policy is enforced immediately and recorded in the audit log.')
      await overview.refresh()
    } catch (cause) {
      setFieldErrors(parseFieldError(cause))
      setSaveError(describeError(cause))
    } finally {
      setSaving(false)
    }
  }

  const loading = policy.loading && !form

  return (
    <div className="page">
      <PageHeader
        eyebrow="Guardrails"
        title="Settings"
        subtitle="Risk thresholds, TTL ceilings and rate limits that drive auto-approval. Changes are validated server-side and audited as warning events."
        metaLabel="Policy loaded"
        metaValue={policy.lastUpdated ? policy.lastUpdated.toLocaleTimeString() : '—'}
        actions={
          <Button
            variant="secondary"
            icon={<IconRefresh size={15} />}
            onClick={() => {
              void policy.refresh()
              void overview.refresh()
            }}
            disabled={policy.refreshing}
          >
            Reload policy
          </Button>
        }
      />

      {policy.error && (
        <div style={{ marginBottom: 16 }}>
          <ErrorBanner
            error={policy.error}
            onRetry={() => void policy.refresh()}
            title="Guardrail policy could not load"
          />
        </div>
      )}

      <div className="settings-grid">
        <div className="stack">
          <section className="panel settings-form">
            <header className="panel__header">
              <div>
                <div className="panel__title">
                  <IconShield size={16} />
                  Guardrail policy
                </div>
                <div className="panel__subtitle">
                  These settings are global. Per-agent limits can never exceed them.
                </div>
              </div>
              {dirty && (
                <span className="badge badge--pending badge--dot">unsaved changes</span>
              )}
            </header>

            {loading || !form ? (
              <div className="settings-form__body">
                {Array.from({ length: 6 }).map((_, index) => (
                  <div key={index} className="settings-field-row">
                    <div>
                      <Skeleton width={180} height={13} />
                      <Skeleton className="sk-line" width="70%" />
                    </div>
                    <Skeleton width={120} height={34} />
                  </div>
                ))}
              </div>
            ) : (
              <>
                <div className="settings-form__body">
                  <div className="settings-field-row">
                    <div className="settings-field-row__text">
                      <div className="settings-field-row__title">Auto-approve maximum risk</div>
                      <div className="settings-field-row__desc">
                        Requests at or below this risk tier, within the TTL below, are granted
                        without a human. Anything higher joins the approval queue.
                      </div>
                    </div>
                    <div className="settings-field-row__control">
                      <select
                        className="select"
                        value={form.autoApproveMaxRisk}
                        onChange={(event) => set('autoApproveMaxRisk', event.target.value as RiskTier)}
                        aria-label="Auto-approve maximum risk"
                      >
                        {RISK_ORDER.map((tier) => (
                          <option key={tier} value={tier}>
                            {tier}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <div className="settings-field-row">
                    <div className="settings-field-row__text">
                      <div className="settings-field-row__title">Auto-approve maximum TTL</div>
                      <div className="settings-field-row__desc">
                        Leases longer than this always require explicit approval, even for low-risk
                        capabilities.
                      </div>
                    </div>
                    <div className="settings-field-row__control">
                      <input
                        className="input input--mono"
                        value={form.autoApproveMaxTtl}
                        onChange={(event) => set('autoApproveMaxTtl', event.target.value)}
                        aria-label="Auto-approve maximum TTL"
                        aria-invalid={fieldErrors.autoApproveMaxTtl ? 'true' : undefined}
                      />
                      <span className="settings-hint">
                        {parseDurationInput(form.autoApproveMaxTtl) ?? '?'} seconds
                      </span>
                      {fieldErrors.autoApproveMaxTtl && (
                        <span className="field__error">{fieldErrors.autoApproveMaxTtl}</span>
                      )}
                    </div>
                  </div>

                  <div className="settings-field-row">
                    <div className="settings-field-row__text">
                      <div className="settings-field-row__title">Maximum lease TTL</div>
                      <div className="settings-field-row__desc">
                        Absolute ceiling for any lease. Capability and agent limits are capped by
                        this value.
                      </div>
                    </div>
                    <div className="settings-field-row__control">
                      <input
                        className="input input--mono"
                        value={form.maxLeaseTtl}
                        onChange={(event) => set('maxLeaseTtl', event.target.value)}
                        aria-label="Maximum lease TTL"
                        aria-invalid={fieldErrors.maxLeaseTtl ? 'true' : undefined}
                      />
                      <span className="settings-hint">
                        {parseDurationInput(form.maxLeaseTtl) ?? '?'} seconds
                      </span>
                      {fieldErrors.maxLeaseTtl && (
                        <span className="field__error">{fieldErrors.maxLeaseTtl}</span>
                      )}
                    </div>
                  </div>

                  <div className="settings-field-row">
                    <div className="settings-field-row__text">
                      <div className="settings-field-row__title">Pending approval timeout</div>
                      <div className="settings-field-row__desc">
                        How long a request survives in the queue before it expires without a
                        decision. The sweeper runs every 10 seconds.
                      </div>
                    </div>
                    <div className="settings-field-row__control">
                      <input
                        className="input input--mono"
                        value={form.pendingTimeout}
                        onChange={(event) => set('pendingTimeout', event.target.value)}
                        aria-label="Pending approval timeout"
                        aria-invalid={fieldErrors.pendingTimeout ? 'true' : undefined}
                      />
                      <span className="settings-hint">
                        {parseDurationInput(form.pendingTimeout) ?? '?'} seconds
                      </span>
                      {fieldErrors.pendingTimeout && (
                        <span className="field__error">{fieldErrors.pendingTimeout}</span>
                      )}
                    </div>
                  </div>

                  <div className="settings-field-row">
                    <div className="settings-field-row__text">
                      <div className="settings-field-row__title">Concurrent leases per agent</div>
                      <div className="settings-field-row__desc">
                        Global cap on simultaneously active leases for one agent. Denials are
                        explainable in the lease decision trail.
                      </div>
                    </div>
                    <div className="settings-field-row__control">
                      <input
                        className="input input--mono"
                        type="number"
                        min={1}
                        value={form.maxConcurrent}
                        onChange={(event) => set('maxConcurrent', event.target.value)}
                        aria-label="Maximum concurrent leases per agent"
                        aria-invalid={fieldErrors.maxConcurrent ? 'true' : undefined}
                      />
                      {fieldErrors.maxConcurrent && (
                        <span className="field__error">{fieldErrors.maxConcurrent}</span>
                      )}
                    </div>
                  </div>

                  <div className="settings-field-row">
                    <div className="settings-field-row__text">
                      <div className="settings-field-row__title">Lease requests per minute</div>
                      <div className="settings-field-row__desc">
                        Rate limit per agent over a rolling 60-second window. Protects against a
                        runaway agent loop.
                      </div>
                    </div>
                    <div className="settings-field-row__control">
                      <input
                        className="input input--mono"
                        type="number"
                        min={1}
                        value={form.leasesPerMinute}
                        onChange={(event) => set('leasesPerMinute', event.target.value)}
                        aria-label="Lease requests per minute per agent"
                        aria-invalid={fieldErrors.leasesPerMinute ? 'true' : undefined}
                      />
                      {fieldErrors.leasesPerMinute && (
                        <span className="field__error">{fieldErrors.leasesPerMinute}</span>
                      )}
                    </div>
                  </div>

                  <div className="settings-field-row">
                    <div className="settings-field-row__text">
                      <div className="settings-field-row__title">Require a reason from risk tier</div>
                      <div className="settings-field-row__desc">
                        Requests at or above this tier must include a stated reason, which is shown
                        to the approver and written to the audit log.
                      </div>
                    </div>
                    <div className="settings-field-row__control">
                      <select
                        className="select"
                        value={form.requireReasonForRisk}
                        onChange={(event) =>
                          set('requireReasonForRisk', event.target.value as RiskTier)
                        }
                        aria-label="Require reason from risk tier"
                      >
                        {RISK_ORDER.map((tier) => (
                          <option key={tier} value={tier}>
                            {tier}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                </div>

                {saveError && (
                  <div style={{ padding: '0 20px 16px' }}>
                    <div className="banner banner--error" role="alert">
                      {saveError}
                    </div>
                  </div>
                )}

                <div className="settings-form__foot">
                  <div className="row gap-8">
                    {dirty ? (
                      <span className="settings-form__dirty">
                        <span className="status-dot status-dot--amber" aria-hidden="true" />
                        Unsaved changes
                      </span>
                    ) : (
                      <span className="row gap-6 muted" style={{ fontSize: 12 }}>
                        <IconCheck size={13} /> Policy matches the control plane
                      </span>
                    )}
                  </div>
                  <div className="row gap-8">
                    <Button variant="ghost" onClick={reset} disabled={!dirty || saving}>
                      Discard
                    </Button>
                    <Button
                      variant="primary"
                      icon={<IconShield size={15} />}
                      loading={saving}
                      disabled={!dirty}
                      onClick={() => void save()}
                    >
                      Save guardrails
                    </Button>
                  </div>
                </div>
              </>
            )}
          </section>

          <InlineNotice kind="info" title="Audit notice">
            Saving writes a <span className="mono">policy.updated</span> warning event with the
            before/after values in metadata. Policy changes take effect on the next lease request.
          </InlineNotice>
        </div>

        <div className="stack">
          <Panel
            title="How the engine decides"
            subtitle="Deny beats require-approval beats allow"
            icon={<IconShield size={16} />}
          >
            {form ? (
              <div className="policy-explain">
                <div className="policy-explain__row">
                  <IconCheck size={14} />
                  <div>
                    <span className="mono">{form.autoApproveMaxRisk}</span> risk and ≤{' '}
                    <span className="mono">{formatTTL(parseDurationInput(form.autoApproveMaxTtl) ?? 0)}</span>{' '}
                    → auto-approved
                  </div>
                </div>
                <div className="policy-explain__row">
                  <IconInfo size={14} style={{ color: 'var(--amber)' }} />
                  <div>
                    Higher risk or longer TTL, or break-glass → human approval
                  </div>
                </div>
                <div className="policy-explain__row">
                  <IconLock size={14} style={{ color: 'var(--rose)' }} />
                  <div>
                    Missing grant, disabled capability, TTL above a limit, rate/concurrency cap, or
                    critical risk without break-glass → denied
                  </div>
                </div>
                <hr className="divider" style={{ margin: '4px 0' }} />
                <div className="muted" style={{ fontSize: 11.5 }}>
                  Every rule evaluation (allow / require / deny) is stored on the lease and shown in
                  the lease detail trail.
                </div>
              </div>
            ) : (
              <Skeleton height={90} />
            )}
          </Panel>

          <Panel
            title="Instance"
            subtitle="Read-only runtime facts"
            icon={<IconInfo size={16} />}
          >
            {overview.data ? (
              <div className="stack gap-8">
                <div className="row-between">
                  <span className="muted" style={{ fontSize: 12 }}>
                    Version
                  </span>
                  <span className="mono" style={{ fontSize: 12 }}>
                    {overview.data.version}
                  </span>
                </div>
                <div className="row-between">
                  <span className="muted" style={{ fontSize: 12 }}>
                    Uptime
                  </span>
                  <span className="mono" style={{ fontSize: 12 }}>
                    {formatDuration(overview.data.uptime_seconds)}
                  </span>
                </div>
                <div className="row-between">
                  <span className="muted" style={{ fontSize: 12 }}>
                    Vault key fingerprint
                  </span>
                  <span className="mono" style={{ fontSize: 11 }}>
                    {overview.data.vault.key_fingerprint?.slice(0, 18) ?? '—'}…
                  </span>
                </div>
                <div className="row-between">
                  <span className="muted" style={{ fontSize: 12 }}>
                    Providers
                  </span>
                  <span className="mono" style={{ fontSize: 12 }}>
                    {overview.data.counts.providers}
                  </span>
                </div>
              </div>
            ) : (
              <Skeleton height={80} />
            )}
          </Panel>

          <section className="panel danger-card">
            <header className="panel__header">
              <div>
                <div className="panel__title">
                  <IconRotate size={16} />
                  Rotation guidance
                </div>
                <div className="panel__subtitle">
                  Credentials this control plane holds
                </div>
              </div>
            </header>
            <div className="panel__body">
              <div className="rotation-steps">
                <div className="rotation-step">
                  <div>
                    <strong>Broker AccessKey</strong> — rotate on the Providers page. Existing
                    leases keep working; new leases use the new key; the change is audited with
                    masked IDs.
                  </div>
                </div>
                <div className="rotation-step">
                  <div>
                    <strong>Agent tokens</strong> — rotate per agent in its detail panel. The old
                    token stops working immediately.
                  </div>
                </div>
                <div className="rotation-step">
                  <div>
                    <strong>Admin token</strong> — re-run{' '}
                    <span className="mono">csg init --force</span> against the data directory to
                    rotate it, then sign in again with the printed token.
                  </div>
                </div>
                <div className="rotation-step">
                  <div>
                    <strong>Master key</strong> — not rotatable from the console in v0.1; back it up
                    separately from the database (it lives at{' '}
                    <span className="mono">&lt;data-dir&gt;/master.key</span>).
                  </div>
                </div>
              </div>
              <div className="banner banner--warning" style={{ marginTop: 14 }}>
                <IconAudit size={15} />
                <div>
                  Losing the master key makes vaulted credentials unrecoverable. Never commit it,
                  and never copy it next to the database.
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}
