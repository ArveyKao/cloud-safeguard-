/** Capability catalog: risk-grouped cards, policy viewer, enable toggle, custom create. */
import { useEffect, useMemo, useState } from 'react'
import { createCapability, listCapabilities, updateCapability } from '../api/client'
import { useResource } from '../api/hooks'
import type { Capability, CapabilityParam, CreateCapabilityInput, RiskTier } from '../api/types'
import { RISK_ORDER } from '../api/types'
import { cx, formatDateTime, formatTTL, parseDurationInput, tryParseJson } from '../lib/format'
import { Modal } from '../components/overlays'
import { ConfirmDialog } from '../components/ConfirmDialog'
import {
  AccessBadge,
  Button,
  EmptyState,
  ErrorBanner,
  Field,
  InlineNotice,
  PageHeader,
  RiskBadge,
  Skeleton,
  Switch,
} from '../components/primitives'
import { JsonView, RelativeTime } from '../components/display'
import { useToast, describeError } from '../components/Toasts'
import {
  IconCapabilities,
  IconChevronDown,
  IconChevronUp,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconShield,
} from '../components/icons'

interface CapabilitiesPageProps {
  refreshKey: number
}

interface PendingToggle {
  capability: Capability
  nextEnabled: boolean
}

const RISK_LABEL: Record<RiskTier, string> = {
  low: 'Low risk',
  medium: 'Medium risk',
  high: 'High risk',
  critical: 'Critical risk',
}

export function CapabilitiesPage({ refreshKey }: CapabilitiesPageProps) {
  const toast = useToast()
  const capabilities = useResource(listCapabilities, [refreshKey])
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState<RiskTier | ''>('')
  const [createOpen, setCreateOpen] = useState(false)
  const [expandedPolicy, setExpandedPolicy] = useState<Set<string>>(new Set())
  const [pendingToggle, setPendingToggle] = useState<PendingToggle | null>(null)
  const [toggling, setToggling] = useState(false)

  const items = useMemo(() => capabilities.data?.items ?? [], [capabilities.data])

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return items.filter((capability) => {
      if (riskFilter && capability.risk !== riskFilter) return false
      if (!query) return true
      return (
        capability.name.toLowerCase().includes(query) ||
        capability.id.toLowerCase().includes(query) ||
        capability.description.toLowerCase().includes(query)
      )
    })
  }, [items, riskFilter, search])

  const grouped = useMemo(() => {
    const providerTypes = Array.from(new Set(filtered.map((capability) => capability.provider_type)))
    return providerTypes.map((providerType) => ({
      providerType,
      risks: RISK_ORDER.map((risk) => ({
        risk,
        items: filtered.filter(
          (capability) => capability.provider_type === providerType && capability.risk === risk,
        ),
      })).filter((group) => group.items.length > 0),
    }))
  }, [filtered])

  function togglePolicy(id: string) {
    setExpandedPolicy((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function applyToggle(capability: Capability, enabled: boolean) {
    setToggling(true)
    try {
      const updated = await updateCapability(capability.id, { enabled })
      toast.success(
        enabled ? 'Capability enabled' : 'Capability disabled',
        enabled
          ? `${updated.name} can be requested again.`
          : `${updated.name} no longer accepts new lease requests.`,
      )
      await capabilities.refresh()
    } catch (cause) {
      toast.error('Could not update capability', describeError(cause))
    } finally {
      setToggling(false)
      setPendingToggle(null)
    }
  }

  const riskCounts = useMemo(() => {
    return {
      low: items.filter((capability) => capability.risk === 'low').length,
      medium: items.filter((capability) => capability.risk === 'medium').length,
      high: items.filter((capability) => capability.risk === 'high').length,
      critical: items.filter((capability) => capability.risk === 'critical').length,
    } as Record<RiskTier, number>
  }, [items])

  return (
    <div className="page">
      <PageHeader
        eyebrow="Permission bundles"
        title="Capabilities"
        subtitle="Named, least-privilege permission sets. Agents request a capability; the broker renders its parameterised IAM policy into a short-lived credential."
        metaLabel="Updated"
        metaValue={capabilities.lastUpdated ? formatDateTime(capabilities.lastUpdated.toISOString()) : '—'}
        actions={
          <>
            <Button
              variant="secondary"
              icon={<IconRefresh size={15} />}
              onClick={() => void capabilities.refresh()}
              disabled={capabilities.refreshing}
            >
              Refresh
            </Button>
            <Button variant="primary" icon={<IconPlus size={15} />} onClick={() => setCreateOpen(true)}>
              New capability
            </Button>
          </>
        }
      />

      {capabilities.error && (
        <div style={{ marginBottom: 16 }}>
          <ErrorBanner
            error={capabilities.error}
            onRetry={() => void capabilities.refresh()}
            title="Capability catalog could not load"
          />
        </div>
      )}

      <div className="filter-bar" style={{ marginBottom: 18 }}>
        <div className="input-group" style={{ flex: 1, minWidth: 220, maxWidth: 340 }}>
          <span className="input-group__icon">
            <IconSearch size={15} />
          </span>
          <input
            className="input"
            placeholder="Search capability name or id…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            aria-label="Search capabilities"
          />
        </div>
        <div className="segmented" role="group" aria-label="Filter by risk">
          <button
            type="button"
            className={cx('segmented__item', riskFilter === '' && 'is-active')}
            onClick={() => setRiskFilter('')}
          >
            All ({items.length})
          </button>
          {RISK_ORDER.map((risk) => (
            <button
              key={risk}
              type="button"
              className={cx('segmented__item', riskFilter === risk && 'is-active')}
              onClick={() => setRiskFilter(risk)}
            >
              {risk} ({riskCounts[risk]})
            </button>
          ))}
        </div>
        <span className="toolbar__spacer" />
        <span className="muted" style={{ fontSize: 12 }}>
          {filtered.filter((capability) => capability.enabled).length} enabled ·{' '}
          {filtered.filter((capability) => capability.builtin).length} built-in
        </span>
      </div>

      {capabilities.loading && items.length === 0 ? (
        <div className="cap-grid">
          {[0, 1, 2, 3].map((index) => (
            <div key={index} className="panel" style={{ padding: 18 }}>
              <Skeleton height={16} width="50%" />
              <Skeleton className="sk-line" width="38%" />
              <div style={{ height: 10 }} />
              <Skeleton height={12} />
              <Skeleton height={12} width="80%" />
              <div style={{ height: 14 }} />
              <Skeleton height={38} />
            </div>
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<IconCapabilities size={18} />}
          title={items.length === 0 ? 'Capability catalog is empty' : 'No capabilities match this filter'}
          hint={
            items.length === 0
              ? 'Run `csg init` to seed the five built-in capabilities, or create a custom capability.'
              : 'Adjust the search or risk filter.'
          }
          action={
            <Button variant="secondary" size="sm" icon={<IconPlus size={14} />} onClick={() => setCreateOpen(true)}>
              New capability
            </Button>
          }
        />
      ) : (
        <div className="stack" style={{ gap: 24 }}>
          {grouped.map((providerGroup) => (
            <div className="stack" style={{ gap: 16 }} key={providerGroup.providerType}>
              <div className="cap-group__header">
                <span className="cap-group__title">
                  <IconShield size={14} />
                  {providerGroup.providerType} · {providerGroup.risks.reduce((sum, risk) => sum + risk.items.length, 0)} capabilities
                </span>
                <span className="cap-group__line" />
              </div>
              {providerGroup.risks.map((riskGroup) => (
                <div className="cap-group" key={riskGroup.risk}>
                  <div className="row gap-8">
                    <RiskBadge risk={riskGroup.risk} />
                    <span className="muted" style={{ fontSize: 11.5 }}>
                      {RISK_LABEL[riskGroup.risk]} · {riskGroup.items.length}
                    </span>
                  </div>
                  <div className="cap-grid">
                    {riskGroup.items.map((capability) => {
                      const policy = tryParseJson(capability.policy_template)
                      const expanded = expandedPolicy.has(capability.id)
                      return (
                        <article
                          className={cx('cap-card', !capability.enabled && 'cap-card--disabled')}
                          key={capability.id}
                        >
                          <span
                            className={cx('cap-card__stripe', `cap-card__stripe--${capability.risk}`)}
                            aria-hidden="true"
                          />
                          <div className="cap-card__head">
                            <span className="cap-card__mark" aria-hidden="true">
                              <IconCapabilities size={18} />
                            </span>
                            <div className="cap-card__title-wrap">
                              <div className="cap-card__title">
                                {capability.name}
                                <RiskBadge risk={capability.risk} />
                                <AccessBadge access={capability.access} />
                                {capability.builtin && (
                                  <span className="badge badge--outline">built-in</span>
                                )}
                                {!capability.enabled && (
                                  <span className="badge badge--neutral">disabled</span>
                                )}
                              </div>
                              <div className="cap-card__id">{capability.id}</div>
                            </div>
                          </div>
                          <div className="cap-card__desc">{capability.description}</div>
                          <div className="cap-card__ttls">
                            <div className="cap-ttl">
                              <span className="cap-ttl__label">Access</span>
                              <span className="cap-ttl__value">
                                <AccessBadge access={capability.access} />
                              </span>
                            </div>
                            <div className="cap-ttl">
                              <span className="cap-ttl__label">Default TTL</span>
                              <span className="cap-ttl__value">
                                {formatTTL(capability.default_ttl_seconds)}
                              </span>
                            </div>
                            <div className="cap-ttl">
                              <span className="cap-ttl__label">Max TTL</span>
                              <span className="cap-ttl__value">{formatTTL(capability.max_ttl_seconds)}</span>
                            </div>
                            <div className="cap-ttl">
                              <span className="cap-ttl__label">Params</span>
                              <span className="cap-ttl__value">{capability.params?.length ?? 0}</span>
                            </div>
                          </div>
                          {capability.params && capability.params.length > 0 ? (
                            <div className="cap-params">
                              {capability.params.map((param) => (
                                <div className="cap-param" key={param.name}>
                                  <span className="cap-param__name">{param.name}</span>
                                  {param.required && <span className="cap-param__req">required</span>}
                                  <span className="cap-param__desc">{param.description || param.pattern}</span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="cap-params">
                              <div className="cap-param">
                                <span className="cap-param__desc">No parameters — fixed scope policy.</span>
                              </div>
                            </div>
                          )}
                          <div className="cap-card__policy">
                            <button
                              type="button"
                              className="cap-card__policy-toggle"
                              onClick={() => togglePolicy(capability.id)}
                              aria-expanded={expanded}
                            >
                              <span className="row gap-6">
                                {expanded ? <IconChevronUp size={13} /> : <IconChevronDown size={13} />}
                                {policy.ok ? 'IAM policy document' : 'Policy template (invalid JSON)'}
                              </span>
                              <span className="mono" style={{ fontSize: 10.5 }}>
                                {expanded ? 'hide' : 'view'}
                              </span>
                            </button>
                            {expanded && (
                              <div className="cap-card__policy-view">
                                {policy.ok ? (
                                  <JsonView value={policy.value} maxHeight={220} />
                                ) : (
                                  <JsonView raw={capability.policy_template} maxHeight={220} />
                                )}
                              </div>
                            )}
                          </div>
                          <div className="cap-card__foot">
                            <span className="cap-card__foot-meta">
                              updated <RelativeTime iso={capability.updated_at} />
                            </span>
                            <div className="cap-card__foot-actions">
                              <Switch
                                checked={capability.enabled}
                                disabled={toggling}
                                ariaLabel={`${capability.enabled ? 'Disable' : 'Enable'} ${capability.name}`}
                                onChange={(next) => {
                                  if (!next) setPendingToggle({ capability, nextEnabled: false })
                                  else void applyToggle(capability, true)
                                }}
                              />
                              <span className="switch__label" style={{ minWidth: 46 }}>
                                {capability.enabled ? 'Enabled' : 'Disabled'}
                              </span>
                            </div>
                          </div>
                        </article>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={Boolean(pendingToggle)}
        title="Disable this capability?"
        confirmLabel="Disable capability"
        onCancel={() => setPendingToggle(null)}
        onConfirm={async () => {
          if (pendingToggle) await applyToggle(pendingToggle.capability, false)
        }}
      >
        <div className="stack gap-8">
          <div>
            <strong>{pendingToggle?.capability.name}</strong> will immediately reject new lease
            requests from every agent. Active leases are not revoked.
          </div>
          <div>You can re-enable it at any time.</div>
        </div>
      </ConfirmDialog>

      <CreateCapabilityModal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={() => {
          setCreateOpen(false)
          void capabilities.refresh()
        }}
      />
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Custom capability creation                                          */
/* ------------------------------------------------------------------ */

interface ParamDraft {
  name: string
  description: string
  required: boolean
  pattern: string
}

const EMPTY_PARAM: ParamDraft = { name: '', description: '', required: false, pattern: '' }

interface CreateCapabilityModalProps {
  open: boolean
  onClose: () => void
  onCreated: (capability: Capability) => void
}

function CreateCapabilityModal({ open, onClose, onCreated }: CreateCapabilityModalProps) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [risk, setRisk] = useState<RiskTier>('low')
  const [defaultTtl, setDefaultTtl] = useState('10m')
  const [maxTtl, setMaxTtl] = useState('30m')
  const [policyTemplate, setPolicyTemplate] = useState(
    '{\n  "Version": "1",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": ["ecs:Describe*"],\n      "Resource": ["*"]\n    }\n  ]\n}',
  )
  const [params, setParams] = useState<ParamDraft[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setName('')
    setDescription('')
    setRisk('low')
    setDefaultTtl('10m')
    setMaxTtl('30m')
    setParams([])
    setError(null)
  }, [open])

  function updateParam(index: number, patch: Partial<ParamDraft>) {
    setParams((current) => current.map((param, i) => (i === index ? { ...param, ...patch } : param)))
  }

  async function submit() {
    if (name.trim() === '') {
      setError('Capability name is required.')
      return
    }
    const defaultSeconds = parseDurationInput(defaultTtl)
    const maxSeconds = parseDurationInput(maxTtl)
    if (defaultSeconds === null || defaultSeconds <= 0) {
      setError('Default TTL must be a duration such as 10m.')
      return
    }
    if (maxSeconds === null || maxSeconds <= 0) {
      setError('Max TTL must be a duration such as 30m.')
      return
    }
    if (defaultSeconds > maxSeconds) {
      setError('Default TTL cannot exceed max TTL.')
      return
    }
    if (!tryParseJson(policyTemplate).ok) {
      setError('Policy template must be valid JSON.')
      return
    }
    const trimmedParams = params.filter((param) => param.name.trim() !== '')
    if (trimmedParams.length !== params.length) {
      setError('Every parameter needs a name.')
      return
    }
    const payload: CreateCapabilityInput = {
      name: name.trim(),
      description: description.trim(),
      provider_type: 'aliyun',
      risk,
      policy_template: policyTemplate,
      params: trimmedParams.map<CapabilityParam>((param) => ({
        name: param.name.trim(),
        description: param.description.trim(),
        required: param.required,
        pattern: param.pattern.trim() || undefined,
      })),
      default_ttl_seconds: defaultSeconds,
      max_ttl_seconds: maxSeconds,
    }
    setBusy(true)
    setError(null)
    try {
      const created = await createCapability(payload)
      toast.success('Capability created', `${created.name} is available to granted agents.`)
      onCreated(created)
    } catch (cause) {
      setError(describeError(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="xl"
      title="New capability"
      subtitle="Define a least-privilege permission bundle with its own risk tier, TTL bounds and parameterised policy."
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" icon={<IconPlus size={15} />} loading={busy} onClick={() => void submit()}>
            Create capability
          </Button>
        </>
      }
    >
      <div className="stack" style={{ gap: 16 }}>
        <InlineNotice kind="info" title="Policy templates use {{param}} placeholders">
          The broker substitutes validated parameters into the rendered IAM policy — that is how a
          capability stays scoped to one domain or one instance.
        </InlineNotice>

        <div className="form-grid">
          <Field label="Name" htmlFor="cap-name" required>
            <input
              id="cap-name"
              className="input"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Manage DNS records for one domain"
            />
          </Field>
          <Field label="Risk tier" htmlFor="cap-risk" hint="Above the auto-approve threshold requires a human.">
            <select
              id="cap-risk"
              className="select"
              value={risk}
              onChange={(event) => setRisk(event.target.value as RiskTier)}
            >
              {RISK_ORDER.map((tier) => (
                <option key={tier} value={tier}>
                  {RISK_LABEL[tier]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Description" htmlFor="cap-description" className="form-span-2">
            <textarea
              id="cap-description"
              className="textarea"
              style={{ minHeight: 60 }}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="What does this allow, and when should it be used?"
            />
          </Field>
          <Field label="Default TTL" htmlFor="cap-default-ttl" hint="Used when a request omits ttl.">
            <input
              id="cap-default-ttl"
              className="input input--mono"
              value={defaultTtl}
              onChange={(event) => setDefaultTtl(event.target.value)}
            />
          </Field>
          <Field label="Max TTL" htmlFor="cap-max-ttl" hint="Hard ceiling for any lease.">
            <input
              id="cap-max-ttl"
              className="input input--mono"
              value={maxTtl}
              onChange={(event) => setMaxTtl(event.target.value)}
            />
          </Field>
          <Field
            label="Provider type"
            htmlFor="cap-provider"
            hint="v0.1 supports Alibaba Cloud only."
          >
            <select id="cap-provider" className="select" value="aliyun" disabled>
              <option value="aliyun">aliyun</option>
            </select>
          </Field>
          <Field label="Capability ID" htmlFor="cap-id" hint="Generated on the server with a cap_ prefix.">
            <input id="cap-id" className="input input--mono" value="cap_…" disabled readOnly />
          </Field>
        </div>

        <div className="field">
          <div className="row-between">
            <span className="field__label">Parameters</span>
            <Button
              size="sm"
              variant="secondary"
              icon={<IconPlus size={13} />}
              onClick={() => setParams((current) => [...current, { ...EMPTY_PARAM }])}
            >
              Add parameter
            </Button>
          </div>
          <div className="field__hint">
            Declared parameters are validated (required, RE2 pattern) before a lease is created and
            substituted into <span className="mono">{'{{placeholders}}'}</span>.
          </div>
          {params.length === 0 ? (
            <div className="empty" style={{ padding: '18px 16px', marginTop: 6 }}>
              <div className="empty__hint">No parameters — this capability has a fixed scope.</div>
            </div>
          ) : (
            <div className="stack" style={{ gap: 10, marginTop: 6 }}>
              {params.map((param, index) => (
                <div
                  key={index}
                  className="panel"
                  style={{ padding: 12, boxShadow: 'none', background: 'rgba(148,163,184,0.025)' }}
                >
                  <div className="form-grid" style={{ gap: 10 }}>
                    <Field label="Name" htmlFor={`param-name-${index}`}>
                      <input
                        id={`param-name-${index}`}
                        className="input input--mono"
                        value={param.name}
                        onChange={(event) => updateParam(index, { name: event.target.value })}
                        placeholder="domain"
                      />
                    </Field>
                    <Field label="Pattern (RE2, optional)" htmlFor={`param-pattern-${index}`}>
                      <input
                        id={`param-pattern-${index}`}
                        className="input input--mono"
                        value={param.pattern}
                        onChange={(event) => updateParam(index, { pattern: event.target.value })}
                        placeholder="^[a-z0-9.-]+$"
                      />
                    </Field>
                    <Field label="Description" htmlFor={`param-desc-${index}`}>
                      <input
                        id={`param-desc-${index}`}
                        className="input"
                        value={param.description}
                        onChange={(event) => updateParam(index, { description: event.target.value })}
                        placeholder="Domain the policy is scoped to"
                      />
                    </Field>
                    <div className="row-between">
                      <label className="checkbox" style={{ padding: '6px 2px' }}>
                        <input
                          type="checkbox"
                          checked={param.required}
                          onChange={(event) => updateParam(index, { required: event.target.checked })}
                        />
                        <span className="checkbox__text">Required</span>
                      </label>
                      <Button
                        size="sm"
                        variant="danger"
                        onClick={() => setParams((current) => current.filter((_, i) => i !== index))}
                      >
                        Remove
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <Field
          label="Policy template (JSON)"
          htmlFor="cap-policy"
          hint="Rendered with parameters, then validated as JSON by the server."
        >
          <textarea
            id="cap-policy"
            className="textarea textarea--mono"
            style={{ minHeight: 180 }}
            value={policyTemplate}
            onChange={(event) => setPolicyTemplate(event.target.value)}
            spellCheck={false}
          />
        </Field>

        {!tryParseJson(policyTemplate).ok && (
          <div className="banner banner--warning" role="alert">
            Policy template is not valid JSON yet.
          </div>
        )}
        {error && (
          <div className="banner banner--error" role="alert">
            {error}
          </div>
        )}
        <InlineNotice kind="info" title="Audit notice">
          Creating a capability writes a <span className="mono">capability.created</span> event to
          the tamper-evident audit log.
        </InlineNotice>
      </div>
    </Modal>
  )
}
