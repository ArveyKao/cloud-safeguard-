/** Agent identities: table, create flow, one-time token, detail drawer. */
import { useEffect, useMemo, useState } from 'react'
import {
  activateAgent,
  createAgent,
  fetchPolicy,
  listAgents,
  listCapabilities,
  listLeases,
  rotateAgentToken,
  suspendAgent,
  updateAgent,
} from '../api/client'
import { ApiError } from '../api/client'
import { useResource } from '../api/hooks'
import type { Agent, AgentWithToken, Capability, ListResponse, Lease, PolicySettings } from '../api/types'
import { RISK_ORDER } from '../api/types'
import { formatDateTime, formatTTL, parseDurationInput } from '../lib/format'
import { navigate } from '../router'
import { Drawer } from '../components/overlays'
import { ConfirmDialog } from '../components/ConfirmDialog'
import { TokenRevealModal } from '../components/TokenReveal'
import {
  Button,
  CopyButton,
  EmptyState,
  ErrorBanner,
  Field,
  InlineNotice,
  LeaseStatusBadge,
  PageHeader,
  RiskBadge,
  Skeleton,
  StatusBadge,
} from '../components/primitives'
import { RelativeTime } from '../components/display'
import { useToast, describeError } from '../components/Toasts'
import {
  IconAgents,
  IconBan,
  IconCheck,
  IconEdit,
  IconPlus,
  IconRefresh,
  IconRotate,
  IconSearch,
} from '../components/icons'

interface AgentsPageProps {
  refreshKey: number
}

interface TokenRevealState {
  agent: Agent
  token: string
  title: string
  subtitle: string
}

export function AgentsPage({ refreshKey }: AgentsPageProps) {
  const toast = useToast()
  const agents = useResource(listAgents, [refreshKey])
  const capabilities = useResource(listCapabilities, [refreshKey])
  const policy = useResource(fetchPolicy, [refreshKey])

  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [selected, setSelected] = useState<Agent | null>(null)
  const [tokenReveal, setTokenReveal] = useState<TokenRevealState | null>(null)
  const [confirmAction, setConfirmAction] = useState<{ kind: 'suspend' | 'rotate'; agent: Agent } | null>(
    null,
  )

  const items = useMemo(() => agents.data?.items ?? [], [agents.data])
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return items.filter((agent) => {
      if (statusFilter && agent.status !== statusFilter) return false
      if (!query) return true
      return (
        agent.name.toLowerCase().includes(query) ||
        agent.id.toLowerCase().includes(query) ||
        agent.description.toLowerCase().includes(query) ||
        agent.grants.some((grant) => grant.toLowerCase().includes(query))
      )
    })
  }, [items, search, statusFilter])

  function refreshAll() {
    void agents.refresh()
    void capabilities.refresh()
    void policy.refresh()
  }

  function handleAgentUpdated(agent: Agent) {
    setSelected((current) => (current && current.id === agent.id ? agent : current))
    void agents.refresh()
  }

  async function performConfirmAction() {
    if (!confirmAction) return
    const { kind, agent } = confirmAction
    if (kind === 'suspend') {
      const updated = await suspendAgent(agent.id)
      toast.success('Agent suspended', `${updated.name} can no longer request leases.`)
      setSelected((current) => (current && current.id === updated.id ? updated : current))
      void agents.refresh()
    } else {
      const result = await rotateAgentToken(agent.id)
      setSelected(null)
      setTokenReveal({
        agent: result.agent,
        token: result.token,
        title: 'Agent token rotated',
        subtitle: 'The previous token stopped working immediately. Store this one now.',
      })
      void agents.refresh()
    }
    setConfirmAction(null)
  }

  return (
    <div className="page">
      <PageHeader
        eyebrow="Identities"
        title="Agents"
        subtitle="Non-human identities authenticate with their own scoped token, then request capability leases. No agent ever holds a long-lived cloud key."
        metaLabel="Updated"
        metaValue={agents.lastUpdated ? formatDateTime(agents.lastUpdated.toISOString()) : '—'}
        actions={
          <>
            <Button
              variant="secondary"
              icon={<IconRefresh size={15} />}
              onClick={refreshAll}
              disabled={agents.refreshing}
            >
              Refresh
            </Button>
            <Button variant="primary" icon={<IconPlus size={15} />} onClick={() => setCreateOpen(true)}>
              Create agent
            </Button>
          </>
        }
      />

      {agents.error && (
        <div style={{ marginBottom: 16 }}>
          <ErrorBanner
            error={agents.error}
            onRetry={() => void agents.refresh()}
            title="Agents could not load"
          />
        </div>
      )}

      <div className="filter-bar" style={{ marginBottom: 16 }}>
        <div className="input-group" style={{ flex: 1, minWidth: 220, maxWidth: 360 }}>
          <span className="input-group__icon">
            <IconSearch size={15} />
          </span>
          <input
            className="input"
            placeholder="Search name, id, description or grant…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            aria-label="Search agents"
          />
        </div>
        <select
          className="select input--inline"
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value)}
          aria-label="Filter by status"
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
          <option value="revoked">Revoked</option>
        </select>
        <span className="toolbar__spacer" />
        <span className="muted" style={{ fontSize: 12 }}>
          {filtered.length} of {items.length} agents
        </span>
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Agent</th>
              <th scope="col">Status</th>
              <th scope="col">Grants</th>
              <th scope="col">Last seen</th>
              <th scope="col">Limits</th>
              <th scope="col" className="cell-actions">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {agents.loading && items.length === 0 ? (
              Array.from({ length: 3 }).map((_, index) => (
                <tr key={`skeleton-${index}`}>
                  {Array.from({ length: 6 }).map((__, cell) => (
                    <td key={cell}>
                      <Skeleton width={cell === 0 ? 160 : 90} />
                    </td>
                  ))}
                </tr>
              ))
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: 0, border: 'none' }}>
                  <div style={{ padding: 20 }}>
                    <EmptyState
                      icon={<IconAgents size={18} />}
                      title={items.length === 0 ? 'No agents yet' : 'No agents match this filter'}
                      hint={
                        items.length === 0
                          ? 'Create the first agent identity, grant it least-privilege capabilities, and hand it the token once.'
                          : 'Try a different search term or status.'
                      }
                      action={
                        items.length === 0 ? (
                          <Button
                            variant="primary"
                            size="sm"
                            icon={<IconPlus size={14} />}
                            onClick={() => setCreateOpen(true)}
                          >
                            Create agent
                          </Button>
                        ) : undefined
                      }
                    />
                  </div>
                </td>
              </tr>
            ) : (
              filtered.map((agent) => (
                <tr key={agent.id}>
                  <td>
                    <div className="agent-name-cell">
                      <span className="agent-avatar" aria-hidden="true">
                        <IconAgents />
                      </span>
                      <div className="agent-name-cell__main">
                        <div className="agent-name-cell__name">{agent.name}</div>
                        <div className="agent-name-cell__id">{agent.id}</div>
                      </div>
                    </div>
                  </td>
                  <td>
                    <StatusBadge status={agent.status} />
                  </td>
                  <td>
                    {agent.grants.length === 0 ? (
                      <span className="muted" style={{ fontSize: 12 }}>
                        no grants
                      </span>
                    ) : (
                      <div className="grant-chips">
                        {agent.grants.slice(0, 2).map((grant) => (
                          <span className="chip" key={grant} title={grant}>
                            {grant}
                          </span>
                        ))}
                        {agent.grants.length > 2 && (
                          <span className="chip chip--strong">+{agent.grants.length - 2}</span>
                        )}
                      </div>
                    )}
                  </td>
                  <td>
                    <RelativeTime iso={agent.last_seen_at} />
                    <div style={{ fontSize: 10.5 }}>
                      {agent.last_seen_at ? '' : 'never authenticated'}
                    </div>
                  </td>
                  <td>
                    <div className="ttl-cell">
                      <span className="ttl-cell__main">
                        {formatTTL(agent.max_ttl_seconds)} · {agent.max_concurrent_leases} concurrent
                      </span>
                      <span className="ttl-cell__sub">
                        created {formatDateTime(agent.created_at)}
                      </span>
                    </div>
                  </td>
                  <td className="cell-actions">
                    <Button
                      variant="secondary"
                      size="sm"
                      icon={<IconEdit size={13} />}
                      onClick={() => setSelected(agent)}
                    >
                      Manage
                    </Button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div
        className="muted"
        style={{ fontSize: 11.5, marginTop: 12, display: 'flex', gap: 14, flexWrap: 'wrap' }}
      >
        <span>
          Last-seen timestamps refresh at most once per minute by design. Times are shown in this
          browser&apos;s timezone.
        </span>
        <button type="button" className="panel__link" onClick={() => navigate('/capabilities')}>
          Review capability grants →
        </button>
      </div>

      <CreateAgentModal
        open={createOpen}
        capabilities={capabilities.data?.items ?? []}
        capabilitiesLoading={capabilities.loading}
        capabilitiesError={capabilities.error}
        policy={policy.data}
        onClose={() => setCreateOpen(false)}
        onCreated={(created) => {
          setCreateOpen(false)
          setTokenReveal({
            agent: created.agent,
            token: created.token,
            title: 'Agent created',
            subtitle: 'Hand this bearer token to the agent now. It is shown exactly once.',
          })
          void agents.refresh()
        }}
      />

      <AgentDetailDrawer
        agent={selected}
        capabilities={capabilities.data?.items ?? []}
        policy={policy.data}
        refreshKey={refreshKey}
        onClose={() => setSelected(null)}
        onUpdated={handleAgentUpdated}
        onRequestSuspend={(agent) => setConfirmAction({ kind: 'suspend', agent })}
        onRequestRotate={(agent) => setConfirmAction({ kind: 'rotate', agent })}
      />

      <TokenRevealModal
        open={Boolean(tokenReveal)}
        title={tokenReveal?.title ?? 'Agent token'}
        subtitle={tokenReveal?.subtitle ?? ''}
        agentName={tokenReveal?.agent.name ?? ''}
        agentId={tokenReveal?.agent.id ?? ''}
        token={tokenReveal?.token ?? ''}
        onDone={() => setTokenReveal(null)}
      />

      <ConfirmDialog
        open={Boolean(confirmAction)}
        title={confirmAction?.kind === 'suspend' ? 'Suspend this agent?' : 'Rotate this agent token?'}
        confirmLabel={confirmAction?.kind === 'suspend' ? 'Suspend agent' : 'Rotate token'}
        danger={confirmAction?.kind === 'rotate'}
        onCancel={() => setConfirmAction(null)}
        onConfirm={async () => {
          try {
            await performConfirmAction()
          } catch (cause) {
            toast.error('Action failed', describeError(cause))
            setConfirmAction(null)
          }
        }}
      >
        {confirmAction?.kind === 'suspend' ? (
          <div className="stack gap-8">
            <div>
              <strong>{confirmAction.agent.name}</strong> is blocked from all agent API calls
              immediately. Existing credentials keep working until they expire.
            </div>
            <div>You can reactivate the agent at any time from its detail panel.</div>
          </div>
        ) : (
          <div className="stack gap-8">
            <div>
              A new bearer token is generated for <strong>{confirmAction?.agent.name}</strong>.
              The current token stops working immediately — update the agent before it next calls
              the API.
            </div>
            <div>The new token is shown exactly once in the next dialog.</div>
          </div>
        )}
      </ConfirmDialog>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Create agent modal                                                  */
/* ------------------------------------------------------------------ */

interface CreateAgentModalProps {
  open: boolean
  capabilities: Capability[]
  capabilitiesLoading: boolean
  capabilitiesError: ApiError | null
  policy: PolicySettings | null
  onClose: () => void
  onCreated: (created: AgentWithToken) => void
}

function groupByRisk(capabilities: Capability[]) {
  return RISK_ORDER.map((risk) => ({
    risk,
    items: capabilities.filter((capability) => capability.risk === risk),
  })).filter((group) => group.items.length > 0)
}

function CreateAgentModal({
  open,
  capabilities,
  capabilitiesLoading,
  capabilitiesError,
  policy,
  onClose,
  onCreated,
}: CreateAgentModalProps) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [grants, setGrants] = useState<Set<string>>(new Set())
  const [ttlInput, setTtlInput] = useState('1h')
  const [concurrency, setConcurrency] = useState('3')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setName('')
    setDescription('')
    setGrants(new Set())
    setTtlInput(formatTTL(policy?.max_lease_ttl_seconds ?? 3600))
    setConcurrency(String(policy?.max_concurrent_leases_per_agent ?? 3))
    setError(null)
  }, [open, policy])

  function toggleGrant(id: string) {
    setGrants((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function submit() {
    if (name.trim() === '') {
      setError('Agent name is required.')
      return
    }
    const ttl = parseDurationInput(ttlInput)
    if (ttl === null || ttl <= 0) {
      setError('Max TTL must be a duration such as 30m or 1h.')
      return
    }
    const maxConcurrent = Number(concurrency)
    if (!Number.isInteger(maxConcurrent) || maxConcurrent <= 0) {
      setError('Max concurrent leases must be a positive whole number.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const created = await createAgent({
        name: name.trim(),
        description: description.trim(),
        grants: Array.from(grants).sort(),
        max_ttl_seconds: ttl,
        max_concurrent_leases: maxConcurrent,
      })
      toast.success('Agent created', `${created.agent.name} can now authenticate.`)
      onCreated(created)
    } catch (cause) {
      setError(describeError(cause))
    } finally {
      setBusy(false)
    }
  }

  const groups = groupByRisk(capabilities)

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Create agent"
      subtitle="Issue a new identity with a one-time bearer token and least-privilege grants."
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            icon={<IconPlus size={15} />}
            loading={busy}
            onClick={() => void submit()}
          >
            Create agent
          </Button>
        </>
      }
    >
      <div className="stack" style={{ gap: 18 }}>
        <InlineNotice kind="info" title="How agents authenticate">
          The agent receives a bearer token once and uses it only to request capability leases.
          It never sees the cloud broker AccessKey.
        </InlineNotice>

        <div className="form-grid">
          <Field label="Name" htmlFor="agent-name" required className="form-span-2">
            <input
              id="agent-name"
              className="input"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="e.g. claude-code"
              autoComplete="off"
            />
          </Field>
          <Field
            label="Description"
            htmlFor="agent-description"
            className="form-span-2"
            hint="What is this agent responsible for? Shown to approvers next to its requests."
          >
            <textarea
              id="agent-description"
              className="textarea"
              style={{ minHeight: 64 }}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Primary coding agent for DNS, certificates and ECS operations"
              maxLength={280}
            />
          </Field>
          <Field label="Max lease TTL" htmlFor="agent-ttl" hint="Duration such as 30m, 1h or 3600.">
            <input
              id="agent-ttl"
              className="input input--mono"
              value={ttlInput}
              onChange={(event) => setTtlInput(event.target.value)}
              placeholder="1h"
              autoComplete="off"
            />
          </Field>
          <Field label="Max concurrent leases" htmlFor="agent-concurrency">
            <input
              id="agent-concurrency"
              className="input input--mono"
              type="number"
              min={1}
              max={100}
              value={concurrency}
              onChange={(event) => setConcurrency(event.target.value)}
            />
          </Field>
        </div>

        <div className="field">
          <div className="row-between">
            <span className="field__label">Capability grants</span>
            <span className="muted" style={{ fontSize: 11.5 }}>
              {grants.size} selected
            </span>
          </div>
          <div className="field__hint" style={{ marginBottom: 6 }}>
            Only granted capabilities can be requested. Risk above the auto-approve threshold
            requires an operator decision.
          </div>
          {capabilitiesLoading ? (
            <div className="stack gap-8">
              <Skeleton height={38} />
              <Skeleton height={38} />
            </div>
          ) : capabilitiesError ? (
            <ErrorBanner error={capabilitiesError} title="Capabilities unavailable" />
          ) : groups.length === 0 ? (
            <EmptyState title="No capabilities available" hint="Seed the catalog before creating agents." />
          ) : (
            <div className="stack" style={{ gap: 14 }}>
              {groups.map((group) => (
                <div key={group.risk} className="stack" style={{ gap: 4 }}>
                  <div className="row gap-8">
                    <RiskBadge risk={group.risk} />
                    <span className="muted" style={{ fontSize: 11 }}>
                      {group.items.length} capabilit{group.items.length === 1 ? 'y' : 'ies'}
                    </span>
                  </div>
                  <div className="checkbox-grid">
                    {group.items.map((capability) => (
                      <label className="checkbox" key={capability.id}>
                        <input
                          type="checkbox"
                          checked={grants.has(capability.id)}
                          onChange={() => toggleGrant(capability.id)}
                          disabled={!capability.enabled}
                        />
                        <span className="checkbox__text">
                          <strong>{capability.name}</strong>
                          <span className="mono">{capability.id}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
          {grants.size === 0 && groups.length > 0 && (
            <div className="field__hint" style={{ color: 'var(--amber)', marginTop: 4 }}>
              No grants selected — this agent will not be able to request any capability.
            </div>
          )}
        </div>

        {error && (
          <div className="banner banner--error" role="alert">
            {error}
          </div>
        )}
      </div>
    </Drawer>
  )
}

/* ------------------------------------------------------------------ */
/* Agent detail drawer                                                 */
/* ------------------------------------------------------------------ */

interface AgentDetailDrawerProps {
  agent: Agent | null
  capabilities: Capability[]
  policy: PolicySettings | null
  refreshKey: number
  onClose: () => void
  onUpdated: (agent: Agent) => void
  onRequestSuspend: (agent: Agent) => void
  onRequestRotate: (agent: Agent) => void
}

function AgentDetailDrawer({
  agent,
  capabilities,
  policy,
  refreshKey,
  onClose,
  onUpdated,
  onRequestSuspend,
  onRequestRotate,
}: AgentDetailDrawerProps) {
  const toast = useToast()
  const [grantIds, setGrantIds] = useState<Set<string>>(new Set())
  const [ttlInput, setTtlInput] = useState('1h')
  const [concurrency, setConcurrency] = useState('3')
  const [savingGrants, setSavingGrants] = useState(false)
  const [savingLimits, setSavingLimits] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [activating, setActivating] = useState(false)

  const leases = useResource<ListResponse<Lease>>(
    (signal) => listLeases({ agent_id: agent?.id ?? '', limit: 8 }, signal),
    [agent?.id, refreshKey],
    Boolean(agent),
  )

  useEffect(() => {
    if (!agent) return
    setGrantIds(new Set(agent.grants))
    setTtlInput(formatTTL(agent.max_ttl_seconds))
    setConcurrency(String(agent.max_concurrent_leases))
    setSaveError(null)
  }, [agent])

  if (!agent) return null
  const currentAgent: Agent = agent

  const groups = groupByRisk(capabilities)
  const dirtyGrants =
    grantIds.size !== agent.grants.length || agent.grants.some((grant) => !grantIds.has(grant))

  function toggleGrant(id: string) {
    setGrantIds((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function saveGrants() {
    setSavingGrants(true)
    setSaveError(null)
    try {
      const updated = await updateAgent(currentAgent.id, { grants: Array.from(grantIds).sort() })
      toast.success('Grants updated', `${updated.grants.length} capabilities granted to ${updated.name}.`)
      onUpdated(updated)
    } catch (cause) {
      setSaveError(describeError(cause))
    } finally {
      setSavingGrants(false)
    }
  }

  async function saveLimits() {
    const ttl = parseDurationInput(ttlInput)
    if (ttl === null || ttl <= 0) {
      setSaveError('Max TTL must be a duration such as 30m or 1h.')
      return
    }
    const maxConcurrent = Number(concurrency)
    if (!Number.isInteger(maxConcurrent) || maxConcurrent <= 0) {
      setSaveError('Max concurrent leases must be a positive whole number.')
      return
    }
    setSavingLimits(true)
    setSaveError(null)
    try {
      const updated = await updateAgent(currentAgent.id, {
        max_ttl_seconds: ttl,
        max_concurrent_leases: maxConcurrent,
      })
      toast.success('Limits updated')
      onUpdated(updated)
    } catch (cause) {
      setSaveError(describeError(cause))
    } finally {
      setSavingLimits(false)
    }
  }

  async function activate() {
    setActivating(true)
    setSaveError(null)
    try {
      const updated = await activateAgent(currentAgent.id)
      toast.success('Agent activated', `${updated.name} can request leases again.`)
      onUpdated(updated)
    } catch (cause) {
      setSaveError(describeError(cause))
    } finally {
      setActivating(false)
    }
  }

  return (
    <Drawer
      open={Boolean(agent)}
      onClose={onClose}
      title="Agent details"
      subtitle={agent.id}
      footer={
        <>
          <span className="muted" style={{ fontSize: 11.5, marginRight: 'auto' }}>
            Changes are audited as agent.updated.
          </span>
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
        </>
      }
    >
      <div className="drawer-section">
        <div className="drawer-identity">
          <span className="drawer-identity__mark" aria-hidden="true">
            <IconAgents size={22} />
          </span>
          <div className="drawer-identity__main">
            <div className="drawer-identity__name">
              {agent.name}
              <StatusBadge status={agent.status} />
            </div>
            <div className="drawer-identity__sub">{agent.id}</div>
          </div>
          <CopyButton value={agent.id} label="Copy ID" />
        </div>
        <div className="meta-list">
          <div className="meta-item">
            <div className="meta-item__label">Token prefix</div>
            <div className="meta-item__value mono">{agent.token_prefix || '—'}</div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Last seen</div>
            <div className="meta-item__value">
              <RelativeTime iso={agent.last_seen_at} />
            </div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Created</div>
            <div className="meta-item__value">{formatDateTime(agent.created_at)}</div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Updated</div>
            <div className="meta-item__value">{formatDateTime(agent.updated_at)}</div>
          </div>
          {agent.description && (
            <div className="meta-item" style={{ gridColumn: '1 / -1' }}>
              <div className="meta-item__label">Description</div>
              <div className="meta-item__value">{agent.description}</div>
            </div>
          )}
        </div>
        <div className="drawer-actions">
          {agent.status === 'active' ? (
            <Button
              variant="danger"
              size="sm"
              icon={<IconBan size={14} />}
              onClick={() => onRequestSuspend(agent)}
            >
              Suspend agent
            </Button>
          ) : agent.status === 'suspended' ? (
            <Button
              variant="primary"
              size="sm"
              icon={<IconCheck size={14} />}
              loading={activating}
              onClick={() => void activate()}
            >
              Activate agent
            </Button>
          ) : null}
          <Button
            variant="secondary"
            size="sm"
            icon={<IconRotate size={14} />}
            onClick={() => onRequestRotate(agent)}
          >
            Rotate token
          </Button>
        </div>
        {agent.status !== 'active' && (
          <InlineNotice kind="warning">
            This agent is {agent.status}. Agent API calls are rejected with 403 until it is
            activated.
          </InlineNotice>
        )}
      </div>

      <div className="drawer-section">
        <div className="drawer-section__title">
          <span>Limits</span>
          <Button
            size="sm"
            variant="secondary"
            loading={savingLimits}
            onClick={() => void saveLimits()}
          >
            Save limits
          </Button>
        </div>
        <div className="limit-grid">
          <Field label="Max TTL" htmlFor="drawer-ttl" hint={`Default ${formatTTL(policy?.max_lease_ttl_seconds ?? 3600)}`}>
            <input
              id="drawer-ttl"
              className="input input--mono"
              value={ttlInput}
              onChange={(event) => setTtlInput(event.target.value)}
            />
          </Field>
          <Field label="Max concurrent leases" htmlFor="drawer-concurrency">
            <input
              id="drawer-concurrency"
              className="input input--mono"
              type="number"
              min={1}
              value={concurrency}
              onChange={(event) => setConcurrency(event.target.value)}
            />
          </Field>
        </div>
      </div>

      <div className="drawer-section">
        <div className="drawer-section__title">
          <span>Capability grants ({grantIds.size})</span>
          <Button
            size="sm"
            variant="secondary"
            loading={savingGrants}
            disabled={!dirtyGrants}
            onClick={() => void saveGrants()}
          >
            {dirtyGrants ? 'Save grants' : 'Saved'}
          </Button>
        </div>
        <div className="stack" style={{ gap: 12 }}>
          {groups.map((group) => (
            <div key={group.risk} className="stack" style={{ gap: 4 }}>
              <div className="row gap-8">
                <RiskBadge risk={group.risk} />
              </div>
              <div className="checkbox-grid">
                {group.items.map((capability) => (
                  <label className="checkbox" key={capability.id}>
                    <input
                      type="checkbox"
                      checked={grantIds.has(capability.id)}
                      onChange={() => toggleGrant(capability.id)}
                    />
                    <span className="checkbox__text">
                      <strong>{capability.name}</strong>
                      <span className="mono">{capability.id}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
        {saveError && (
          <div className="banner banner--error" role="alert">
            {saveError}
          </div>
        )}
      </div>

      <div className="drawer-section">
        <div className="drawer-section__title">
          <span>Recent leases</span>
          <button
            type="button"
            className="panel__link"
            onClick={() => {
              onClose()
              navigate('/leases')
            }}
          >
            All leases →
          </button>
        </div>
        {leases.loading && !leases.data ? (
          <div className="stack gap-8">
            <Skeleton height={32} />
            <Skeleton height={32} />
          </div>
        ) : leases.error ? (
          <ErrorBanner error={leases.error} title="Leases unavailable" />
        ) : (leases.data?.items.length ?? 0) === 0 ? (
          <EmptyState title="No leases yet" hint="This agent has not requested any capability." />
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th scope="col">Capability</th>
                  <th scope="col">Status</th>
                  <th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {leases.data?.items.map((lease) => (
                  <tr key={lease.id}>
                    <td>
                      <div className="cell-primary">{lease.capability_name || lease.capability_id}</div>
                      <div className="mono" style={{ fontSize: 10, color: 'var(--text-faint)' }}>
                        {lease.id}
                      </div>
                    </td>
                    <td>
                      <LeaseStatusBadge status={lease.status} />
                    </td>
                    <td>
                      <RelativeTime iso={lease.created_at} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Drawer>
  )
}
