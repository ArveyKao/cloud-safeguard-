/** Lease ledger: server-side filters, pagination, detail modal with decisions. */
import { useEffect, useMemo, useState } from 'react'
import { fetchPolicy, listAgents, listCapabilities, listLeases } from '../api/client'
import { useResource } from '../api/hooks'
import type { Lease, LeaseFilter, ListResponse } from '../api/types'
import { RISK_ORDER } from '../api/types'
import { cx, formatDateTime, formatTTL } from '../lib/format'
import {
  Button,
  EmptyState,
  ErrorBanner,
  LeaseStatusBadge,
  PageHeader,
  RiskBadge,
  Skeleton,
} from '../components/primitives'
import { LeaseCountdown, RelativeTime } from '../components/display'
import { LeaseDetailModal } from '../components/LeaseDetailModal'
import {
  IconChevronDown,
  IconChevronRight,
  IconLeases,
  IconRefresh,
  IconSearch,
} from '../components/icons'

interface LeasesPageProps {
  refreshKey: number
}

const PAGE_SIZE = 50

export function LeasesPage({ refreshKey }: LeasesPageProps) {
  const [status, setStatus] = useState('')
  const [agentId, setAgentId] = useState('')
  const [capabilityId, setCapabilityId] = useState('')
  const [risk, setRisk] = useState('')
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<Lease | null>(null)

  const leases = useResource<ListResponse<Lease>>(
    (signal) =>
      listLeases(
        {
          status: (status || undefined) as LeaseFilter['status'],
          agent_id: agentId || undefined,
          capability_id: capabilityId || undefined,
          limit: PAGE_SIZE,
          offset,
        },
        signal,
      ),
    [refreshKey, status, agentId, capabilityId, offset],
  )

  const capabilities = useResource(listCapabilities, [refreshKey])
  const agents = useResource(listAgents, [refreshKey])
  const policy = useResource(fetchPolicy, [refreshKey])

  useEffect(() => {
    setOffset(0)
  }, [status, agentId, capabilityId])

  const items = leases.data?.items ?? []
  const total = leases.data?.total ?? 0
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return items.filter((lease) => {
      if (risk && lease.risk !== risk) return false
      if (!query) return true
      return (
        lease.id.toLowerCase().includes(query) ||
        lease.agent_name.toLowerCase().includes(query) ||
        lease.agent_id.toLowerCase().includes(query) ||
        lease.capability_id.toLowerCase().includes(query) ||
        lease.capability_name.toLowerCase().includes(query)
      )
    })
  }, [items, risk, search])

  function refreshAll() {
    void leases.refresh()
    void capabilities.refresh()
    void agents.refresh()
    void policy.refresh()
  }

  function handleUpdated(updated: Lease) {
    setSelected((current) => (current && current.id === updated.id ? updated : current))
    void leases.refresh()
  }

  const activeFilterCount =
    (status ? 1 : 0) + (agentId ? 1 : 0) + (capabilityId ? 1 : 0) + (risk ? 1 : 0)

  return (
    <div className="page">
      <PageHeader
        eyebrow="Access"
        title="Leases"
        subtitle="Every request for cloud access, its explainable policy decision, and the credential lifecycle. Pending requests are highlighted."
        metaLabel="Updated"
        metaValue={leases.lastUpdated ? formatDateTime(leases.lastUpdated.toISOString()) : '—'}
        actions={
          <Button
            variant="secondary"
            icon={<IconRefresh size={15} />}
            onClick={refreshAll}
            disabled={leases.refreshing}
          >
            Refresh
          </Button>
        }
      />

      {leases.error && (
        <div style={{ marginBottom: 16 }}>
          <ErrorBanner
            error={leases.error}
            onRetry={() => void leases.refresh()}
            title="Leases could not load"
          />
        </div>
      )}

      <div className="filter-bar" style={{ marginBottom: 16 }}>
        <span className="filter-bar__label">Filters</span>
        <select
          className="select"
          value={status}
          onChange={(event) => setStatus(event.target.value)}
          aria-label="Filter by status"
        >
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="active">Active</option>
          <option value="denied">Denied</option>
          <option value="expired">Expired</option>
          <option value="revoked">Revoked</option>
          <option value="failed">Failed</option>
        </select>
        <select
          className="select"
          value={agentId}
          onChange={(event) => setAgentId(event.target.value)}
          aria-label="Filter by agent"
        >
          <option value="">All agents</option>
          {agents.data?.items.map((agent) => (
            <option key={agent.id} value={agent.id}>
              {agent.name}
            </option>
          ))}
        </select>
        <select
          className="select"
          value={capabilityId}
          onChange={(event) => setCapabilityId(event.target.value)}
          aria-label="Filter by capability"
        >
          <option value="">All capabilities</option>
          {capabilities.data?.items.map((capability) => (
            <option key={capability.id} value={capability.id}>
              {capability.name}
            </option>
          ))}
        </select>
        <div className="input-group" style={{ minWidth: 200, flex: 1, maxWidth: 300 }}>
          <span className="input-group__icon">
            <IconSearch size={15} />
          </span>
          <input
            className="input"
            placeholder="Filter by lease id, agent…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            aria-label="Search loaded leases"
          />
        </div>
        {activeFilterCount > 0 && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setStatus('')
              setAgentId('')
              setCapabilityId('')
              setRisk('')
              setSearch('')
            }}
          >
            Clear filters
          </Button>
        )}
        <span className="toolbar__spacer" />
        <div className="segmented" role="group" aria-label="Filter by risk">
          <button
            type="button"
            className={cx('segmented__item', risk === '' && 'is-active')}
            onClick={() => setRisk('')}
          >
            Any risk
          </button>
          {RISK_ORDER.map((tier) => (
            <button
              key={tier}
              type="button"
              className={cx('segmented__item', risk === tier && 'is-active')}
              onClick={() => setRisk(risk === tier ? '' : tier)}
            >
              {tier}
            </button>
          ))}
        </div>
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th scope="col">Lease</th>
              <th scope="col">Capability</th>
              <th scope="col">Status</th>
              <th scope="col">TTL</th>
              <th scope="col">Created</th>
              <th scope="col">Expires</th>
              <th scope="col" className="cell-actions">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {leases.loading && items.length === 0 ? (
              Array.from({ length: 6 }).map((_, index) => (
                <tr key={`skeleton-${index}`}>
                  {Array.from({ length: 7 }).map((__, cell) => (
                    <td key={cell}>
                      <Skeleton width={cell === 0 ? 150 : 90} />
                    </td>
                  ))}
                </tr>
              ))
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: 0, border: 'none' }}>
                  <div style={{ padding: 20 }}>
                    <EmptyState
                      icon={<IconLeases size={18} />}
                      title={items.length === 0 ? 'No leases found' : 'No leases match this filter'}
                      hint={
                        items.length === 0
                          ? 'When an agent requests a capability, the lease appears here with its policy decision and credential lifecycle.'
                          : 'Clear the filters or widen the search.'
                      }
                    />
                  </div>
                </td>
              </tr>
            ) : (
              filtered.map((lease) => (
                <tr
                  key={lease.id}
                  className={cx(
                    'is-clickable',
                    lease.status === 'pending' && 'row--pending',
                    lease.risk === 'critical' && lease.status === 'active' && 'row--critical',
                  )}
                  onClick={() => setSelected(lease)}
                >
                  <td>
                    <div className="mono" style={{ fontSize: 11.5, color: 'var(--text)' }}>
                      {lease.id}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {lease.agent_name}
                    </div>
                  </td>
                  <td>
                    <div className="cell-primary" style={{ fontSize: 12.5 }}>
                      {lease.capability_name || lease.capability_id}
                    </div>
                    <div className="row gap-6" style={{ marginTop: 3 }}>
                      <RiskBadge risk={lease.risk} />
                      {lease.break_glass && <span className="badge badge--critical">break-glass</span>}
                    </div>
                  </td>
                  <td>
                    <LeaseStatusBadge status={lease.status} />
                  </td>
                  <td>
                    <div className="ttl-cell">
                      <span className="ttl-cell__main">{formatTTL(lease.effective_ttl_seconds)}</span>
                      <span className="ttl-cell__sub">requested {formatTTL(lease.requested_ttl_seconds)}</span>
                    </div>
                  </td>
                  <td>
                    <RelativeTime iso={lease.created_at} />
                  </td>
                  <td>
                    {lease.status === 'active' && lease.expires_at ? (
                      <LeaseCountdown expiresAt={lease.expires_at} />
                    ) : lease.expires_at ? (
                      <span className="mono" style={{ fontSize: 11, color: 'var(--text-faint)' }}>
                        {formatDateTime(lease.expires_at)}
                      </span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td className="cell-actions">
                    <Button
                      variant="ghost"
                      size="sm"
                      icon={<IconChevronRight size={14} />}
                      onClick={(event) => {
                        event.stopPropagation()
                        setSelected(lease)
                      }}
                      aria-label={`Open lease ${lease.id}`}
                    />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        <div className="pagination">
          <span>
            {total === 0
              ? 'No leases'
              : `Showing ${offset + 1}–${Math.min(offset + items.length, total)} of ${total} leases`}
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

      <div className="muted" style={{ fontSize: 11.5, marginTop: 12 }}>
        Server-side filters: status, agent, capability. Risk and text filters apply to the loaded
        page. Click a row to see the policy decision trail.
      </div>

      <LeaseDetailModal
        lease={selected}
        capabilities={capabilities.data?.items ?? null}
        policy={policy.data}
        onClose={() => setSelected(null)}
        onUpdated={handleUpdated}
      />
    </div>
  )
}
