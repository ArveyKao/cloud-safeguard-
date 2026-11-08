/** Dashboard: live control-plane counts, approval queue, leases, risk, audit. */
import { useEffect, useState } from 'react'
import { fetchOverview, listCapabilities, testProvider } from '../api/client'
import { syncServerClock, usePolling, useResource } from '../api/hooks'
import type { Lease, Overview, Provider } from '../api/types'
import { formatRelative, formatTTL, formatDateTime, formatDuration, truncateMiddle } from '../lib/format'
import { navigate } from '../router'
import {
  Button,
  EmptyState,
  ErrorBanner,
  PageHeader,
  Panel,
  RiskBadge,
  Skeleton,
  StatCard,
} from '../components/primitives'
import { LeaseCountdown, RelativeTime, RiskBar } from '../components/display'
import { LeaseDecisionActions } from '../components/LeaseDecision'
import { LeaseDetailModal } from '../components/LeaseDetailModal'
import { useToast, describeError } from '../components/Toasts'
import {
  IconActivity,
  IconAgents,
  IconAudit,
  IconChevronRight,
  IconKey,
  IconLeases,
  IconProviders,
  IconRefresh,
  IconShield,
} from '../components/icons'

interface OverviewPageProps {
  refreshKey: number
  onPendingCount: (count: number) => void
}

export function OverviewPage({ refreshKey, onPendingCount }: OverviewPageProps) {
  const toast = useToast()
  const [selectedLease, setSelectedLease] = useState<Lease | null>(null)
  const [testingProviderId, setTestingProviderId] = useState<string | null>(null)

  const overview = usePolling<Overview>(fetchOverview, 4000, { deps: [refreshKey] })
  const capabilities = useResource(listCapabilities, [refreshKey])
  const data = overview.data
  const loading = overview.loading && !data

  useEffect(() => {
    if (data?.server_time) syncServerClock(data.server_time)
    if (data) onPendingCount(data.counts.pending_leases)
  }, [data, onPendingCount])

  async function handleProviderTest(provider: Provider) {
    setTestingProviderId(provider.id)
    try {
      const result = await testProvider(provider.id)
      if (result.ok) toast.success(`${provider.name} reachable`, result.message)
      else toast.error(`${provider.name} test failed`, result.message)
      await overview.refresh()
    } catch (cause) {
      toast.error('Provider test failed', describeError(cause))
    } finally {
      setTestingProviderId(null)
    }
  }

  function handleLeaseUpdated(updated: Lease) {
    setSelectedLease((current) => (current && current.id === updated.id ? updated : current))
    void overview.refresh()
  }

  const counts = data?.counts
  const pending = data?.pending_leases ?? []
  const active = data?.active_leases ?? []
  const events = data?.recent_events ?? []
  const providers = data?.providers ?? []
  const policy = data?.policy
  const vault = data?.vault

  return (
    <div className="page">
      <PageHeader
        eyebrow="Operations"
        title="Overview"
        subtitle={
          data ? (
            <>
              Control plane v{data.version} · uptime {formatDuration(data.uptime_seconds)} ·{' '}
              {counts?.capabilities ?? 0} capabilities across {counts?.providers ?? 0}{' '}
              {counts?.providers === 1 ? 'provider' : 'providers'}
            </>
          ) : (
            'Live state of agents, leases and the credential vault.'
          )
        }
        metaLabel="Updated"
        metaValue={overview.lastUpdated ? formatDateTime(overview.lastUpdated.toISOString()) : '—'}
        actions={
          <>
            <Button
              variant="secondary"
              icon={<IconRefresh size={15} className={overview.refreshing ? 'btn__spinner' : ''} />}
              onClick={() => void overview.refresh()}
              disabled={overview.refreshing}
            >
              Refresh
            </Button>
            <Button variant="ghost" onClick={() => navigate('/leases')}>
              All leases
            </Button>
          </>
        }
      />

      {overview.error && (
        <div style={{ marginBottom: 18 }}>
          <ErrorBanner
            error={overview.error}
            onRetry={() => void overview.refresh()}
            title="Overview could not refresh"
          />
        </div>
      )}

      <div className="grid-stats">
        <StatCard
          label="Agents"
          value={counts?.active_agents ?? 0}
          suffix={counts ? `of ${counts.agents} total` : undefined}
          sub="Non-human identities with scoped grants"
          icon={<IconAgents size={16} />}
          tone="sky"
          loading={loading}
        />
        <StatCard
          label="Active leases"
          value={counts?.active_leases ?? 0}
          sub="Live credentials that auto-expire on TTL"
          icon={<IconLeases size={16} />}
          tone="accent"
          loading={loading}
        />
        <StatCard
          label="Pending approvals"
          value={counts?.pending_leases ?? 0}
          sub={
            counts && counts.pending_leases > 0
              ? 'Waiting on a human decision'
              : 'Queue clear — nothing waiting'
          }
          icon={<IconShield size={16} />}
          tone="amber"
          attention={Boolean(counts && counts.pending_leases > 0)}
          loading={loading}
        />
        <StatCard
          label="Audit events · 24h"
          value={counts?.events_24h ?? 0}
          sub={`${counts?.denied_leases_24h ?? 0} denied leases in the same window`}
          icon={<IconAudit size={16} />}
          tone="violet"
          loading={loading}
        />
      </div>

      <div className="grid-overview">
        <div className="stack">
          <Panel
            flush
            title="Approval queue"
            subtitle={
              pending.length > 0
                ? `${pending.length} request${pending.length === 1 ? '' : 's'} waiting for a decision`
                : 'Risky requests park here until an operator decides'
            }
            icon={<IconShield size={16} />}
            actions={
              pending.length > 0 ? (
                <span className="badge badge--pending badge--dot">{pending.length} pending</span>
              ) : (
                <span className="badge badge--neutral">clear</span>
              )
            }
            footer={
              <>
                <span>
                  Pending requests expire after{' '}
                  <span className="mono">{policy ? formatTTL(policy.pending_timeout_seconds) : '10m'}</span>
                </span>
                <button type="button" className="panel__link" onClick={() => navigate('/leases')}>
                  Open leases <IconChevronRight size={13} />
                </button>
              </>
            }
          >
            {loading ? (
              <div style={{ padding: 18 }} className="stack gap-12">
                {[0, 1].map((index) => (
                  <div key={index} className="stack gap-8">
                    <Skeleton width="42%" height={14} />
                    <Skeleton width="70%" />
                    <Skeleton width="55%" />
                  </div>
                ))}
              </div>
            ) : pending.length === 0 ? (
              <div style={{ padding: 16 }}>
                <EmptyState
                  icon={<IconShield size={18} />}
                  title="No approvals waiting"
                  hint="When an agent requests a capability above the auto-approve threshold, it appears here with its risk, parameters and stated reason. Read-only work never interrupts you."
                />
              </div>
            ) : (
              <div className="approval-list">
                {pending.map((lease) => (
                  <div className="approval-item" key={lease.id}>
                    <div className="approval-item__head">
                      <RiskBadge risk={lease.risk} />
                      <div className="approval-item__title">
                        <button
                          type="button"
                          className="panel__link"
                          style={{ color: 'var(--text)', fontSize: 'inherit', fontWeight: 570 }}
                          onClick={() => setSelectedLease(lease)}
                        >
                          {lease.capability_name || lease.capability_id}
                        </button>{' '}
                        <span className="mono">
                          {lease.id} · {lease.agent_name}
                        </span>
                      </div>
                      <span className="approval-item__wait">
                        <span className="status-dot status-dot--amber" aria-hidden="true" />
                        queued {formatRelative(lease.created_at)}
                      </span>
                    </div>
                    <div className="approval-item__meta">
                      <span className="chip chip--key">{lease.capability_id}</span>
                      {lease.break_glass && <span className="badge badge--critical">break-glass</span>}
                      {lease.params &&
                        Object.entries(lease.params).map(([key, value]) => (
                          <span className="chip" key={key}>
                            <span className="chip__label">{key}</span>
                            {value}
                          </span>
                        ))}
                      <span>
                        Requested TTL <span className="mono">{formatTTL(lease.requested_ttl_seconds)}</span>
                      </span>
                      <span>·</span>
                      <span>
                        Decision TTL{' '}
                        <span className="mono">{formatTTL(lease.effective_ttl_seconds)}</span>
                      </span>
                    </div>
                    {lease.reason && <div className="approval-item__reason">“{lease.reason}”</div>}
                    <LeaseDecisionActions
                      lease={lease}
                      capabilities={capabilities.data?.items ?? null}
                      policy={policy ?? null}
                      onUpdated={handleLeaseUpdated}
                    />
                  </div>
                ))}
              </div>
            )}
          </Panel>

          <Panel
            flush
            title="Active leases"
            subtitle="Credentials in flight — revoked immediately when revoked or expired"
            icon={<IconLeases size={16} />}
            actions={
              active.length > 0 ? (
                <span className="badge badge--active badge--dot">{active.length} active</span>
              ) : undefined
            }
            footer={
              <>
                <span>Countdown uses the control-plane clock.</span>
                <button type="button" className="panel__link" onClick={() => navigate('/leases')}>
                  Lease history <IconChevronRight size={13} />
                </button>
              </>
            }
          >
            {loading ? (
              <div style={{ padding: 18 }} className="stack gap-12">
                {[0, 1, 2].map((index) => (
                  <Skeleton key={index} height={34} />
                ))}
              </div>
            ) : active.length === 0 ? (
              <div style={{ padding: 16 }}>
                <EmptyState
                  icon={<IconLeases size={18} />}
                  title="No active leases"
                  hint="Agents get credentials only while a lease is active. Request one from an agent, or auto-approve a read-only capability."
                />
              </div>
            ) : (
              <div>
                {active.map((lease) => (
                  <div className="lease-row" key={lease.id}>
                    <div className="lease-row__main">
                      <div className="lease-row__title">
                        <button
                          type="button"
                          className="panel__link"
                          style={{ color: 'var(--text)', fontSize: 'inherit', fontWeight: 540 }}
                          onClick={() => setSelectedLease(lease)}
                        >
                          {lease.agent_name}
                        </button>
                        <span className="muted">·</span>
                        <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                          {truncateMiddle(lease.capability_id, 28)}
                        </span>
                        <RiskBadge risk={lease.risk} />
                      </div>
                      <div className="lease-row__sub">
                        <span className="mono">{lease.id}</span>
                        <span>·</span>
                        <span>{lease.credential_fingerprint || 'credential issued'}</span>
                        {lease.break_glass && <span className="badge badge--critical">break-glass</span>}
                      </div>
                    </div>
                    <div className="lease-row__expiry">
                      <span className="lease-row__expiry-label">expires in</span>
                      <LeaseCountdown expiresAt={lease.expires_at} />
                    </div>
                    <div className="lease-row__actions">
                      <LeaseDecisionActions
                        lease={lease}
                        capabilities={capabilities.data?.items ?? null}
                        policy={policy ?? null}
                        onUpdated={handleLeaseUpdated}
                        align="end"
                      />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>

        <div className="stack">
          <Panel
            title="Risk distribution"
            subtitle="Active + pending leases by blast radius"
            icon={<IconActivity size={16} />}
          >
            {loading || !data ? (
              <div className="stack gap-12">
                <Skeleton height={26} width="45%" />
                <Skeleton height={9} />
                <Skeleton height={50} />
              </div>
            ) : (
              <>
                <RiskBar risk={data.risk_breakdown} />
                {policy && (
                  <div className="guardrail-chips">
                    <span className="chip">
                      auto ≤ <span className="mono">{policy.auto_approve_max_risk}</span> &amp;{' '}
                      <span className="mono">{formatTTL(policy.auto_approve_max_ttl_seconds)}</span>
                    </span>
                    <span className="chip">
                      max <span className="mono">{formatTTL(policy.max_lease_ttl_seconds)}</span>
                    </span>
                    <span className="chip">
                      reason from <span className="mono">{policy.require_reason_for_risk}</span>
                    </span>
                    <button
                      type="button"
                      className="panel__link"
                      onClick={() => navigate('/settings')}
                      style={{ fontSize: 11.5 }}
                    >
                      Edit guardrails
                    </button>
                  </div>
                )}
              </>
            )}
          </Panel>

          <Panel
            title="Providers & vault"
            subtitle="Credential minting health"
            icon={<IconProviders size={16} />}
            footer={
              <>
                <span>{vault?.configured ? 'Vault sealed with master key' : 'Vault not configured'}</span>
                <button type="button" className="panel__link" onClick={() => navigate('/providers')}>
                  Manage <IconChevronRight size={13} />
                </button>
              </>
            }
          >
            {loading ? (
              <div className="stack gap-12">
                <Skeleton height={34} />
                <Skeleton height={34} />
                <Skeleton height={34} />
              </div>
            ) : providers.length === 0 ? (
              <EmptyState
                title="No providers configured"
                hint="Add an Alibaba Cloud provider so the broker can mint credentials."
                action={
                  <Button size="sm" variant="secondary" onClick={() => navigate('/providers')}>
                    Open providers
                  </Button>
                }
              />
            ) : (
              <div>
                {providers.map((provider) => (
                  <div className="health-row" key={provider.id}>
                    <span
                      className={
                        provider.status === 'active'
                          ? 'status-dot status-dot--live'
                          : 'status-dot status-dot--muted'
                      }
                      aria-hidden="true"
                    />
                    <div className="health-row__main">
                      <div className="health-row__name">
                        {provider.name}
                        <span className={provider.mode === 'mock' ? 'badge badge--purple' : 'badge badge--sky'}>
                          {provider.mode}
                        </span>
                      </div>
                      <div className="health-row__meta">
                        {provider.region} · {provider.access_key_id_masked}
                        {provider.last_tested_at ? (
                          <>
                            {' '}
                            · tested{' '}
                            <RelativeTime iso={provider.last_tested_at} />
                            {provider.last_test_ok === false && (
                              <span style={{ color: 'var(--rose)' }}> · failed</span>
                            )}
                          </>
                        ) : (
                          ' · not tested yet'
                        )}
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      loading={testingProviderId === provider.id}
                      onClick={() => void handleProviderTest(provider)}
                    >
                      Test
                    </Button>
                  </div>
                ))}
                {vault && (
                  <div className="vault-row">
                    <span className="vault-row__icon" aria-hidden="true">
                      <IconKey size={16} />
                    </span>
                    <div className="vault-row__main">
                      <div className="vault-row__title">
                        Credential vault{' '}
                        <span className={vault.configured ? 'badge badge--active' : 'badge badge--neutral'}>
                          {vault.configured ? 'configured' : 'unconfigured'}
                        </span>
                      </div>
                      <div className="vault-row__meta">
                        {vault.key_fingerprint || 'no key fingerprint'} · {vault.secrets_stored}{' '}
                        secret{vault.secrets_stored === 1 ? '' : 's'} stored
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </Panel>

          <Panel
            flush
            title="Recent audit"
            subtitle="Newest hash-chained events"
            icon={<IconAudit size={16} />}
            footer={
              <>
                <span className="mono" style={{ fontSize: 10.5 }}>
                  every action is chained
                </span>
                <button type="button" className="panel__link" onClick={() => navigate('/audit')}>
                  Verify chain <IconChevronRight size={13} />
                </button>
              </>
            }
          >
            {loading ? (
              <div style={{ padding: 18 }} className="stack gap-12">
                {[0, 1, 2, 3, 4].map((index) => (
                  <Skeleton key={index} height={28} />
                ))}
              </div>
            ) : events.length === 0 ? (
              <div style={{ padding: 16 }}>
                <EmptyState
                  icon={<IconAudit size={18} />}
                  title="No audit events yet"
                  hint="Requests, approvals, credential fetches and mock cloud calls will appear here."
                />
              </div>
            ) : (
              <div className="feed">
                {events.slice(0, 8).map((event) => (
                  <div className="feed__item" key={event.id || event.seq}>
                    <span
                      className={`feed__dot feed__dot--${
                        event.severity === 'critical'
                          ? 'critical'
                          : event.severity === 'warning'
                            ? 'warning'
                            : 'info'
                      }`}
                      aria-hidden="true"
                    />
                    <div className="feed__body">
                      <div className="feed__action">{event.action}</div>
                      <div className="feed__meta">
                        <span>
                          {event.actor_type}/{event.actor_name || event.actor_id || 'system'}
                        </span>
                        {event.status !== 'ok' && (
                          <span className={`badge badge--${event.status === 'denied' ? 'denied' : 'failed'}`}>
                            {event.status}
                          </span>
                        )}
                      </div>
                    </div>
                    <span className="feed__time" title={formatDateTime(event.time)}>
                      {formatRelative(event.time)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>

      <LeaseDetailModal
        lease={selectedLease}
        capabilities={capabilities.data?.items ?? null}
        policy={policy ?? null}
        onClose={() => setSelectedLease(null)}
        onUpdated={handleLeaseUpdated}
      />
    </div>
  )
}
