/** Providers & vault: minting health, connection tests, credential rotation, vault status. */
import { useEffect, useState } from 'react'
import {
  fetchOverview,
  listProviders,
  rotateProviderCredential,
  testProvider,
} from '../api/client'
import { useResource } from '../api/hooks'
import type { Provider, ProviderTestResult } from '../api/types'
import { formatDateTime, formatTTL } from '../lib/format'
import { Modal } from '../components/overlays'
import {
  Button,
  EmptyState,
  ErrorBanner,
  Field,
  InlineNotice,
  ModeBadge,
  PageHeader,
  Panel,
  Skeleton,
  StatusBadge,
} from '../components/primitives'
import { RelativeTime } from '../components/display'
import { useToast, describeError } from '../components/Toasts'
import {
  IconAlert,
  IconCheck,
  IconKey,
  IconLock,
  IconProviders,
  IconRefresh,
  IconRotate,
  IconShield,
} from '../components/icons'

interface ProvidersPageProps {
  refreshKey: number
}

export function ProvidersPage({ refreshKey }: ProvidersPageProps) {
  const toast = useToast()
  const providers = useResource(listProviders, [refreshKey])
  const overview = useResource(fetchOverview, [refreshKey])
  const [testingId, setTestingId] = useState<string | null>(null)
  const [testResults, setTestResults] = useState<Record<string, ProviderTestResult>>({})
  const [rotateTarget, setRotateTarget] = useState<Provider | null>(null)

  const items = providers.data?.items ?? []
  const vault = overview.data?.vault

  async function runTest(provider: Provider) {
    setTestingId(provider.id)
    try {
      const result = await testProvider(provider.id)
      setTestResults((current) => ({ ...current, [provider.id]: result }))
      if (result.ok) toast.success(`${provider.name} reachable`, result.message)
      else toast.error(`${provider.name} test failed`, result.message)
      await providers.refresh()
    } catch (cause) {
      toast.error('Provider test failed', describeError(cause))
    } finally {
      setTestingId(null)
    }
  }

  return (
    <div className="page">
      <PageHeader
        eyebrow="Infrastructure"
        title="Providers & vault"
        subtitle="The broker AccessKey lives encrypted in the vault and is only used server-side to mint short-lived credentials. Rotate it here — no agent needs to change."
        metaLabel="Updated"
        metaValue={providers.lastUpdated ? formatDateTime(providers.lastUpdated.toISOString()) : '—'}
        actions={
          <Button
            variant="secondary"
            icon={<IconRefresh size={15} />}
            onClick={() => {
              void providers.refresh()
              void overview.refresh()
            }}
            disabled={providers.refreshing}
          >
            Refresh
          </Button>
        }
      />

      {providers.error && (
        <div style={{ marginBottom: 16 }}>
          <ErrorBanner
            error={providers.error}
            onRetry={() => void providers.refresh()}
            title="Providers could not load"
          />
        </div>
      )}

      <div className="grid-sidebar">
        <div className="stack">
          {providers.loading && items.length === 0 ? (
            <div className="grid-2">
              {[0, 1].map((index) => (
                <div className="panel" key={index} style={{ padding: 20 }}>
                  <Skeleton height={18} width="45%" />
                  <Skeleton className="sk-line" width="30%" />
                  <div style={{ height: 12 }} />
                  <Skeleton height={60} />
                  <div style={{ height: 12 }} />
                  <Skeleton height={34} />
                </div>
              ))}
            </div>
          ) : items.length === 0 ? (
            <Panel title="Providers" icon={<IconProviders size={16} />}>
              <EmptyState
                icon={<IconProviders size={18} />}
                title="No cloud providers wired in yet"
                hint="Initialise a demo instance with `csg init --demo`, or add a provider from the CLI (`csg providers add`). The console displays and rotates providers; creation stays on the audited CLI path."
              />
            </Panel>
          ) : (
            <div className="grid-2">
              {items.map((provider) => {
                const result = testResults[provider.id]
                return (
                  <article className="provider-card" key={provider.id}>
                    <div className="provider-card__head">
                      <span className="provider-card__mark" aria-hidden="true">
                        <IconProviders size={20} />
                      </span>
                      <div className="provider-card__title-wrap">
                        <div className="provider-card__title">
                          {provider.name}
                          <StatusBadge status={provider.status} />
                        </div>
                        <div className="provider-card__id">{provider.id}</div>
                      </div>
                      <ModeBadge mode={provider.mode} />
                    </div>
                    <div className="provider-facts">
                      <div className="provider-fact">
                        <div className="provider-fact__label">Region</div>
                        <div className="provider-fact__value mono">{provider.region}</div>
                      </div>
                      <div className="provider-fact">
                        <div className="provider-fact__label">Masked AccessKey</div>
                        <div className="provider-fact__value mono">{provider.access_key_id_masked}</div>
                      </div>
                      <div className="provider-fact" style={{ gridColumn: '1 / -1' }}>
                        <div className="provider-fact__label">Role ARN</div>
                        <div className="provider-fact__value mono">{provider.role_arn || '—'}</div>
                      </div>
                      <div className="provider-fact">
                        <div className="provider-fact__label">Type</div>
                        <div className="provider-fact__value">{provider.type}</div>
                      </div>
                      <div className="provider-fact">
                        <div className="provider-fact__label">Created</div>
                        <div className="provider-fact__value">{formatDateTime(provider.created_at)}</div>
                      </div>
                    </div>
                    <div className="provider-card__test">
                      {result ? (
                        result.ok ? (
                          <span className="provider-card__test-ok">
                            <IconCheck size={14} /> {result.message}
                          </span>
                        ) : (
                          <span className="provider-card__test-fail">
                            <IconAlert size={14} /> {result.message}
                          </span>
                        )
                      ) : provider.last_tested_at ? (
                        <span>
                          <span
                            className={
                              provider.last_test_ok
                                ? 'status-dot status-dot--live'
                                : 'status-dot status-dot--offline'
                            }
                            aria-hidden="true"
                            style={{ display: 'inline-block', marginRight: 7 }}
                          />
                          Last test <RelativeTime iso={provider.last_tested_at} />
                          {provider.last_test_ok ? ' · passed' : ' · failed'}
                          <span className="mono muted" style={{ marginLeft: 6 }}>
                            {formatDateTime(provider.last_tested_at)}
                          </span>
                        </span>
                      ) : (
                        <span>No connection test recorded yet.</span>
                      )}
                    </div>
                    <div className="provider-card__foot">
                      <Button
                        size="sm"
                        variant="secondary"
                        icon={<IconShield size={13} />}
                        loading={testingId === provider.id}
                        onClick={() => void runTest(provider)}
                      >
                        Test connection
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        icon={<IconRotate size={13} />}
                        onClick={() => setRotateTarget(provider)}
                      >
                        Rotate credential
                      </Button>
                    </div>
                  </article>
                )
              })}
            </div>
          )}
        </div>

        <div className="stack">
          <Panel
            className="vault-card"
            title="Credential vault"
            subtitle="AES-256-GCM envelope encryption"
            icon={<IconLock size={16} />}
          >
            {overview.loading && !vault ? (
              <div className="stack gap-12">
                <Skeleton height={58} />
                <Skeleton height={52} />
              </div>
            ) : vault ? (
              <>
                <div className="row-between">
                  <span className="status-pill">
                    <span
                      className={
                        vault.configured ? 'status-dot status-dot--live' : 'status-dot status-dot--offline'
                      }
                      aria-hidden="true"
                    />
                    {vault.configured ? 'Vault configured' : 'Vault unavailable'}
                  </span>
                  <span className="badge badge--active">encrypted</span>
                </div>
                <div>
                  <div className="meta-item__label">Master key fingerprint</div>
                  <div className="vault-fingerprint">{vault.key_fingerprint || '—'}</div>
                </div>
                <div className="vault-stats">
                  <div className="vault-stat">
                    <div className="vault-stat__value">{vault.secrets_stored}</div>
                    <div className="vault-stat__label">Secrets stored</div>
                  </div>
                  <div className="vault-stat">
                    <div className="vault-stat__value">{items.length}</div>
                    <div className="vault-stat__label">Providers sealed</div>
                  </div>
                </div>
                <div className="row gap-8" style={{ alignItems: 'flex-start' }}>
                  <IconKey size={14} style={{ color: 'var(--text-muted)', marginTop: 2 }} />
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.55 }}>
                    The master key lives outside the database (file mode 0600 or{' '}
                    <span className="mono">CSG_MASTER_KEY</span>). Broker AccessKeys and lease
                    credentials are never returned by any API.
                  </div>
                </div>
              </>
            ) : (
              <ErrorBanner error={overview.error} title="Vault status unavailable" />
            )}
          </Panel>

          <Panel
            title="Rotation runbook"
            subtitle="One place to rotate the broker credential"
            icon={<IconRotate size={16} />}
          >
            <div className="rotation-steps">
              <div className="rotation-step">
                <div>
                  <strong>Create a new AccessKey</strong> for the broker RAM user in the Alibaba
                  Cloud console, granting only <span className="mono">sts:AssumeRole</span> on the
                  role.
                </div>
              </div>
              <div className="rotation-step">
                <div>
                  <strong>Rotate here.</strong> Paste the new AccessKey ID and secret — they are
                  encrypted in the vault and never echoed back.
                </div>
              </div>
              <div className="rotation-step">
                <div>
                  <strong>Test the connection.</strong> Existing leases keep working; new leases
                  mint with the new credential.
                </div>
              </div>
              <div className="rotation-step">
                <div>
                  <strong>Retire the old key.</strong> Disable it in the cloud console. Rotation is
                  recorded as a warning-severity audit event.
                </div>
              </div>
            </div>
            <div className="banner banner--info" style={{ marginTop: 14 }}>
              <IconLock size={15} />
              <div>
                No agent, script, server or cron entry holds this AccessKey — that is the point.
                Rotate once, and everything keeps working.
              </div>
            </div>
          </Panel>

          <Panel
            title="Policy at a glance"
            subtitle="Guardrails the broker enforces"
            icon={<IconShield size={16} />}
            footer={
              <span className="muted" style={{ fontSize: 11.5 }}>
                Edit under Settings
              </span>
            }
          >
            {overview.data ? (
              <div className="stack gap-8">
                <div className="row-between">
                  <span className="muted" style={{ fontSize: 12 }}>
                    Auto-approve up to
                  </span>
                  <span className="mono" style={{ fontSize: 12 }}>
                    {overview.data.policy.auto_approve_max_risk} /{' '}
                    {formatTTL(overview.data.policy.auto_approve_max_ttl_seconds)}
                  </span>
                </div>
                <div className="row-between">
                  <span className="muted" style={{ fontSize: 12 }}>
                    Hard TTL ceiling
                  </span>
                  <span className="mono" style={{ fontSize: 12 }}>
                    {formatTTL(overview.data.policy.max_lease_ttl_seconds)}
                  </span>
                </div>
                <div className="row-between">
                  <span className="muted" style={{ fontSize: 12 }}>
                    Pending timeout
                  </span>
                  <span className="mono" style={{ fontSize: 12 }}>
                    {formatTTL(overview.data.policy.pending_timeout_seconds)}
                  </span>
                </div>
              </div>
            ) : (
              <Skeleton height={60} />
            )}
          </Panel>
        </div>
      </div>

      <RotateCredentialModal
        provider={rotateTarget}
        onClose={() => setRotateTarget(null)}
        onRotated={() => {
          setRotateTarget(null)
          void providers.refresh()
        }}
      />
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Rotate credential modal                                             */
/* ------------------------------------------------------------------ */

interface RotateCredentialModalProps {
  provider: Provider | null
  onClose: () => void
  onRotated: () => void
}

function RotateCredentialModal({ provider, onClose, onRotated }: RotateCredentialModalProps) {
  const toast = useToast()
  const [accessKeyId, setAccessKeyId] = useState('')
  const [accessKeySecret, setAccessKeySecret] = useState('')
  const [revealSecret, setRevealSecret] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (provider) {
      setAccessKeyId('')
      setAccessKeySecret('')
      setRevealSecret(false)
      setError(null)
    }
  }, [provider])

  if (!provider) return null
  const currentProvider: Provider = provider

  async function submit() {
    if (accessKeyId.trim() === '' || accessKeySecret.trim() === '') {
      setError('Both the new AccessKey ID and AccessKey secret are required.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const updated = await rotateProviderCredential(currentProvider.id, {
        access_key_id: accessKeyId.trim(),
        access_key_secret: accessKeySecret.trim(),
      })
      // Clear the form state immediately so secrets do not linger in the DOM.
      setAccessKeyId('')
      setAccessKeySecret('')
      toast.success(
        'Provider credential rotated',
        `Now using ${updated.access_key_id_masked}. Existing leases are unaffected.`,
      )
      onRotated()
    } catch (cause) {
      setError(describeError(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open={Boolean(provider)}
      onClose={onClose}
      title="Rotate broker credential"
      subtitle={`${provider.name} · ${provider.mode === 'mock' ? 'mock cloud signing key placeholder' : 'Alibaba Cloud STS broker AccessKey'}`}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" icon={<IconRotate size={15} />} loading={busy} onClick={() => void submit()}>
            Rotate credential
          </Button>
        </>
      }
    >
      <div className="stack" style={{ gap: 16 }}>
        <InlineNotice kind="warning" title="Security-sensitive operation">
          The new AccessKey is sent once to this control plane, encrypted in the vault, and never
          returned by any API — including this console. Rotation is audited with masked IDs only.
        </InlineNotice>

        <div className="meta-list">
          <div className="meta-item">
            <div className="meta-item__label">Current masked AccessKey</div>
            <div className="meta-item__value mono">{provider.access_key_id_masked}</div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Region</div>
            <div className="meta-item__value mono">{provider.region}</div>
          </div>
        </div>

        <Field label="New AccessKey ID" htmlFor="rotate-akid" required>
          <input
            id="rotate-akid"
            className="input input--mono"
            type="password"
            value={accessKeyId}
            onChange={(event) => setAccessKeyId(event.target.value)}
            autoComplete="off"
            spellCheck={false}
            placeholder="LTAI…"
          />
        </Field>
        <Field
          label="New AccessKey secret"
          htmlFor="rotate-aksecret"
          required
          hint="Stored encrypted with AES-256-GCM; never echoed back or written to logs."
        >
          <div style={{ position: 'relative' }}>
            <input
              id="rotate-aksecret"
              className="input input--mono"
              type={revealSecret ? 'text' : 'password'}
              value={accessKeySecret}
              onChange={(event) => setAccessKeySecret(event.target.value)}
              autoComplete="new-password"
              spellCheck={false}
              placeholder="Paste the new secret"
              style={{ paddingRight: 52 }}
            />
            <button
              type="button"
              className="btn btn--icon btn--ghost btn--sm"
              style={{ position: 'absolute', right: 4, top: '50%', transform: 'translateY(-50%)' }}
              onClick={() => setRevealSecret((value) => !value)}
              aria-label={revealSecret ? 'Hide secret' : 'Show secret'}
            >
              {revealSecret ? 'hide' : 'show'}
            </button>
          </div>
        </Field>

        {error && (
          <div className="banner banner--error" role="alert">
            {error}
          </div>
        )}

        <div className="banner banner--info">
          <IconAlert size={15} />
          <div>
            Existing leases continue until they expire — they were minted with the previous
            credential and are not re-signed. New leases use the new AccessKey immediately.
          </div>
        </div>
      </div>
    </Modal>
  )
}
