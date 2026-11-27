import { useState } from 'react'
import { api } from '../api'
import type { LongLivedCredential, LongLivedSecret, Person, PersonAccount, Provider } from '../types'
import { navigate } from '../router'
import { Badge, Button, Card, Empty, ErrorNote, Field, Modal, PageHead, ago, useAction, useConfirm, useLoad, useToast, when, Pending } from '../ui'
import { AWS_BOUNDARY_POLICY_NAME, awsBoundaryPolicy, awsUserAdminPolicy, userAdminPolicy } from '../rolePolicy'

// Long-lived credentials (CONTRACT §17.14): cloud users with access keys that
// do not expire, created only after a person confirms here.

const statusBadge = (c: LongLivedCredential) => {
  switch (c.status) {
    case 'active': return <Badge tone="green">active</Badge>
    case 'pending': return <Badge tone="amber">waiting for you</Badge>
    case 'revoke_failed': return <Badge tone="red">deletion failed</Badge>
    case 'failed': return <Badge tone="red">failed</Badge>
    default: return <Badge>{c.status}</Badge>
  }
}

const scopeOf = (c: LongLivedCredential) =>
  `${c.permission} ${c.resource.toUpperCase()} · ${c.resource_name ? c.resource_name : 'all'}`

/** Copy-able text for the secret answer. */
function Secret({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="code-block">
      <pre aria-label={label}>{value}</pre>
      <Button onClick={async () => { try { await navigator.clipboard.writeText(value); setCopied(true) } catch { /* ignore */ } }}>{copied ? 'Copied' : 'Copy'}</Button>
    </div>
  )
}

/** The link a request gives: the owner checks it and creates the key. */
export function LongLivedConfirmPage({ code }: { code: string }) {
  const req = useLoad(() => api.longLivedRequest(code), [code])
  const [checked, setChecked] = useState(false)
  const [secret, setSecret] = useState<LongLivedSecret | null>(null)
  const [declined, setDeclined] = useState(false)
  const action = useAction()

  if (secret) {
    const exports = secret.env.map((e) => `export ${e.name}='${e.value.replace(/'/g, `'\\''`)}'`).join('\n')
    return (
      <>
        <PageHead title="Long-lived key created" lead="Copy the secret now. It is shown only this once; Cloud Safeguard does not keep it." />
        <Card>
          <dl className="facts">
            <div><dt>Cloud user</dt><dd className="mono">{secret.credential.cloud_user}</dd></div>
            <div><dt>Access</dt><dd>{scopeOf(secret.credential)} on {secret.credential.cloud_account_name}</dd></div>
          </dl>
          <Secret label="Access key ID" value={secret.access_key_id} />
          <Secret label="Secret" value={secret.access_key_secret} />
          <Secret label="Shell" value={exports} />
          <p className="note note-info">The key does not expire. It is deleted when you revoke it, or at once if you lose the right to hold it.</p>
          <div className="row-actions left"><Button kind="primary" onClick={() => { setSecret(null); navigate('/accounts') }}>I saved it</Button></div>
        </Card>
      </>
    )
  }
  if (declined) {
    return <><PageHead title="Declined" /><Card><p>Nothing was created.</p><Button onClick={() => navigate('/accounts')}>Cloud accounts</Button></Card></>
  }
  if (req.error) {
    return (
      <>
        <PageHead title="Long-lived key" />
        <Card><p>This request is unknown, already decided or expired, or it was made by someone else.</p>
          <Button onClick={() => navigate('/accounts')}>Cloud accounts</Button></Card>
      </>
    )
  }
  const c = req.data
  if (!c) return null
  return (
    <>
      <PageHead title="Create a long-lived key?" lead="A cloud user with an access key that does not expire. Only create it if you know what it is for." />
      <Card>
        <dl className="facts facts-spaced">
          <div><dt>Cloud account</dt><dd><b>{c.cloud_account_name}</b> <span className="mono muted">{c.cloud_account_id}</span></dd></div>
          <div><dt>Access</dt><dd><b>{scopeOf(c)}</b></dd></div>
          <div><dt>Asked by</dt><dd>{c.agent_name ? <>your agent <b>{c.agent_name}</b></> : 'you'} · {ago(c.created_at)}</dd></div>
          <div><dt>Reason</dt><dd>“{c.reason}”</dd></div>
        </dl>
        <p className="note note-info">Cloud Safeguard creates a cloud user, a policy limited to this access (never IAM) and an access key, and shows the secret to you once.
          {c.agent_name && ' The agent never receives it.'}</p>
        <label className="check">
          <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} />
          I asked for this key, and I will store its secret safely.
        </label>
        {c.expires_at && <p className="muted small">This link expires {ago(c.expires_at)}.</p>}
        <ErrorNote error={action.error} />
        <div className="row-actions">
          <Button busy={action.busy} onClick={() => action.run(async () => { await api.denyLongLived(code); setDeclined(true) })}>Decline</Button>
          <Button kind="primary" busy={action.busy} disabled={!checked} onClick={() => action.run(async () => setSecret(await api.createLongLived(code)))}>Create key</Button>
        </div>
      </Card>
    </>
  )
}

/** Long-lived keys on the Cloud accounts page: the person's own (or, for a
 * supervisor, everyone's), revoking, and asking for a new one. */
export function LongLivedCard({ person, accounts }: { person: Person; accounts: PersonAccount[] }) {
  const list = useLoad(() => (person.supervisor ? api.allLongLived() : api.myLongLived()), [person.supervisor])
  const [asking, setAsking] = useState(false)
  const toast = useToast()
  const { confirm, element: confirmDialog } = useConfirm()
  const allowed = person.supervisor || person.long_lived
  const items = (list.data?.items ?? []).filter((c) => c.status !== 'expired' && c.status !== 'denied')
  if (!allowed && items.length === 0) return null
  return (
    <Card title="Long-lived keys">
      <p className="muted">Cloud users with access keys that do not expire, for things like a CDN origin or a bucket sync. Revoking deletes the key, its policy and the user in the cloud.</p>
      <ErrorNote error={list.error} />
      {!list.ready ? <Pending error={list.error} /> : items.length === 0 ? <Empty>None.</Empty> : (
        <table className="table compact">
          <thead><tr><th>Account</th><th>Access</th><th>Cloud user</th>{person.supervisor && <th>Owner</th>}<th>Created</th><th>Status</th><th /></tr></thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.id}>
                <td>{c.cloud_account_name}</td>
                <td>{scopeOf(c)}</td>
                <td className="mono">{c.cloud_user || '—'}</td>
                {person.supervisor && <td>{c.owner_name}</td>}
                <td>{when(c.created_at)}</td>
                <td>{statusBadge(c)}{c.failure_reason && <div className="muted small">{c.failure_reason}</div>}</td>
                <td className="right">{(c.status === 'active' || c.status === 'revoke_failed') && (person.supervisor || c.owner_id === person.id) &&
                  <Button kind="link" onClick={() => confirm({
                    title: `Revoke ${c.cloud_user}?`, body: 'The key, its policy and the cloud user are deleted. Whatever uses the key stops working.',
                    confirmLabel: 'Revoke', danger: true,
                    run: async () => {
                      const out = person.supervisor ? await api.supRevokeLongLived(c.id) : await api.revokeLongLived(c.id)
                      toast(out.status === 'revoked' ? 'Deleted' : `Deletion failed: ${out.failure_reason ?? ''}`, out.status === 'revoked' ? 'ok' : 'error')
                      list.reload()
                    },
                  })}>Revoke</Button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {allowed && <div className="row-actions left"><Button onClick={() => setAsking(true)}>+ New long-lived key</Button></div>}
      {asking && <AskDialog accounts={accounts.filter((a) => a.status === 'active')} onClose={() => setAsking(false)} />}
      {confirmDialog}
    </Card>
  )
}

const RESOURCES: Record<string, string[]> = { aliyun: ['ecs', 'dns', 'oss'], aws: ['s3'] }
const RESOURCE_LABEL: Record<string, string> = { ecs: 'ECS instances', dns: 'DNS domains', oss: 'OSS buckets', s3: 'S3 buckets' }
const PERMISSION_LABEL: Record<string, string> = { read: 'read', write: 'write: change existing', full: 'full: also create and delete' }

function AskDialog({ accounts, onClose }: { accounts: PersonAccount[]; onClose: () => void }) {
  const [account, setAccount] = useState(accounts[0]?.cloud_account_id ?? '')
  const acct = accounts.find((a) => a.cloud_account_id === account)
  const resources = RESOURCES[acct?.provider_type ?? 'aliyun'] ?? []
  const [resource, setResource] = useState(resources[0] ?? '')
  const [permission, setPermission] = useState('read')
  const [name, setName] = useState('')
  const [reason, setReason] = useState('')
  const action = useAction()
  return (
    <Modal title="New long-lived key" onClose={onClose}>
      <label className="field"><span>Cloud account</span>
        <select value={account} onChange={(e) => { setAccount(e.target.value); setResource(RESOURCES[accounts.find((a) => a.cloud_account_id === e.target.value)?.provider_type ?? 'aliyun']?.[0] ?? '') }}>
          {accounts.map((a) => <option key={a.provider_id} value={a.cloud_account_id}>{a.name} · {a.cloud_account_id}</option>)}
        </select>
      </label>
      <label className="field"><span>Resource type</span>
        <select value={resource} onChange={(e) => setResource(e.target.value)}>{resources.map((r) => <option key={r} value={r}>{RESOURCE_LABEL[r] ?? r}</option>)}</select>
      </label>
      <label className="field"><span>Permission</span>
        <select value={permission} onChange={(e) => setPermission(e.target.value)}>
          {['read', 'write', 'full'].map((p) => <option key={p} value={p}>{PERMISSION_LABEL[p]}</option>)}
        </select>
      </label>
      <Field label="Resource name" value={name} onChange={setName} hint="One bucket, instance or domain. Leave empty for all of that type." />
      <Field label="What it is for" value={reason} onChange={setReason} />
      <ErrorNote error={action.error} />
      <div className="row-actions">
        <Button onClick={onClose}>Cancel</Button>
        <Button kind="primary" busy={action.busy} disabled={!account || !resource || !reason.trim()} onClick={() => action.run(async () => {
          const out = await api.askLongLived({ cloud_account_id: account, resource, permission, resource_name: name.trim() || undefined, reason: reason.trim() })
          const key = new URL(out.link).searchParams.get('long-lived') ?? ''
          onClose()
          navigate(`/long-lived?code=${encodeURIComponent(key)}`)
        })}>Continue</Button>
      </div>
    </Modal>
  )
}

/** The supervisor's switch for one account: the second key that creates
 * long-lived credentials. */
export function UserAdminSection({ account, onChange }: { account: Provider; onChange: () => void }) {
  const [open, setOpen] = useState(false)
  const [keyId, setKeyId] = useState('')
  const [secret, setSecret] = useState('')
  const action = useAction()
  const toast = useToast()
  const enabled = Boolean(account.user_admin_key_masked)
  const id = account.cloud_account_id ?? '<account-id>'
  const policy = account.type === 'aws' ? awsUserAdminPolicy(id) : userAdminPolicy(id)
  return (
    <>
      <h3>Long-lived keys</h3>
      {enabled ? (
        <p className="muted small">Enabled with key {account.user_admin_key_masked}. People you allow can create cloud users with keys that do not expire here.</p>
      ) : (
        <p className="muted small">Off. Turning it on needs a second key, used only to create and delete <span className="mono">csg</span> users; short-lived access never uses it.</p>
      )}
      <ErrorNote error={action.error} />
      <div className="row-actions left">
        {enabled
          ? <Button busy={action.busy} onClick={() => action.run(async () => { await api.clearUserAdmin(account.id); toast('Long-lived keys turned off'); onChange() })}>Turn off</Button>
          : <Button onClick={() => setOpen(true)}>Turn on…</Button>}
      </div>
      {open && (
        <Modal title={`Long-lived keys on ${account.name}`} onClose={() => setOpen(false)}>
          {account.type === 'aws' && <>
            <p className="muted small"><strong>1.</strong> Create a customer managed policy named <span className="mono">{AWS_BOUNDARY_POLICY_NAME}</span> with this content. Every user made here is bounded by it: it can never do more than the role, and never IAM.</p>
            <div className="code-block"><pre>{awsBoundaryPolicy()}</pre></div>
            <p className="muted small"><strong>2.</strong> Create a separate IAM user (not under path <span className="mono">/csg/</span>, and not named <span className="mono">csg-…</span>) with an access key and only this policy.</p>
          </>}
          {account.type !== 'aws' && <p className="muted small">Create a separate RAM user (not named <span className="mono">csg-…</span>) with an access key and only this policy.</p>}
          <div className="code-block"><pre>{policy}</pre></div>
          {account.type !== 'aws' && <p className="note note-warn">RAM has no permissions boundary, and this key may write csg policies with any content: whoever holds it can give a csg user full access to the account. Treat it as an account administrator's key.</p>}
          {account.mode !== 'mock' && <>
            <Field label="Access key ID" value={keyId} onChange={setKeyId} autoComplete="off" />
            <Field label="Secret" value={secret} onChange={setSecret} type="password" autoComplete="off" />
          </>}
          <div className="row-actions">
            <Button onClick={() => setOpen(false)}>Cancel</Button>
            <Button kind="primary" busy={action.busy} disabled={account.mode !== 'mock' && (!keyId.trim() || !secret)} onClick={() => action.run(async () => {
              await api.setUserAdmin(account.id, keyId.trim(), secret)
              setSecret('')
              setOpen(false)
              toast('Long-lived keys turned on')
              onChange()
            })}>Test and turn on</Button>
          </div>
        </Modal>
      )}
    </>
  )
}
