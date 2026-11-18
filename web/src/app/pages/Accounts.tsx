import { useState } from 'react'
import { api } from '../api'
import type { ApprovalMode, Person, PersonAccount, Provider, Role } from '../types'
import { navigate } from '../router'
import { LongLivedCard, UserAdminSection } from './LongLived'
import {
  Badge, Button, Card, Empty, ErrorNote, Field, Modal, PageHead, ago, roleHint, roleLabel, useAction, useConfirm, useLoad, useToast, when,
} from '../ui'

const MODES: { value: ApprovalMode; title: string; text: string }[] = [
  { value: 'read', title: 'Read mode', text: 'Reading is automatic. Every change asks you.' },
  { value: 'write', title: 'Write mode', text: 'Reading and changing existing resources are automatic. Creating and deleting ask you.' },
  { value: 'full', title: 'Full mode', text: 'Everything your role allows is automatic. Nothing asks you.' },
]

const KEEP = -1

const EXPIRY = [
  { seconds: 0, label: 'Until I change it' }, { seconds: 3600, label: 'For 1 hour' },
  { seconds: 8 * 3600, label: 'For 8 hours' }, { seconds: 86400, label: 'For 1 day' },
]

const rank: Record<ApprovalMode, number> = { read: 1, write: 2, full: 3 }

export function AccountsPage({ person }: { person: Person }) {
  const mine = useLoad(() => api.myAccounts(), [])
  const [editing, setEditing] = useState<PersonAccount | null>(null)
  return (
    <>
      <PageHead title="Cloud accounts"
        lead={person.supervisor
          ? 'You are a supervisor: you add accounts and give each person a role. You are Administrator on every account yourself.'
          : 'The accounts you have a role on. Your agents inherit it.'}
        actions={person.supervisor && <Button kind="primary" onClick={() => navigate('/accounts/new')}>+ Add cloud account</Button>} />
      <ErrorNote error={mine.error} />
      <Card title="Your roles">
        {(mine.data?.items ?? []).length === 0 ? <Empty>You have no role on any cloud account yet. A supervisor gives you one.</Empty> : (
          <table className="table">
            <thead><tr><th>Account</th><th>Your role</th><th>Your approval mode</th><th>Your agents get without asking</th><th>Status</th></tr></thead>
            <tbody>
              {mine.data!.items.map((a) => (
                <tr key={a.provider_id}>
                  <td><b>{a.name}</b><div className="mono muted small">{a.cloud_account_id}</div></td>
                  <td>{roleLabel[a.role] ?? a.role} <span className="muted small">· {roleHint[a.role]}</span></td>
                  <td>
                    {MODES.find((m) => m.value === a.approval_mode)?.title ?? a.approval_mode}
                    {a.approval_mode_expires_at && <div className="muted small">until {when(a.approval_mode_expires_at)}</div>}
                    <div><Button kind="link" onClick={() => setEditing(a)}>Change</Button></div>
                  </td>
                  <td>{a.automatic_up_to ? <Badge tone="blue">{a.automatic_up_to}</Badge> : <span className="muted">nothing</span>}</td>
                  <td>{a.status === 'active' ? <Badge tone="green">active</Badge> : <Badge>disabled</Badge>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted small">Your approval mode decides, per account, what your agents get without asking you. It never goes beyond your role there.</p>
      </Card>
      <LongLivedCard person={person} accounts={mine.data?.items ?? []} />
      {editing && <ModeDialog account={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); mine.reload() }} />}
      {person.supervisor && <ManageAccounts onChange={mine.reload} />}
    </>
  )
}

/** Sets the person's approval mode on one cloud account. */
function ModeDialog({ account, onClose, onSaved }: { account: PersonAccount; onClose: () => void; onSaved: () => void }) {
  const [mode, setMode] = useState<ApprovalMode>(account.approval_mode)
  // KEEP keeps the current end of a temporary mode; saving must never turn
  // a temporary mode into a permanent one by accident.
  const hasEnd = Boolean(account.approval_mode_expires_at)
  const [expiry, setExpiry] = useState(hasEnd ? KEEP : 0)
  const [confirming, setConfirming] = useState(false)
  const action = useAction()
  const toast = useToast()
  const what = MODES.find((m) => m.value === mode)!

  function expirySeconds(): number {
    if (mode === 'read') return 0
    if (expiry !== KEEP) return expiry
    const left = Math.ceil((new Date(account.approval_mode_expires_at ?? 0).getTime() - Date.now()) / 1000)
    return Math.max(1, left)
  }
  async function save() {
    await api.setMode(account.provider_id, mode, expirySeconds())
    toast(`${account.name}: ${what.title.toLowerCase()} saved`)
    onSaved()
  }
  const raising = rank[mode] > rank[account.approval_mode]
  const endingRemoved = hasEnd && mode !== 'read' && expiry === 0
  // A later end keeps a standing approval longer: confirm that too.
  const endingLater = hasEnd && mode !== 'read' && expiry > 0 &&
    Date.now() + expiry * 1000 > new Date(account.approval_mode_expires_at ?? 0).getTime()

  return (
    <Modal title={`Approval mode on ${account.name}`} onClose={onClose}>
      {confirming ? (
        <>
          <div className="confirm-body">
            <p><b>{raising ? 'Switch to' : 'Keep'} {what.title.toLowerCase()}{expiry === 0 ? ' until you change it'
              : expiry === KEEP ? '' : ` ${EXPIRY.find((x) => x.seconds === expiry)?.label.toLowerCase()}`}?</b></p>
            <p>{what.text} This applies to all your agents on {account.name}, up to your role ({roleLabel[account.role] ?? account.role}).</p>
          </div>
          <ErrorNote error={action.error} />
          <div className="row-actions">
            <Button onClick={() => setConfirming(false)}>Back</Button>
            <Button kind="primary" busy={action.busy} onClick={() => action.run(save)}>Switch</Button>
          </div>
        </>
      ) : (
        <>
          <div className="mode-grid" role="radiogroup">
            {MODES.map((m) => (
              <label key={m.value} className="mode" data-selected={mode === m.value}>
                <input type="radio" name="mode" aria-label={m.title} checked={mode === m.value} onChange={() => setMode(m.value)} />
                <b>{m.title}</b><span>{m.text}</span>
              </label>
            ))}
          </div>
          {mode !== 'read' && (
            <label className="field inline">
              <span>Keep it</span>
              <select value={expiry} onChange={(e) => setExpiry(Number(e.target.value))}>
                {hasEnd && <option value={KEEP}>Until {when(account.approval_mode_expires_at)}, as now</option>}
                {EXPIRY.map((x) => <option key={x.seconds} value={x.seconds}>{x.label}</option>)}
              </select>
            </label>
          )}
          <ErrorNote error={action.error} />
          <div className="row-actions">
            <Button onClick={onClose}>Cancel</Button>
            <Button kind="primary" busy={action.busy}
              onClick={() => (raising || endingRemoved || endingLater ? setConfirming(true) : action.run(save))}>Save</Button>
          </div>
        </>
      )}
    </Modal>
  )
}

function ManageAccounts({ onChange }: { onChange: () => void }) {
  const accounts = useLoad(() => api.accounts(), [])
  const people = useLoad(() => api.people(), [])
  const [open, setOpen] = useState<string | null>(null)
  const list = accounts.data?.items ?? []
  return (
    <>
      <h2 className="section-title">All cloud accounts</h2>
      <ErrorNote error={accounts.error} />
      {list.length === 0 && <Card><Empty>No cloud accounts yet.</Empty></Card>}
      {list.map((p) => (
        <AccountCard key={p.id} account={p} people={people.data?.items ?? []} open={open === p.id}
          onToggle={() => setOpen(open === p.id ? null : p.id)} onChange={() => { accounts.reload(); onChange() }} />
      ))}
    </>
  )
}

function AccountCard({ account, people, open, onToggle, onChange }: {
  account: Provider; people: Person[]; open: boolean; onToggle: () => void; onChange: () => void
}) {
  const bindings = useLoad(() => (open ? api.bindings(account.id) : Promise.resolve(null)), [open, account.id])
  const [adding, setAdding] = useState('')
  const [rotating, setRotating] = useState(false)
  const action = useAction()
  const toast = useToast()
  const { confirm, element: confirmDialog } = useConfirm()
  const byId = new Map(people.map((p) => [p.id, p]))
  const nameOf = (id: string) => { const p = byId.get(id); return p ? (p.display_name || p.username) : id }
  const bound = bindings.data?.items ?? []
  const unbound = people.filter((p) => p.status !== 'suspended' && !bound.some((b) => b.person_id === p.id))

  const run = (fn: () => Promise<unknown>, done: string) => action.run(async () => {
    await fn(); toast(done); bindings.reload(); onChange()
  })
  // Asks first, then runs; the toast and reload follow a confirmed change.
  const ask = (title: string, body: string, confirmLabel: string, fn: () => Promise<unknown>, done: string, danger = false) =>
    confirm({ title, body, confirmLabel, danger, run: async () => { await fn(); toast(done); bindings.reload(); onChange() } })
  const changeRole = (personId: string, from: Role, to: Role) => ask(
    `Make ${nameOf(personId)} ${roleLabel[to].toLowerCase()} on ${account.name}?`,
    to === 'administrator'
      ? `Their agents will be able to ask for full access here, including creating and deleting resources.`
      : `Their agents get at most ${roleHint[to]} here. Credentials beyond that are revoked at once.`,
    'Change role', () => api.putBinding(account.id, personId, to), 'Role changed', to !== 'administrator' && from !== to && roleRank(to) < roleRank(from))

  return (
    <Card>
      <div className="account-head">
        <div>
          <b className="account-name">{account.name}</b>
          <div className="muted small">
            {account.type === 'aws' ? 'AWS' : 'Alibaba Cloud'} · <span className="mono">{account.cloud_account_id || 'no account ID'}</span> · {account.region}
            {account.mode === 'mock' && ' · demo'}
          </div>
        </div>
        <span className="spacer" />
        {account.status === 'active' ? <Badge tone="green">active</Badge> : <Badge>disabled</Badge>}
        <Button onClick={onToggle}>{open ? 'Close' : 'Manage'}</Button>
      </div>
      {open && (
        <div className="account-body">
          <ErrorNote error={action.error ?? bindings.error} />
          <h3>People and roles</h3>
          {bound.length === 0 ? <p className="muted">Nobody has a role here yet.</p> : (
            <table className="table compact">
              <tbody>
                {bound.map((b) => {
                  const p = byId.get(b.person_id)
                  return (
                    <tr key={b.person_id}>
                      <td>{p ? (p.display_name || p.username) : b.person_id}{p?.supervisor && <span className="muted small"> · supervisor</span>}</td>
                      <td>
                        <select value={b.role} aria-label="Role" onChange={(e) => changeRole(b.person_id, b.role, e.target.value as Role)}>
                          {(['guest', 'member', 'administrator'] as Role[]).map((r) => <option key={r} value={r}>{roleLabel[r]} · {roleHint[r]}</option>)}
                        </select>
                      </td>
                      <td className="right"><Button kind="link" onClick={() => ask(`Remove ${nameOf(b.person_id)} from ${account.name}?`,
                        'They and their agents lose all access here, and their credentials on this account are revoked at once.',
                        'Remove', () => api.deleteBinding(account.id, b.person_id), 'Role removed', true)}>Remove</Button></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
          {unbound.length > 0 && (
            <div className="inline-form">
              <select value={adding} onChange={(e) => setAdding(e.target.value)} aria-label="Person">
                <option value="">Give someone a role…</option>
                {unbound.map((p) => <option key={p.id} value={p.id}>{p.display_name || p.username}</option>)}
              </select>
              <Button disabled={!adding} busy={action.busy} onClick={() => run(async () => { await api.putBinding(account.id, adding, 'guest'); setAdding('') }, 'Added as guest')}>Add as guest</Button>
            </div>
          )}

          <UserAdminSection account={account} onChange={onChange} />

          <h3>Connection</h3>
          <p className="muted small">
            Key {account.access_key_id_masked || '—'} · role <span className="mono">{account.role_arn || '—'}</span> ·
            last test {account.last_tested_at ? `${account.last_test_ok ? 'passed' : 'failed'} ${ago(account.last_tested_at)}` : 'never'}
          </p>
          <div className="row-actions left">
            <Button busy={action.busy} onClick={() => action.run(async () => {
              const result = await api.testAccount(account.id)
              toast(result.ok ? (result.warning ? `Connection works, but ${result.warning}` : 'Connection works') : `Connection failed: ${result.message}`,
                result.ok && !result.warning ? 'ok' : 'error')
              onChange()
            })}>Test connection</Button>
            <Button onClick={() => setRotating(true)}>Replace AccessKey</Button>
            {account.status === 'active'
              ? <Button kind="danger" onClick={() => ask(`Disable ${account.name}?`,
                'No agent can get access to it until it is enabled again, and every credential issued on it is revoked at once.',
                'Disable', () => api.updateAccount(account.id, { status: 'disabled' }), 'Disabled; its credentials were revoked', true)}>Disable</Button>
              : <Button onClick={() => run(() => api.updateAccount(account.id, { status: 'active' }), 'Enabled')}>Enable</Button>}
          </div>
        </div>
      )}
      {confirmDialog}
      {rotating && <RotateKey account={account} onClose={() => setRotating(false)} onDone={() => { setRotating(false); onChange() }} />}
    </Card>
  )
}

function RotateKey({ account, onClose, onDone }: { account: Provider; onClose: () => void; onDone: () => void }) {
  const [id, setId] = useState('')
  const [secret, setSecret] = useState('')
  const action = useAction()
  return (
    <Modal title={`Replace the AccessKey of ${account.name}`} onClose={onClose}>
      <Field label="AccessKey ID" value={id} onChange={setId} autoComplete="off" />
      <Field label="AccessKey secret" value={secret} onChange={setSecret} type="password" autoComplete="off"
        hint="Encrypted at once and never shown again." />
      <ErrorNote error={action.error} />
      <div className="row-actions">
        <Button onClick={onClose}>Cancel</Button>
        <Button kind="primary" busy={action.busy} disabled={!id || !secret}
          onClick={() => action.run(async () => { await api.rotateAccount(account.id, id.trim(), secret); setSecret(''); onDone() })}>Replace</Button>
      </div>
    </Modal>
  )
}

const roleRank = (r: Role) => ({ guest: 1, member: 2, administrator: 3 })[r]
