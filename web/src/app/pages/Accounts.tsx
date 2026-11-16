import { useState } from 'react'
import { api } from '../api'
import type { ApprovalMode, Person, Provider, Role } from '../types'
import { navigate } from '../router'
import {
  Badge, Button, Card, Empty, ErrorNote, Field, Modal, PageHead, ago, roleHint, roleLabel, useAction, useConfirm, useLoad, useToast,
} from '../ui'

const LEVELS: { value: ApprovalMode; label: string }[] = [
  { value: 'read', label: 'Read only' }, { value: 'write', label: 'Up to write' }, { value: 'full', label: 'Up to full' },
]

export function AccountsPage({ person }: { person: Person }) {
  const mine = useLoad(() => api.myAccounts(), [])
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
            <thead><tr><th>Account</th><th>Your role</th><th>Your agents get without asking</th><th>Status</th></tr></thead>
            <tbody>
              {mine.data!.items.map((a) => (
                <tr key={a.provider_id}>
                  <td><b>{a.name}</b><div className="mono muted small">{a.cloud_account_id}</div></td>
                  <td>{roleLabel[a.role] ?? a.role} <span className="muted small">· {roleHint[a.role]}</span></td>
                  <td>{a.automatic_up_to ? <Badge tone="blue">{a.automatic_up_to}</Badge> : <span className="muted">nothing</span>}</td>
                  <td>{a.status === 'active' ? <Badge tone="green">active</Badge> : <Badge>disabled</Badge>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {person.supervisor && <ManageAccounts onChange={mine.reload} />}
    </>
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
            Alibaba Cloud · <span className="mono">{account.cloud_account_id || 'no account ID'}</span> · {account.region}
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

          <h3>What agents get without asking</h3>
          <p className="muted small">The most any person's approval mode can issue automatically on this account. Above it, the agent's owner must approve.</p>
          <div className="segmented" role="radiogroup">
            {LEVELS.map((l) => (
              <button key={l.value} role="radio" aria-checked={account.max_auto_level === l.value}
                onClick={() => l.value !== account.max_auto_level && ask(`Set ${account.name} to "${l.label.toLowerCase()}"?`,
                  l.value === 'read'
                    ? 'Every change on this account will need the agent owner\'s approval.'
                    : `People whose approval mode allows it will get ${l.value} access here without approving each request.`,
                  'Change level', () => api.setAutoLevel(account.id, l.value), 'Level changed')}>{l.label}</button>
            ))}
          </div>

          <h3>Connection</h3>
          <p className="muted small">
            Key {account.access_key_id_masked || '—'} · role <span className="mono">{account.role_arn || '—'}</span> ·
            last test {account.last_tested_at ? `${account.last_test_ok ? 'passed' : 'failed'} ${ago(account.last_tested_at)}` : 'never'}
          </p>
          <div className="row-actions left">
            <Button busy={action.busy} onClick={() => action.run(async () => {
              const result = await api.testAccount(account.id)
              toast(result.ok ? 'Connection works' : `Connection failed: ${result.message}`, result.ok ? 'ok' : 'error')
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
