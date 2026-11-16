import { useState } from 'react'
import { api } from '../api'
import type { Person, PersonWithSetupCode } from '../types'
import { Badge, Button, Card, ErrorNote, Field, Modal, PageHead, Secret, ago, useAction, useConfirm, useLoad, useToast, when } from '../ui'

/** Supervisors create people, reset them, suspend them and grant the flag. */
export function PeoplePage({ me }: { me: Person }) {
  const people = useLoad(() => api.people(), [])
  const [creating, setCreating] = useState(false)
  const [issued, setIssued] = useState<PersonWithSetupCode | null>(null)
  const action = useAction()
  const toast = useToast()
  const { confirm, element: confirmDialog } = useConfirm()
  const ask = (title: string, body: string, confirmLabel: string, fn: () => Promise<unknown>, danger = true) =>
    confirm({ title, body, confirmLabel, danger, run: async () => { await fn(); people.reload() } })
  const label = (p: Person) => p.display_name || p.username

  return (
    <>
      <PageHead title="People" lead="Who can sign in. Supervisors manage the platform; roles on cloud accounts are set in Cloud accounts."
        actions={<Button kind="primary" onClick={() => setCreating(true)}>+ Add person</Button>} />
      <ErrorNote error={people.error ?? action.error} />
      <Card>
        <table className="table">
          <thead><tr><th>Person</th><th>Status</th><th>Last sign-in</th><th>Password set up</th><th /></tr></thead>
          <tbody>
            {(people.data?.items ?? []).map((p) => (
              <tr key={p.id}>
                <td>
                  <b>{p.display_name || p.username}</b> <span className="muted small">{p.username}</span>
                  {p.supervisor && <> <Badge tone="blue">supervisor</Badge></>}
                </td>
                <td>{p.status === 'active' ? <Badge tone="green">active</Badge> : p.status === 'pending' ? <Badge tone="amber">waiting for setup</Badge> : <Badge>suspended</Badge>}</td>
                <td className="muted">{ago(p.last_login_at)}</td>
                <td className="muted small">{p.setup_issued ? `code from ${p.setup_issued.by_name}, ${when(p.setup_issued.at)}` : '—'}</td>
                <td className="right nowrap">
                  {p.id !== me.id && p.status !== 'suspended' && <Button kind="link" onClick={() => ask(`Suspend ${label(p)}?`,
                    'They are signed out at once and cannot sign in. Their agents stop working and every credential they hold is revoked.',
                    'Suspend', async () => { await api.updatePerson(p.id, { status: 'suspended' }); toast(`${p.username} suspended`) })}>Suspend</Button>}
                  {p.status === 'suspended' && p.setup_issued && <Button kind="link" onClick={() => ask(`Activate ${label(p)}?`,
                    'They can sign in again with their password and authenticator. Their agents work again, within their roles.',
                    'Activate', async () => { await api.updatePerson(p.id, { status: 'active' }); toast(`${p.username} active`) }, false)}>Activate</Button>}
                  <Button kind="link" onClick={() => ask(`Reset ${label(p)}?`,
                    'Their password and authenticator are erased, they are signed out, their approval mode goes back to read and their agents\' credentials are revoked. You get a new setup code to give them.',
                    'Reset', async () => { setIssued(await api.resetPerson(p.id)) })}>Reset</Button>
                  <Button kind="link" onClick={() => ask(p.supervisor ? `Remove ${label(p)} as supervisor?` : `Make ${label(p)} a supervisor?`,
                    p.supervisor
                      ? 'They can no longer manage cloud accounts, people, roles or limits, and they stop being Administrator on every cloud account. They keep the roles given to them by name; credentials their agents hold beyond those are revoked.'
                      : 'They can add cloud accounts, add and suspend people, change everyone\'s roles and the platform limits. They also become Administrator on every cloud account, so their agents can ask for full access there.',
                    p.supervisor ? 'Remove supervisor' : 'Make supervisor',
                    async () => { await api.updatePerson(p.id, { supervisor: !p.supervisor }); toast(p.supervisor ? 'Supervisor removed' : 'Now a supervisor') }, !p.supervisor)}>
                    {p.supervisor ? 'Remove supervisor' : 'Make supervisor'}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {confirmDialog}
      {creating && <CreatePerson onClose={() => setCreating(false)} onCreated={(c) => { setCreating(false); setIssued(c); people.reload() }} />}
      {issued && (
        <Modal title={`Setup code for ${issued.person.username}`} onClose={() => setIssued(null)} closable={false}>
          <p>Give this code to {issued.person.display_name || issued.person.username} in person or through a channel only they read. They open this console, choose <b>Set up your account</b>, pick a password and add an authenticator app.</p>
          <Secret label="Setup code" value={issued.setup_code} />
          <p className="muted small">Shown once. Valid until {when(issued.setup_expires_at)}. Whoever uses it first sets the password, and the record shows you issued it.</p>
          <div className="row-actions"><Button kind="primary" onClick={() => setIssued(null)}>I have given it to them</Button></div>
        </Modal>
      )}
    </>
  )
}

function CreatePerson({ onClose, onCreated }: { onClose: () => void; onCreated: (c: PersonWithSetupCode) => void }) {
  const [username, setUsername] = useState('')
  const [display, setDisplay] = useState('')
  const [supervisor, setSupervisor] = useState(false)
  const action = useAction()
  return (
    <Modal title="Add a person" onClose={onClose}>
      <Field label="Username" value={username} onChange={(v) => setUsername(v.toLowerCase())} autoFocus
        hint="Lowercase letters, digits, dot, dash or underscore." />
      <Field label="Name shown in the console" value={display} onChange={setDisplay} />
      <label className="check"><input type="checkbox" checked={supervisor} onChange={(e) => setSupervisor(e.target.checked)} /> Supervisor (manages the platform and is Administrator on every cloud account)</label>
      <ErrorNote error={action.error} />
      <div className="row-actions">
        <Button onClick={onClose}>Cancel</Button>
        <Button kind="primary" busy={action.busy} disabled={!username} onClick={() => action.run(async () => onCreated(await api.createPerson(username, display, supervisor)))}>Add person</Button>
      </div>
    </Modal>
  )
}
