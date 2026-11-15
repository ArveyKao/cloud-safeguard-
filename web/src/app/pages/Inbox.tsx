import { useState } from 'react'
import { api } from '../api'
import type { AccessRequest, Person } from '../types'
import { navigate } from '../router'
import {
  Badge, Button, Card, Empty, ErrorNote, Modal, PageHead, ago, duration, permissionTone, useAction, useLoad, useToast, when,
} from '../ui'

/** Requests from the person's own agents that wait for a decision. */
export function InboxPage({ person, onChange }: { person: Person; onChange: () => void }) {
  const pending = useLoad(() => api.myRequests('pending'), [], 5000)
  const recent = useLoad(() => api.myRequests(), [], 15000)
  const [denying, setDenying] = useState<AccessRequest | null>(null)
  const toast = useToast()
  const action = useAction()

  const refresh = () => { pending.reload(); recent.reload(); onChange() }
  const approve = (r: AccessRequest) => action.run(async () => {
    await api.approveRequest(r.id)
    toast(`Approved: ${r.agent_name} has ${r.permission} on ${r.resource} for ${duration(r.ttl_seconds)}`)
    refresh()
  })

  const items = pending.data?.items ?? []
  const decided = (recent.data?.items ?? []).filter((r) => r.status !== 'pending').slice(0, 8)
  const issued = person.setup_issued
  // Only a code issued by another person is worth a warning; csg init and
  // local recovery are run by whoever holds the server.
  const fresh = issued && issued.by_id !== 'system' && issued.by_id !== person.id &&
    Date.now() - new Date(issued.at).getTime() < 7 * 86400_000

  return (
    <>
      <PageHead title="Inbox" lead="Your agents' requests that wait for you. What your approval mode allows was issued automatically." />
      {fresh && issued && (
        <p className="note note-info">
          Your account was {issued.kind === 'created' ? 'created' : 'reset'} by <b>{issued.by_name}</b> on {when(issued.at)}.
          If you did not choose your own password, tell another supervisor.
        </p>
      )}
      <ErrorNote error={pending.error ?? action.error} />
      {items.length === 0 ? (
        <Card><Empty>Nothing waits for you. <a href="/agents" onClick={(e) => { e.preventDefault(); navigate('/agents') }}>Connect an agent</a> to get started.</Empty></Card>
      ) : items.map((r) => (
        <Card key={r.id}>
          <div className="request">
            <div className="request-head">
              <b>{r.agent_name}</b>
              <span className="muted">wants</span>
              <Badge tone={permissionTone(r.permission)}>{r.permission}</Badge>
              <span className="muted">access</span>
              <span className="spacer" />
              <span className="muted small">{ago(r.created_at)}</span>
            </div>
            {r.reason && <p className="reason">“{r.reason}”</p>}
            <dl className="facts">
              <div><dt>Cloud account</dt><dd>{r.cloud_account_name} <span className="mono muted">{r.cloud_account_id}</span></dd></div>
              <div><dt>Resource</dt><dd>{r.resource.toUpperCase()} · {r.resource_name ? <span className="mono">{r.resource_name}</span> : 'all'}</dd></div>
              <div><dt>For</dt><dd>{duration(r.ttl_seconds)}</dd></div>
            </dl>
            <div className="row-actions">
              <Button onClick={() => setDenying(r)}>Deny</Button>
              <Button kind="primary" busy={action.busy} onClick={() => approve(r)}>Approve</Button>
            </div>
          </div>
        </Card>
      ))}

      {decided.length > 0 && (
        <Card title="Recent">
          <table className="table">
            <tbody>
              {decided.map((r) => (
                <tr key={r.id}>
                  <td><b>{r.agent_name}</b></td>
                  <td><Badge tone={permissionTone(r.permission)}>{r.permission}</Badge> {r.resource}{r.resource_name ? ` · ${r.resource_name}` : ''}</td>
                  <td>{statusText(r)}</td>
                  <td className="muted small">{ago(r.created_at)}</td>
                  <td className="right">
                    {r.status === 'active' && (
                      <Button kind="link" onClick={() => action.run(async () => { await api.revokeRequest(r.id); toast('Revoked'); refresh() })}>Revoke</Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {denying && <DenyDialog request={denying} onClose={() => setDenying(null)} onDone={() => { setDenying(null); refresh() }} />}
    </>
  )
}

export function statusText(r: AccessRequest) {
  switch (r.status) {
    case 'active': return <span className="ok">Active · expires {ago(r.expires_at)}</span>
    case 'denied': return <span className="muted" title={r.denied_reason}>Denied</span>
    case 'revoked': return <span className="muted" title={r.revoke_reason}>Revoked</span>
    case 'expired': return <span className="muted">Expired</span>
    case 'pending': return <span className="warn">Waiting for you</span>
    default: return <span className="muted">{r.status}</span>
  }
}

function DenyDialog({ request, onClose, onDone }: { request: AccessRequest; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState('')
  const action = useAction()
  return (
    <Modal title={`Deny ${request.agent_name}'s request?`} onClose={onClose}>
      <label className="field">
        <span>Reason (optional, shown to the agent)</span>
        <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} autoFocus />
      </label>
      <ErrorNote error={action.error} />
      <div className="row-actions">
        <Button onClick={onClose}>Cancel</Button>
        <Button kind="danger" busy={action.busy} onClick={() => action.run(async () => { await api.denyRequest(request.id, reason); onDone() })}>Deny</Button>
      </div>
    </Modal>
  )
}
