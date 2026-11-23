import { api } from '../api'
import type { Person } from '../types'
import { Badge, Card, Empty, ErrorNote, PageHead, ago, permissionTone, useLoad } from '../ui'
import { statusText } from './Inbox'

export function ActivityPage({ person }: { person: Person }) {
  return person.supervisor ? <AuditLog /> : <MyHistory />
}

function MyHistory() {
  const requests = useLoad(() => api.myRequests(), [], 15000)
  const items = requests.data?.items ?? []
  return (
    <>
      <PageHead title="Activity" lead="Everything your agents asked for, newest first." />
      <ErrorNote error={requests.error} />
      <Card>
        {items.length === 0 ? <Empty>No requests yet.</Empty> : (
          <table className="table">
            <thead><tr><th>When</th><th>Agent</th><th>Access</th><th>Account</th><th>Outcome</th></tr></thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id}>
                  <td className="muted">{ago(r.created_at)}</td>
                  <td><b>{r.agent_name}</b></td>
                  <td><Badge tone={permissionTone(r.permission)}>{r.permission}</Badge> {r.resource}{r.resource_name ? ` · ${r.resource_name}` : ''}</td>
                  <td>{r.cloud_account_name}</td>
                  <td>{statusText(r)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  )
}

const tone = (s: string) => (s === 'critical' ? 'red' : s === 'warning' ? 'amber' : 'grey') as 'red' | 'amber' | 'grey'

function AuditLog() {
  const audit = useLoad(() => api.audit(150), [], 15000)
  const verify = useLoad(() => api.verifyAudit(), [])
  const items = audit.data?.items ?? []
  return (
    <>
      <PageHead title="Activity" lead="The tamper-evident audit log of the whole platform, newest first."
        actions={verify.data && (verify.data.ok
          ? <Badge tone="green">chain verified · {verify.data.events} events</Badge>
          : <Badge tone="red">chain broken: {verify.data.message}</Badge>)} />
      <ErrorNote error={audit.error} />
      <Card>
        {items.length === 0 ? <Empty>No events yet.</Empty> : (
          <table className="table">
            <thead><tr><th>When</th><th>Who</th><th>What</th><th>On</th><th /></tr></thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id}>
                  <td className="muted" title={e.time}>{ago(e.time)}</td>
                  <td>{e.actor_name} <span className="muted small">{e.actor_type}</span></td>
                  <td className="mono small">{e.action}{e.status !== 'ok' && <span className="muted"> · {e.status}</span>}</td>
                  <td className="mono muted small">{e.target_type}{e.target_id ? ` ${e.target_id.slice(0, 16)}` : ''}</td>
                  <td>{e.severity !== 'info' && <Badge tone={tone(e.severity)}>{e.severity}</Badge>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  )
}
