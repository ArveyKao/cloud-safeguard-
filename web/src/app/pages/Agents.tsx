import { useState } from 'react'
import { api } from '../api'
import type { Agent } from '../types'
import { Badge, Button, Card, Empty, ErrorNote, Modal, PageHead, ago, useAction, useLoad, useToast } from '../ui'

export function AgentsPage() {
  const agents = useLoad(() => api.myAgents(), [], 15000)
  const [connect, setConnect] = useState(false)
  const [tab, setTab] = useState<'mcp' | 'cli'>('mcp')
  const [revoking, setRevoking] = useState<Agent | null>(null)
  const origin = window.location.origin
  const list = (agents.data?.items ?? []).filter((a) => a.status !== 'revoked')

  return (
    <>
      <PageHead title="Your agents" lead="Every agent belongs to you and inherits your role on each cloud account."
        actions={<Button kind="primary" onClick={() => setConnect(!connect)}>+ Connect an agent</Button>} />
      {connect && (
        <Card title="Connect an agent in two steps">
          <div className="tabs" role="tablist">
            <button role="tab" aria-selected={tab === 'mcp'} onClick={() => setTab('mcp')}>MCP (Claude, Cursor…)</button>
            <button role="tab" aria-selected={tab === 'cli'} onClick={() => setTab('cli')}>Command line</button>
          </div>
          <ol className="steps">
            <li>On the machine where the agent runs, sign it in:
              <pre>{`csg login --server ${origin} --name my-agent`}</pre>
              It shows a short code and a link. Open the link here and approve; no token to copy.
            </li>
            {tab === 'mcp' ? (
              <li>Add Cloud Safeguard to the agent's MCP servers:
                <pre>{`"cloud-safeguard": { "command": "csg", "args": ["mcp"] }`}</pre>
                The agent gets list_accounts, request_access, check_status, get_credential and revoke.
              </li>
            ) : (
              <li>Run a cloud command with short-lived access:
                <pre>{`csg accounts\ncsg exec --account <ID> --resource ecs --permission read --ttl 15m -- aliyun ecs DescribeInstances`}</pre>
              </li>
            )}
          </ol>
        </Card>
      )}
      <ErrorNote error={agents.error} />
      <Card>
        {list.length === 0 ? <Empty>No agents yet.</Empty> : (
          <table className="table">
            <thead><tr><th>Agent</th><th>Status</th><th>Last active</th><th>Signed in</th><th /></tr></thead>
            <tbody>
              {list.map((a) => (
                <tr key={a.id}>
                  <td><b>{a.name}</b>{a.description && <div className="muted small">{a.description}</div>}</td>
                  <td>{a.status === 'active' ? <Badge tone="green">active</Badge> : <Badge tone="amber">{a.status}</Badge>}</td>
                  <td className="muted">{ago(a.last_seen_at)}</td>
                  <td className="muted">{ago(a.created_at)}</td>
                  <td className="right"><Button kind="link" onClick={() => setRevoking(a)}>Revoke</Button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {revoking && <RevokeAgent agent={revoking} onClose={() => setRevoking(null)} onDone={() => { setRevoking(null); agents.reload() }} />}
    </>
  )
}

function RevokeAgent({ agent, onClose, onDone }: { agent: Agent; onClose: () => void; onDone: () => void }) {
  const action = useAction()
  const toast = useToast()
  return (
    <Modal title={`Revoke ${agent.name}?`} onClose={onClose}>
      <p>Its token stops working at once and every credential it holds is revoked. To use it again, sign it in again with csg login.</p>
      <ErrorNote error={action.error} />
      <div className="row-actions">
        <Button onClick={onClose}>Cancel</Button>
        <Button kind="danger" busy={action.busy} onClick={() => action.run(async () => { await api.revokeAgent(agent.id); toast(`${agent.name} revoked`); onDone() })}>Revoke agent</Button>
      </div>
    </Modal>
  )
}
