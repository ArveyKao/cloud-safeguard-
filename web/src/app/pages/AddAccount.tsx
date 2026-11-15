import { useState } from 'react'
import { api } from '../api'
import type { Provider } from '../types'
import { navigate } from '../router'
import { Button, Card, ErrorNote, Field, useAction } from '../ui'

const ROLE_NAME = 'cloud-safeguard'

/** Three steps for a supervisor: which account, the RAM role, the key. */
export function AddAccountPage() {
  const [step, setStep] = useState(1)
  const [accountId, setAccountId] = useState('')
  const [name, setName] = useState('')
  const [region, setRegion] = useState('cn-hangzhou')
  const [keyId, setKeyId] = useState('')
  const [secret, setSecret] = useState('')
  const [created, setCreated] = useState<Provider | null>(null)
  const [copied, setCopied] = useState(false)
  const action = useAction()
  const validId = /^[0-9]{6,32}$/.test(accountId.trim())

  const permissions = JSON.stringify({
    Version: '1',
    Statement: [
      { Effect: 'Allow', Action: ['ecs:*', 'alidns:*', 'oss:*'], Resource: '*' },
      { Effect: 'Deny', Action: ['ram:*', 'sts:AssumeRole'], Resource: '*' },
    ],
  }, null, 2)

  async function connect() {
    await action.run(async () => {
      const p = await api.createAccount({
        name: name.trim(), type: 'aliyun', mode: 'sts', region: region.trim(),
        role_arn: `acs:ram::${accountId.trim()}:role/${ROLE_NAME}`, access_key_id: keyId.trim(), access_key_secret: secret,
      })
      setSecret('')
      setCreated(await api.testAccount(p.id).catch(() => p))
    })
  }

  return (
    <div className="wizard">
      <div className="wizard-top">
        <a href="/accounts" onClick={(e) => { e.preventDefault(); navigate('/accounts') }}>← Cloud accounts</a>
        <span className="muted">Step {created ? 3 : step} of 3</span>
      </div>
      <ol className="progress">
        {['Account', 'Role', 'Connect'].map((l, i) => <li key={l} data-done={i + 1 <= (created ? 3 : step)}>{l}</li>)}
      </ol>
      <Card>
        {step === 1 && (
          <>
            <h1>Which cloud account?</h1>
            <p className="muted">Cloud Safeguard hands out short-lived access to this account. Agents never see its keys.</p>
            <div className="segmented" role="radiogroup" aria-label="Cloud">
              <button role="radio" aria-checked="true">Alibaba Cloud</button>
              <button role="radio" aria-checked="false" disabled>AWS · soon</button>
              <button role="radio" aria-checked="false" disabled>GCP · soon</button>
            </div>
            <Field label="Account ID" value={accountId} onChange={(v) => setAccountId(v.replace(/\D/g, ''))} inputMode="numeric"
              hint="Shown at the top right of the Alibaba Cloud console (the numeric UID)." autoFocus />
            <Field label="Name" value={name} onChange={setName} placeholder="Production" />
            <Field label="Region" value={region} onChange={setRegion} />
            <div className="row-actions"><Button kind="primary" disabled={!validId || !name.trim() || !region.trim()} onClick={() => setStep(2)}>Continue</Button></div>
          </>
        )}
        {step === 2 && (
          <>
            <h1>Create a role for Cloud Safeguard</h1>
            <p className="muted">In the RAM console, create a role named <b>{ROLE_NAME}</b> that a RAM user of this account can assume, and give it this policy.</p>
            <div className="code-block">
              <pre>{permissions}</pre>
              <Button onClick={async () => { try { await navigator.clipboard.writeText(permissions); setCopied(true) } catch { /* ignore */ } }}>{copied ? 'Copied' : 'Copy'}</Button>
            </div>
            <p className="note note-ok">The Deny block means no agent can ever manage users, roles or keys in this account, even with full access. Cloud Safeguard adds the same deny to every credential it issues.</p>
            <p className="muted small">Then create a RAM user whose only permission is <span className="mono">sts:AssumeRole</span> on this role, and an AccessKey for it.</p>
            <a href="https://ram.console.aliyun.com/roles" target="_blank" rel="noreferrer noopener">Open the RAM console in a new tab ↗</a>
            <div className="row-actions"><Button onClick={() => setStep(1)}>Back</Button><Button kind="primary" onClick={() => setStep(3)}>I created the role</Button></div>
          </>
        )}
        {step === 3 && !created && (
          <>
            <h1>Connect</h1>
            <p className="muted">Paste the AccessKey of that RAM user. It is encrypted at once and never shown again.</p>
            <Field label="AccessKey ID" value={keyId} onChange={setKeyId} autoComplete="off" />
            <Field label="AccessKey secret" value={secret} onChange={setSecret} type="password" autoComplete="off" />
            <ErrorNote error={action.error} />
            <div className="row-actions"><Button onClick={() => setStep(2)}>Back</Button>
              <Button kind="primary" busy={action.busy} disabled={!keyId.trim() || !secret} onClick={connect}>Connect and test</Button></div>
          </>
        )}
        {created && (
          <>
            <h1>{created.name} is connected</h1>
            <ul className="checklist">
              <li data-ok={created.last_test_ok === true}>{created.last_test_ok ? 'The AccessKey works and can assume the role' : 'The connection test did not pass yet; check the role and key, then test again from Cloud accounts'}</li>
              <li data-ok="true">The key is stored encrypted; only a masked ID is shown</li>
              <li data-ok="true">Nobody has a role on it yet; you decide who does</li>
            </ul>
            <div className="row-actions"><Button kind="primary" onClick={() => navigate('/accounts')}>Give people a role</Button></div>
          </>
        )}
      </Card>
    </div>
  )
}
