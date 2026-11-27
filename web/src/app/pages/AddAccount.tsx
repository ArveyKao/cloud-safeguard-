import { useState } from 'react'
import { api } from '../api'
import type { Provider } from '../types'
import type { TestResult } from '../api'
import { navigate } from '../router'
import { Button, Card, ErrorNote, Field, useAction } from '../ui'
import {
  BROKER_USER, ROLE_NAME, awsBrokerPolicy, awsRoleArn, awsRolePermissions, awsTrustPolicy, brokerPolicy, roleArn, rolePermissions,
  trustPolicy,
} from '../rolePolicy'

type Cloud = 'aliyun' | 'aws'

/** What differs between clouds in the three steps. */
const CLOUDS: Record<Cloud, {
  label: string; idPattern: RegExp; idHint: string; region: string; iam: string; consoleUrl: string; consoleName: string
  arn: (id: string) => string; broker: (id: string) => string; trust: (id: string) => string; permissions: () => string
  denyNote: string
}> = {
  aliyun: {
    label: 'Alibaba Cloud', idPattern: /^[0-9]{6,32}$/, idHint: 'Shown at the top right of the Alibaba Cloud console (the numeric UID).',
    region: 'cn-hangzhou', iam: 'RAM', consoleUrl: 'https://ram.console.aliyun.com/roles', consoleName: 'the RAM console',
    arn: roleArn, broker: brokerPolicy, trust: trustPolicy, permissions: rolePermissions,
    denyNote: 'The Deny block means no agent can ever manage users, roles or keys in this account, even with full access. Cloud Safeguard adds the same deny to every credential it issues.',
  },
  aws: {
    label: 'AWS', idPattern: /^[0-9]{12}$/, idHint: 'The 12-digit account ID, shown in the account menu at the top right of the AWS console.',
    region: 'us-east-1', iam: 'IAM', consoleUrl: 'https://console.aws.amazon.com/iam/home#/roles', consoleName: 'the IAM console',
    arn: awsRoleArn, broker: awsBrokerPolicy, trust: awsTrustPolicy, permissions: awsRolePermissions,
    denyNote: 'The Deny block means no agent can ever use IAM or the organization, or assume another role, even with full access. Cloud Safeguard adds a deny like it to every credential it issues. Do not attach AdministratorAccess or PowerUserAccess instead.',
  },
}

/** A policy to copy into the RAM console. */
function Policy({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="code-block">
      <pre>{text}</pre>
      <Button onClick={async () => { try { await navigator.clipboard.writeText(text); setCopied(true) } catch { /* ignore */ } }}>{copied ? 'Copied' : 'Copy'}</Button>
    </div>
  )
}

/** Three steps for a supervisor: which account, the RAM role, the key. */
export function AddAccountPage() {
  const [step, setStep] = useState(1)
  const [cloud, setCloud] = useState<Cloud>('aliyun')
  const [accountId, setAccountId] = useState('')
  const [name, setName] = useState('')
  const [region, setRegion] = useState('cn-hangzhou')
  const [keyId, setKeyId] = useState('')
  const [secret, setSecret] = useState('')
  const [created, setCreated] = useState<Provider | null>(null)
  const [test, setTest] = useState<TestResult | null>(null)
  const action = useAction()
  const c = CLOUDS[cloud]
  const validId = c.idPattern.test(accountId.trim())
  const chooseCloud = (next: Cloud) => { setCloud(next); setRegion(CLOUDS[next].region) }

  const id = accountId.trim()

  async function connect() {
    await action.run(async () => {
      const p = await api.createAccount({
        name: name.trim(), type: cloud, mode: 'sts', region: region.trim(),
        role_arn: c.arn(id), access_key_id: keyId.trim(), access_key_secret: secret,
      })
      setSecret('')
      setCreated(p)
      setTest(await api.testAccount(p.id).catch((e) => ({ ok: false, message: String(e?.message ?? e), tested_at: '' })))
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
              <button role="radio" aria-checked={cloud === 'aliyun'} onClick={() => chooseCloud('aliyun')}>Alibaba Cloud</button>
              <button role="radio" aria-checked={cloud === 'aws'} onClick={() => chooseCloud('aws')}>AWS</button>
              <button role="radio" aria-checked="false" disabled>GCP · soon</button>
            </div>
            <Field label="Account ID" value={accountId} onChange={(v) => setAccountId(v.replace(/\D/g, ''))} inputMode="numeric"
              hint={c.idHint} autoFocus />
            <Field label="Name" value={name} onChange={setName} placeholder="Production" />
            <Field label="Region" value={region} onChange={setRegion} />
            <div className="row-actions"><Button kind="primary" disabled={!validId || !name.trim() || !region.trim()} onClick={() => setStep(2)}>Continue</Button></div>
          </>
        )}
        {step === 2 && (
          <>
            <h1>Create a user and a role for Cloud Safeguard</h1>
            <p className="muted">Three things in {c.consoleName} of account {id}. Use these names, so the policies below fit as they are.</p>
            <h3>1. An {c.iam} user named <span className="mono">{BROKER_USER}</span></h3>
            <p className="muted small">Create an access key for it and keep the secret for the next step. Give the user only this policy: it can do nothing but assume the role.</p>
            <Policy text={c.broker(id)} />
            <h3>2. An {c.iam} role named <span className="mono">{ROLE_NAME}</span></h3>
            <p className="muted small">Trusted by that user only. This is the role's trust policy.</p>
            <Policy text={c.trust(id)} />
            <h3>3. The role's permissions</h3>
            <p className="muted small">The outer limit of what any agent can get in this account. Remove what you never want an agent to do; do not add wildcards per service.</p>
            <Policy text={c.permissions()} />
            <p className="note note-ok">{c.denyNote}</p>
            <a href={c.consoleUrl} target="_blank" rel="noreferrer noopener">Open {c.consoleName} in a new tab ↗</a>
            <div className="row-actions"><Button onClick={() => setStep(1)}>Back</Button><Button kind="primary" onClick={() => setStep(3)}>I created them</Button></div>
          </>
        )}
        {step === 3 && !created && (
          <>
            <h1>Connect</h1>
            <p className="muted">Paste the access key of <span className="mono">{BROKER_USER}</span>. It is encrypted at once and never shown again.</p>
            <Field label={cloud === 'aws' ? 'Access key ID' : 'AccessKey ID'} value={keyId} onChange={setKeyId} autoComplete="off" />
            <Field label={cloud === 'aws' ? 'Secret access key' : 'AccessKey secret'} value={secret} onChange={setSecret} type="password" autoComplete="off" />
            <ErrorNote error={action.error} />
            <div className="row-actions"><Button onClick={() => setStep(2)}>Back</Button>
              <Button kind="primary" busy={action.busy} disabled={!keyId.trim() || !secret} onClick={connect}>Connect and test</Button></div>
          </>
        )}
        {created && (
          <>
            <h1>{created.name} is connected</h1>
            <ul className="checklist">
              <li data-ok={test?.ok === true}>{test?.ok ? 'The access key is valid and can assume the role'
                : `The connection test did not pass yet${test?.message ? `: ${test.message}` : ''}. Check the role and key, then test again from Cloud accounts.`}</li>
              {test?.warning && <li data-ok="false">{test.warning}</li>}
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
