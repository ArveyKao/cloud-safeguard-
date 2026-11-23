import { useState } from 'react'
import type { FormEvent } from 'react'
import { api } from '../api'
import type { SessionInfo, SetupBeginResult } from '../types'
import { navigate } from '../router'
import { Button, ErrorNote, Field, QRCode, Secret, useAction } from '../ui'
import { Logo } from '../Shell'

/** First sign-in: setup code, a password, then an authenticator app. */
export function SetupPage({ onSignedIn }: { onSignedIn: (s: SessionInfo) => void }) {
  const [setupCode, setSetupCode] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [begun, setBegun] = useState<SetupBeginResult | null>(null)
  const [totp, setTotp] = useState('')
  const action = useAction()

  async function begin(e: FormEvent) {
    e.preventDefault()
    if (password !== confirm) {
      action.setError(new Error('The two passwords are different.'))
      return
    }
    await action.run(async () => setBegun(await api.setupBegin(setupCode.trim(), password)))
  }

  async function finish(e: FormEvent) {
    e.preventDefault()
    await action.run(async () => onSignedIn(await api.setupFinish(setupCode.trim(), totp)))
  }

  return (
    <div className="auth-page">
      {!begun ? (
        <form className="auth-card" onSubmit={begin}>
          <Logo />
          <h1>Set up your account</h1>
          <p className="muted">Step 1 of 2. Use the setup code a supervisor gave you, then choose a password only you know.</p>
          <Field label="Setup code" value={setupCode} onChange={setSetupCode} autoFocus autoComplete="off" />
          <Field label="New password" value={password} onChange={setPassword} type="password" autoComplete="new-password"
            hint="At least 12 characters. A sentence of a few words works well." />
          <Field label="Repeat the password" value={confirm} onChange={setConfirm} type="password" autoComplete="new-password" />
          <ErrorNote error={action.error} />
          <Button kind="primary" type="submit" busy={action.busy} disabled={!setupCode || password.length < 12 || !confirm}>Continue</Button>
          <p className="auth-foot"><a href="/login" onClick={(e) => { e.preventDefault(); navigate('/login') }}>Back to sign in</a></p>
        </form>
      ) : (
        <form className="auth-card" onSubmit={finish}>
          <Logo />
          <h1>Add an authenticator</h1>
          <p className="muted">Step 2 of 2. Scan this with an authenticator app (Google Authenticator, 1Password, Authy…), then enter the 6-digit code it shows.</p>
          <QRCode text={begun.otpauth_url} />
          <details className="manual-key">
            <summary>Can't scan? Enter the key by hand</summary>
            <Secret label="Key" value={begun.totp_secret} />
          </details>
          <Field label="6-digit code" value={totp} onChange={(v) => setTotp(v.replace(/\D/g, '').slice(0, 6))}
            inputMode="numeric" autoComplete="one-time-code" autoFocus />
          <ErrorNote error={action.error} />
          <Button kind="primary" type="submit" busy={action.busy} disabled={totp.length !== 6}>Finish and sign in</Button>
        </form>
      )}
    </div>
  )
}
