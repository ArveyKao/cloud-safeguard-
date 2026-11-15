import { useState } from 'react'
import type { FormEvent } from 'react'
import { api } from '../api'
import type { SessionInfo } from '../types'
import { navigate } from '../router'
import { Button, ErrorNote, Field, useAction } from '../ui'
import { Logo } from '../Shell'

export function LoginPage({ onSignedIn }: { onSignedIn: (s: SessionInfo) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const action = useAction()

  async function submit(e: FormEvent) {
    e.preventDefault()
    await action.run(async () => onSignedIn(await api.login(username, password, code)))
  }

  return (
    <div className="auth-page">
      <form className="auth-card" onSubmit={submit}>
        <Logo />
        <h1>Sign in</h1>
        <Field label="Username" value={username} onChange={setUsername} autoComplete="username" autoFocus />
        <Field label="Password" value={password} onChange={setPassword} type="password" autoComplete="current-password" />
        <Field label="Code from your authenticator app" value={code} onChange={(v) => setCode(v.replace(/\D/g, '').slice(0, 6))}
          inputMode="numeric" autoComplete="one-time-code" placeholder="123456" />
        <ErrorNote error={action.error} />
        <Button kind="primary" type="submit" busy={action.busy} disabled={!username || !password || code.length !== 6}>Sign in</Button>
        <p className="auth-foot">
          First time here? <a href="/setup" onClick={(e) => { e.preventDefault(); navigate('/setup') }}>Set up your account</a> with the code a supervisor gave you.
        </p>
      </form>
    </div>
  )
}
