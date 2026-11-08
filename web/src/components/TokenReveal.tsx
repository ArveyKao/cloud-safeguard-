/**
 * One-time agent token reveal. The token is displayed exactly once (create or
 * rotate) and is never persisted client-side beyond this dialog.
 */
import { useEffect, useState } from 'react'
import { Modal } from './overlays'
import { Button, CopyButton } from './primitives'
import { IconAlert, IconKey, IconShield } from './icons'

interface TokenRevealModalProps {
  open: boolean
  title: string
  subtitle: string
  agentName: string
  agentId: string
  token: string
  onDone: () => void
}

export function TokenRevealModal({
  open,
  title,
  subtitle,
  agentName,
  agentId,
  token,
  onDone,
}: TokenRevealModalProps) {
  const [acknowledged, setAcknowledged] = useState(false)

  useEffect(() => {
    if (open) setAcknowledged(false)
  }, [open])

  return (
    <Modal
      open={open}
      onClose={() => {
        if (acknowledged) onDone()
      }}
      dismissible={false}
      title={title}
      subtitle={subtitle}
      footer={
        <>
          <span className="muted" style={{ fontSize: 11.5, marginRight: 'auto' }}>
            This dialog cannot be reopened.
          </span>
          <Button
            variant="primary"
            disabled={!acknowledged}
            icon={<IconShield size={15} />}
            onClick={onDone}
          >
            I have stored the token
          </Button>
        </>
      }
    >
      <div className="stack" style={{ gap: 16 }}>
        <div className="banner banner--error">
          <IconAlert size={16} />
          <div>
            <div className="banner__title">Save this token now — it will not be shown again</div>
            Cloud Safeguard stores only a hash of the token. If you lose it, rotate the token to
            issue a new one; the current token stops working immediately.
          </div>
        </div>

        <div className="meta-list">
          <div className="meta-item">
            <div className="meta-item__label">Agent</div>
            <div className="meta-item__value">{agentName}</div>
          </div>
          <div className="meta-item">
            <div className="meta-item__label">Agent ID</div>
            <div className="meta-item__value mono">{agentId}</div>
          </div>
        </div>

        <div>
          <div className="row-between" style={{ marginBottom: 7 }}>
            <span className="field__label" style={{ margin: 0 }}>
              <IconKey size={13} /> Bearer token
            </span>
            <CopyButton value={token} label="Copy token" />
          </div>
          <pre
            className="vault-fingerprint"
            style={{
              color: 'var(--text)',
              fontFamily: 'var(--font-mono)',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
              maxHeight: 120,
              overflow: 'auto',
              background: 'var(--panel-inset)',
            }}
            aria-label="Agent bearer token"
          >
            {token}
          </pre>
          <div className="field__hint" style={{ marginTop: 7 }}>
            Store it in the agent&apos;s secret manager or environment — never in shell history,
            transcripts or source control. The console does not keep a copy.
          </div>
        </div>

        <label className="checkbox" style={{ borderColor: 'var(--line-strong)' }}>
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />
          <span className="checkbox__text">
            <strong>I have stored this token securely</strong>
            <span>I understand it cannot be recovered from the console later.</span>
          </span>
        </label>
      </div>
    </Modal>
  )
}
