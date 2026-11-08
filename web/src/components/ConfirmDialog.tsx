/** Confirmation dialog for destructive or security-relevant actions. */
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { ApiError } from '../api/client'
import { Button } from './primitives'
import { Modal } from './overlays'
import { IconAlert } from './icons'

interface ConfirmDialogProps {
  open: boolean
  title: string
  children: ReactNode
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
  /** Called with the trimmed reason input (empty string when no input shown). */
  onConfirm: (reason: string) => Promise<void> | void
  onCancel: () => void
  reasonLabel?: string
  reasonRequired?: boolean
  reasonPlaceholder?: string
  /** When false, show a plain confirmation without a reason field. */
  requireReason?: boolean
  busy?: boolean
}

export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  danger = true,
  onConfirm,
  onCancel,
  reasonLabel = 'Reason',
  reasonRequired = false,
  reasonPlaceholder = 'Optional context for the audit trail',
  requireReason = false,
  busy = false,
}: ConfirmDialogProps) {
  const [reason, setReason] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (open) {
      setReason('')
      setError(null)
    }
  }, [open])

  async function handleConfirm() {
    if (reasonRequired && reason.trim() === '') {
      setError('A reason is required for this action.')
      return
    }
    setError(null)
    setSubmitting(true)
    try {
      await onConfirm(reason.trim())
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'The action could not be completed.')
    } finally {
      setSubmitting(false)
    }
  }

  function handleCancel() {
    setReason('')
    setError(null)
    onCancel()
  }

  return (
    <Modal
      open={open}
      onClose={handleCancel}
      title={title}
      size="sm"
      footer={
        <>
          <Button variant="ghost" onClick={handleCancel} disabled={submitting || busy}>
            {cancelLabel}
          </Button>
          <Button
            variant={danger ? 'danger-solid' : 'primary'}
            onClick={() => void handleConfirm()}
            loading={submitting || busy}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <div className="stack" style={{ gap: 14 }}>
        <div className="row" style={{ alignItems: 'flex-start', gap: 10 }}>
          <span
            className="icon-tint icon-tint--rose"
            style={{ width: 30, height: 30, borderRadius: 9 }}
            aria-hidden="true"
          >
            <IconAlert size={15} />
          </span>
          <div style={{ fontSize: 13, lineHeight: 1.55, color: 'var(--text-secondary)' }}>
            {children}
          </div>
        </div>
        {requireReason && (
          <div className="field">
            <label className="field__label" htmlFor="confirm-reason">
              {reasonLabel}
              {reasonRequired && (
                <span className="req" aria-hidden="true">
                  required
                </span>
              )}
            </label>
            <textarea
              id="confirm-reason"
              className="textarea"
              style={{ minHeight: 66 }}
              value={reason}
              placeholder={reasonPlaceholder}
              onChange={(event) => setReason(event.target.value)}
              aria-invalid={error ? 'true' : undefined}
              maxLength={500}
            />
            {error && <div className="field__error">{error}</div>}
          </div>
        )}
        {!requireReason && error && <div className="field__error">{error}</div>}
      </div>
    </Modal>
  )
}
