/** Accessible modal + drawer primitives: portal, ESC, focus trap, scroll lock. */
import { useEffect, useRef } from 'react'
import type { ReactNode, RefObject } from 'react'
import { createPortal } from 'react-dom'
import { IconX } from './icons'
import { cx } from '../lib/format'

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'

interface DialogBehaviorOptions {
  open: boolean
  onClose: () => void
  dismissible: boolean
  dialogRef: RefObject<HTMLElement>
}

function useDialogBehavior({ open, onClose, dismissible, dialogRef }: DialogBehaviorOptions) {
  const closeRef = useRef(onClose)
  closeRef.current = onClose
  const dismissibleRef = useRef(dismissible)
  dismissibleRef.current = dismissible

  useEffect(() => {
    if (!open) return
    const previousActive = document.activeElement as HTMLElement | null
    const originalOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'

    const focusTimer = window.setTimeout(() => {
      const container = dialogRef.current
      if (!container) return
      const preferred = container.querySelector<HTMLElement>('[data-autofocus]')
      const focusables = container.querySelectorAll<HTMLElement>(FOCUSABLE)
      const target = preferred ?? focusables[0] ?? container
      target.focus()
    }, 30)

    function onKeyDown(event: KeyboardEvent) {
      const container = dialogRef.current
      if (!container) return
      if (event.key === 'Escape' && dismissibleRef.current) {
        event.preventDefault()
        event.stopPropagation()
        closeRef.current()
        return
      }
      if (event.key !== 'Tab') return
      const focusables = Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (element) => element.offsetParent !== null || element === document.activeElement,
      )
      if (focusables.length === 0) {
        event.preventDefault()
        return
      }
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      if (event.shiftKey && (document.activeElement === first || document.activeElement === container)) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown, true)
    return () => {
      window.clearTimeout(focusTimer)
      document.removeEventListener('keydown', onKeyDown, true)
      document.body.style.overflow = originalOverflow
      previousActive?.focus?.()
    }
  }, [open, dialogRef])
}

/* ------------------------------------------------------------------ */
/* Modal                                                               */
/* ------------------------------------------------------------------ */

interface ModalProps {
  open: boolean
  onClose: () => void
  title: ReactNode
  subtitle?: ReactNode
  children: ReactNode
  footer?: ReactNode
  size?: 'sm' | 'md' | 'lg' | 'xl'
  dismissible?: boolean
  className?: string
  labelledBy?: string
}

export function Modal({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  size = 'md',
  dismissible = true,
  className,
  labelledBy,
}: ModalProps) {
  const dialogRef = useRef<HTMLDivElement>(null)
  useDialogBehavior({ open, onClose, dismissible, dialogRef })

  if (!open) return null
  const titleId = labelledBy ?? 'modal-title'

  return createPortal(
    <div
      className="modal-overlay"
      onMouseDown={(event) => {
        if (dismissible && event.target === event.currentTarget) onClose()
      }}
    >
      <div
        ref={dialogRef}
        className={cx('modal', size !== 'md' && `modal--${size}`, className)}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <header className="modal__header">
          <div className="modal__heading">
            <h2 className="modal__title" id={titleId}>
              {title}
            </h2>
            {subtitle && <div className="modal__subtitle">{subtitle}</div>}
          </div>
          {dismissible && (
            <button
              type="button"
              className="btn btn--icon btn--ghost modal__close"
              onClick={onClose}
              aria-label="Close dialog"
            >
              <IconX size={17} />
            </button>
          )}
        </header>
        <div className="modal__body">{children}</div>
        {footer && <footer className="modal__footer">{footer}</footer>}
      </div>
    </div>,
    document.body,
  )
}

/* ------------------------------------------------------------------ */
/* Drawer                                                              */
/* ------------------------------------------------------------------ */

interface DrawerProps {
  open: boolean
  onClose: () => void
  title: ReactNode
  subtitle?: ReactNode
  children: ReactNode
  footer?: ReactNode
  labelledBy?: string
  dismissible?: boolean
}

export function Drawer({
  open,
  onClose,
  title,
  subtitle,
  children,
  footer,
  labelledBy,
  dismissible = true,
}: DrawerProps) {
  const dialogRef = useRef<HTMLDivElement>(null)
  useDialogBehavior({ open, onClose, dismissible, dialogRef })

  if (!open) return null
  const titleId = labelledBy ?? 'drawer-title'

  return createPortal(
    <div
      className="drawer-overlay"
      onMouseDown={(event) => {
        if (dismissible && event.target === event.currentTarget) onClose()
      }}
    >
      <div
        ref={dialogRef}
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <header className="drawer__header">
          <div>
            <h2 className="drawer__title" id={titleId}>
              {title}
            </h2>
            {subtitle && <div className="drawer__subtitle">{subtitle}</div>}
          </div>
          {dismissible && (
            <button
              type="button"
              className="btn btn--icon btn--ghost"
              onClick={onClose}
              aria-label="Close panel"
            >
              <IconX size={17} />
            </button>
          )}
        </header>
        <div className="drawer__body">{children}</div>
        {footer && <footer className="drawer__footer">{footer}</footer>}
      </div>
    </div>,
    document.body,
  )
}
