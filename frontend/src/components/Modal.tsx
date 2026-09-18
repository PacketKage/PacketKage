import { X } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { useT } from '../i18n/LocaleContext'

/** Shared modal shell: backdrop, Escape to close, stopPropagation, focus trap. */
export function Modal({
  title,
  subtitle,
  onClose,
  children,
  wide,
}: {
  title: React.ReactNode
  subtitle?: React.ReactNode
  onClose: () => void
  children: React.ReactNode
  wide?: boolean
}) {
  const panelRef = useRef<HTMLDivElement>(null)
  // keep the latest onClose in a ref so the keydown listener below doesn't
  // re-attach (and re-steal focus) every time a parent re-render passes a
  // fresh inline arrow — e.g. while a background query polls
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose
  const t = useT()

  // focus-in on mount only; restore focus on unmount
  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null
    const panel = panelRef.current
    if (panel) {
      const focusables = getFocusable(panel)
      ;(focusables[0] ?? panel).focus()
    }
    return () => {
      previouslyFocused?.focus?.()
    }
  }, [])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onCloseRef.current()
        return
      }
      // focus trap: Tab cycles within the dialog
      if (e.key === 'Tab' && panelRef.current) {
        const focusables = getFocusable(panelRef.current)
        if (!focusables.length) return
        const first = focusables[0]
        const last = focusables[focusables.length - 1]
        const active = document.activeElement
        if (e.shiftKey && (active === first || !panelRef.current.contains(active))) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && active === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
    }
  }, [])

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-8 backdrop-blur-sm modal-backdrop"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
    >
      <div
        ref={panelRef}
        tabIndex={-1}
        className={`modal-enter max-h-[85vh] w-full ${
          wide ? 'max-w-4xl' : 'max-w-2xl'
        } overflow-hidden rounded-2xl border border-border-strong bg-surface shadow-2xl shadow-black/30 focus:outline-none`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div>
            <div className="font-medium text-fg">{title}</div>
            {subtitle && <div className="mt-0.5 text-xs text-fg-subtle">{subtitle}</div>}
          </div>
          <button onClick={onClose} aria-label={t('modal.close')} className="text-fg-subtle hover:text-fg-muted">
            <X size={18} aria-hidden />
          </button>
        </div>
        <div className="max-h-[70vh] overflow-y-auto">{children}</div>
      </div>
    </div>
  )
}

function getFocusable(root: HTMLElement): HTMLElement[] {
  const sel = 'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'
  return Array.from(root.querySelectorAll<HTMLElement>(sel)).filter(
    // jsdom has no layout — offsetParent is always null there; treat
    // elements without explicit display:none as focusable.
    (el) => el.offsetParent !== null || !el.hidden,
  )
}
