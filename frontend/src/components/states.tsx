import { useEffect, useRef } from 'react'
import { AlertTriangle, ArrowLeft, ArrowRight } from 'lucide-react'
import { Button } from './ui'
import { useT } from '../i18n/LocaleContext'

/** Error message + retry button for a failed query. */
export function ErrorState({ message, onRetry }: { message?: string; onRetry?: () => void }) {
  const t = useT()
  return (
    <div
      className="flex items-center justify-center gap-3 rounded-xl border border-danger/30 bg-danger/5 p-12 text-center text-sm text-danger"
      role="alert"
    >
      <AlertTriangle size={16} aria-hidden />
      {message ?? t('states.error_generic')}
      {onRetry && (
        <Button size="sm" variant="secondary" onClick={onRetry}>
          {t('common.retry')}
        </Button>
      )}
    </div>
  )
}

/** Standard empty-state box. */
export function EmptyState({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/50 p-12 text-center text-sm text-fg-muted">
      {children}
    </div>
  )
}

/** Server-side pagination controls (Prev/Next + page x of y). */
export function Pagination({
  offset,
  limit,
  total,
  onPageChange,
}: {
  offset: number
  limit: number
  total: number
  onPageChange: (offset: number) => void
}) {
  const page = Math.floor(offset / limit) + 1
  const pageCount = Math.max(1, Math.ceil(total / limit))
  const canPrev = offset > 0
  const canNext = offset + limit < total
  const topRef = useRef<HTMLDivElement>(null)
  const t = useT()

  useEffect(() => {
    // follow page changes into view (tables live above the controls)
    topRef.current?.scrollIntoView({ block: 'nearest' })
  }, [offset])

  return (
    <div
      ref={topRef}
      className="flex items-center justify-between border-t border-border px-4 py-2.5 text-xs text-fg-muted"
    >
      <span className="tabular-nums">
        {t('pagination.records', { count: total.toLocaleString(), page, total: pageCount })}
      </span>
      <div className="flex gap-2">
        <Button
          size="sm"
          variant="ghost"
          disabled={!canPrev}
          onClick={() => onPageChange(Math.max(0, offset - limit))}
        >
          <ArrowLeft size={14} aria-hidden /> {t('pagination.prev')}
        </Button>
        <Button size="sm" variant="ghost" disabled={!canNext} onClick={() => onPageChange(offset + limit)}>
          {t('pagination.next')} <ArrowRight size={14} aria-hidden />
        </Button>
      </div>
    </div>
  )
}
