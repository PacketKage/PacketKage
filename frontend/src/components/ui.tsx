import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Loader2 } from 'lucide-react'
import { useT } from '../i18n/LocaleContext'
import { currentLocale, type Locale } from '../i18n/locale'

/* ------------------------------------------------------------------ */
/* Formatters — locale-aware; every call site passes a Locale when it   */
/* already has one (pages/components), otherwise the module-level       */
/* current locale is applied.                                          */
/* ------------------------------------------------------------------ */

const UNIT_NAMES: Record<Locale, string[]> = {
  en: ['B', 'KB', 'MB', 'GB'],
  fr: ['o', 'Ko', 'Mo', 'Go'],
}

export function formatBytes(bytes: number, locale?: Locale): string {
  const loc = locale ?? currentLocale()
  if (!bytes) return loc === 'fr' ? '0 o' : '0 B'
  const units = UNIT_NAMES[loc]
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / 1024 ** i).toFixed(1)} ${units[i]}`
}

export function formatTime(ts: number | null, locale?: Locale): string {
  if (ts == null) return '—'
  return new Date(ts * 1000).toLocaleTimeString(locale ?? currentLocale())
}

export function formatDuration(start: number | null, end: number | null, locale?: Locale): string {
  if (start == null || end == null) return '—'
  const s = Math.max(0, end - start)
  if (locale === 'fr') {
    return s < 60 ? `${s.toFixed(1)}s` : `${Math.floor(s / 60)} min ${Math.round(s % 60)}s`
  }
  return s < 60 ? `${s.toFixed(1)}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`
}

/* ------------------------------------------------------------------ */
/* Button                                                              */
/* ------------------------------------------------------------------ */

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'
type ButtonSize = 'sm' | 'md' | 'lg'

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-accent-fg hover:brightness-110 ring-1 ring-accent-ring',
  secondary: 'bg-surface-2 text-fg hover:bg-surface-3 ring-1 ring-border',
  ghost: 'text-fg-muted hover:text-fg hover:bg-surface-2',
  danger: 'bg-danger/10 text-danger hover:bg-danger/20 ring-1 ring-danger/30',
}

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-xs gap-1.5',
  md: 'h-9 px-4 text-sm gap-2',
  lg: 'h-11 px-5 text-sm gap-2',
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  loading?: boolean
  children?: ReactNode
}

export function Button({
  variant = 'secondary',
  size = 'md',
  loading = false,
  disabled,
  className = '',
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      disabled={disabled || loading}
      className={`inline-flex items-center justify-center rounded-lg font-medium transition-all
        disabled:pointer-events-none disabled:opacity-50
        ${BUTTON_VARIANTS[variant]} ${BUTTON_SIZES[size]} ${className}`}
      {...rest}
    >
      {loading && <Loader2 size={14} className="animate-spin" aria-hidden />}
      {children}
    </button>
  )
}

/* ------------------------------------------------------------------ */
/* Badge / StatusPill                                                  */
/* ------------------------------------------------------------------ */

type BadgeTone = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'accent'

const BADGE_TONES: Record<BadgeTone, string> = {
  neutral: 'bg-fg/10 text-fg-muted ring-fg/20',
  success: 'bg-success/10 text-success ring-success/30',
  warning: 'bg-warning/10 text-warning ring-warning/30',
  danger: 'bg-danger/10 text-danger ring-danger/30',
  info: 'bg-info/10 text-info ring-info/30',
  accent: 'bg-accent-soft text-accent ring-accent-ring',
}

export function Badge({
  tone = 'neutral',
  children,
  className = '',
  ...rest
}: {
  tone?: BadgeTone
  children: ReactNode
  className?: string
} & React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ${BADGE_TONES[tone]} ${className}`}
      {...rest}
    >
      {children}
    </span>
  )
}

const STATUS_TONES: Record<string, BadgeTone> = {
  completed: 'success',
  analyzing: 'warning',
  queued: 'info',
  created: 'neutral',
  stopped: 'warning',
  failed: 'danger',
  running: 'warning',
}

export function StatusPill({ status }: { status: string }) {
  const t = useT()
  return (
    <Badge tone={STATUS_TONES[status] ?? 'neutral'}>
      {t(`status.${status}`, undefined) === `status.${status}`
        ? status.charAt(0).toUpperCase() + status.slice(1)
        : t(`status.${status}`)}
    </Badge>
  )
}

/* ------------------------------------------------------------------ */
/* Spinner / Skeleton                                                  */
/* ------------------------------------------------------------------ */

export function Spinner({ size = 16, className = '' }: { size?: number; className?: string }) {
  const label = useT()('common.loading')
  return (
    <Loader2
      size={size}
      className={`animate-spin text-fg-subtle ${className}`}
      role="status"
      aria-label={label}
    />
  )
}

export function SkeletonRow({ className = '' }: { className?: string }) {
  return <div className={`skeleton-shimmer h-4 rounded-md ${className}`} aria-hidden />
}

/* ------------------------------------------------------------------ */
/* Loading skeletons (initial data load only — not background refresh) */
/* ------------------------------------------------------------------ */

/** A11y wrapper: announces a loading message to screen readers while showing skeletons. */
export function SkeletonStatus({ label, children }: { label?: string; children: React.ReactNode }) {
  const t = useT()
  const resolved = label ?? t('common.loading')
  return (
    <div role="status" aria-label={resolved}>
      <span className="sr-only">{resolved}</span>
      {children}
    </div>
  )
}

/**
 * Skeleton body for a data table: real header row + `rows` skeleton rows with
 * per-column width classes. Drop-in replacement for text-only table loading.
 */
export function SkeletonTable({
  headers,
  widths,
  rows = 8,
  className = '',
}: {
  headers: string[]
  widths?: string[]
  rows?: number
  className?: string
}) {
  return (
    <SkeletonStatus>
      <div className={`overflow-hidden rounded-xl border border-border bg-surface-2/50 ${className}`}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-fg-subtle">
                {headers.map((h) => (
                  <th key={h} className="px-4 py-2.5">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody aria-hidden>
              {Array.from({ length: rows }, (_, i) => (
                <tr key={i} className="border-t border-border/60">
                  {headers.map((h, c) => (
                    <td key={h} className="px-4 py-2.5">
                      <SkeletonRow className={widths?.[c] ?? 'w-full'} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </SkeletonStatus>
  )
}

/** Skeleton stat-box matching StatBox/Metric cards (label + big number). */
export function SkeletonStatBox() {
  return (
    <div className="rounded-xl border border-border bg-surface-2/50 p-4" aria-hidden>
      <SkeletonRow className="w-1/2" />
      <SkeletonRow className="mt-3 h-7 w-1/3" />
    </div>
  )
}
