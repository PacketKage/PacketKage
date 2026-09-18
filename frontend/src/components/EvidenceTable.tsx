/**
 * Structured evidence renderer — replaces raw JSON.stringify dumps.
 * Renders nested objects as labeled rows, arrays as chip rows, and
 * primitives as monospace values. Compact and theme-aware.
 */
import { useT } from '../i18n/LocaleContext'

export function EvidenceTable({ data, depth = 0 }: { data: Record<string, unknown>; depth?: number }) {
  const entries = Object.entries(data)
  const t = useT()
  if (!entries.length) {
    return <p className="text-xs text-fg-subtle">{t('evidence.no_evidence')}</p>
  }
  return (
    <div className="space-y-1.5">
      {entries.map(([key, value]) => (
        <div key={key} className="flex items-start gap-3 text-sm">
          <span className="w-40 shrink-0 text-xs uppercase tracking-wider text-fg-subtle">
            {key}
          </span>
          <span className="min-w-0 flex-1">
            <Value value={value} depth={depth} />
          </span>
        </div>
      ))}
    </div>
  )
}

function Value({ value, depth }: { value: unknown; depth: number }) {
  if (value == null) return <span className="text-xs text-fg-subtle">—</span>

  if (Array.isArray(value)) {
    if (!value.length) return <span className="text-xs text-fg-subtle">[]</span>
    // arrays of primitives → chips; arrays of objects → nested tables
    if (value.every((v) => typeof v !== 'object' || v === null)) {
      return (
        <span className="flex flex-wrap gap-1.5">
          {value.map((v, i) => (
            <span
              key={i}
              className="rounded bg-surface-3/70 px-1.5 py-0.5 font-mono text-xs text-fg-muted ring-1 ring-border"
            >
              {String(v)}
            </span>
          ))}
        </span>
      )
    }
    return (
      <span className="block space-y-1.5">
        {value.map((v, i) =>
          typeof v === 'object' && v !== null ? (
            <span key={i} className="block rounded-lg bg-surface/60 p-2 ring-1 ring-border">
              <EvidenceTable data={v as Record<string, unknown>} depth={depth + 1} />
            </span>
          ) : (
            <span key={i} className="block font-mono text-xs text-fg-muted">{String(v)}</span>
          ),
        )}
      </span>
    )
  }

  if (typeof value === 'object') {
    return (
      <span className="block">
        <EvidenceTable data={value as Record<string, unknown>} depth={depth + 1} />
      </span>
    )
  }

  if (typeof value === 'boolean') {
    return <span className="font-mono text-xs text-fg-muted">{String(value)}</span>
  }

  // numbers/strings — monospace value
  return <span className="font-mono text-xs text-fg-muted">{String(value)}</span>
}

