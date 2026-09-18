import type { Capture } from '../types/api'
import { useT } from '../i18n/LocaleContext'

/** Shared capture <select> used by every analysis page. */
export function CapturePicker({
  captures,
  value,
  onChange,
}: {
  captures: Capture[]
  value: string | null
  onChange: (id: string | null) => void
}) {
  const t = useT()
  return (
    <select
      aria-label={t('capture_picker.select')}
      value={value ?? ''}
      onChange={(e) => onChange(e.target.value || null)}
      className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg"
    >
      {captures.map((c) => (
        <option key={c.id} value={c.id}>
          {c.filename}
        </option>
      ))}
    </select>
  )
}
