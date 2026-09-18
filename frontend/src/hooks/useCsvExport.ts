import { useState } from 'react'
import { toast } from 'sonner'
import { mutateError, mutateSuccess } from '../components/toasts'
import { downloadCsv, toCsv, type CsvCell } from '../utils/csv'
import type { Page } from '../types/api'
import { translate } from '../i18n/locale'

/** Backend caps: paged endpoints accept limit ≤ 500; hosts endpoint ≤ 1000. */
const PAGE_LIMIT = 500

/**
 * Fetch every row matching the current filters, paging at the backend cap
 * until the reported `total` is accumulated. Used by CSV export so the file
 * always reflects the full filtered dataset, not just the visible page.
 */
export async function fetchAllPages<T>(
  fetchPage: (page: { limit: number; offset: number }) => Promise<Page<T>>,
): Promise<T[]> {
  const first = await fetchPage({ limit: PAGE_LIMIT, offset: 0 })
  const all = [...first.items]
  const total = first.total
  while (all.length < total) {
    const next = await fetchPage({ limit: PAGE_LIMIT, offset: all.length })
    if (next.items.length === 0) break // server sent fewer than total — stop safely
    all.push(...next.items)
  }
  return all
}

export interface CsvExportOptions<T> {
  /** Filename slug + toast id, e.g. 'alerts'. */
  label: string
  /** Human-readable column headers, in order (already localized). */
  headers: string[]
  /** Map a row to CSV cells, in header order. */
  toRow: (row: T) => CsvCell[]
  /** Fetch all rows matching the CURRENT filters (may page internally). */
  fetchAll: () => Promise<T[]>
}

/**
 * CSV export for a filtered table dataset. Returns an accessible click handler
 * plus a pending flag for the button. Fires the existing toast system:
 * success with the row count, an info toast when nothing matches the
 * filters (no empty file is downloaded), and an error toast on failure.
 */
export function useCsvExport<T>(opts: CsvExportOptions<T>) {
  const [isExporting, setIsExporting] = useState(false)

  const run = async () => {
    if (isExporting) return
    setIsExporting(true)
    try {
      const rows = await opts.fetchAll()
      if (rows.length === 0) {
        toast.info(translate('csvexport.nothing'), { id: `export-${opts.label}` })
        return
      }
      downloadCsv(`${opts.label}-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(opts.headers, rows.map(opts.toRow)))
      mutateSuccess(translate('csvexport.exported', { count: rows.length }), `export-${opts.label}`)
    } catch (err) {
      mutateError(translate('csvexport.action'), err, `export-${opts.label}`)
    } finally {
      setIsExporting(false)
    }
  }

  return { export: run, isExporting }
}
