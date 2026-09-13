/**
 * CSV generation + browser download. RFC 4180-compliant: fields containing
 * commas, quotes, or newlines are quoted; embedded quotes are doubled;
 * rows are CRLF-terminated.
 */

/** A CSV cell. Nested values (arrays/objects) are JSON-serialized. */
export type CsvCell = string | number | boolean | null | undefined | unknown[] | Record<string, unknown>

export function toCsv(headers: string[], rows: CsvCell[][]): string {
  const escapeCell = (cell: CsvCell): string => {
    let value: string
    if (cell == null) {
      value = ''
    } else if (Array.isArray(cell)) {
      value = JSON.stringify(cell)
    } else if (typeof cell === 'object') {
      value = JSON.stringify(cell)
    } else {
      value = String(cell)
    }
    // CSV-formula mitigation: cells that Excel/Sheets would evaluate as a
    // formula (=, +, -, @, tab, CR) get a leading single quote. Exports come
    // from hostile network data (DNS names, UAs, paths) — see OWASP CSV
    // Injection; the quote is a standard neutralizer and survives re-export.
    if (/^[=+\-@\t\r]/.test(value)) {
      value = `'${value}`
    }
    if (/[",\r\n]/.test(value)) {
      return `"${value.replace(/"/g, '""')}"`
    }
    return value
  }
  const lines = [headers.map(escapeCell).join(','), ...rows.map((row) => row.map(escapeCell).join(','))]
  return lines.join('\r\n') + '\r\n'
}

/** Epoch-seconds (API timestamps) → ISO 8601 string; null → empty. */
export function csvTime(ts: number | null | undefined): string {
  if (ts == null) return ''
  return new Date(ts * 1000).toISOString()
}

/**
 * Trigger a browser download of `content` as a CSV file. Uses a UTF-8 BOM so
 * Excel detects the encoding; revokes the object URL after the click.
 */
export function downloadCsv(filename: string, content: string): void {
  const blob = new Blob([`\uFEFF${content}`], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}
