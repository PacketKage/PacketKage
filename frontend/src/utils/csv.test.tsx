import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup } from '@testing-library/react'
import { toast as toastImported } from 'sonner'

// Mock sonner for every page-level test below (pages import it directly).
// The factory is hoisted; mock fns are created inside it and read back via
// vi.mocked() on the imported module.
vi.mock('sonner', () => {
  const fns = {
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warning: vi.fn(),
    promise: vi.fn(),
  }
  return { toast: fns, Toaster: () => null }
})
const toastMock = vi.mocked(toastImported)

import { csvTime, downloadCsv, toCsv } from './csv'
import { FlowsPage } from '../pages/FlowsPage'
import { AlertsPage } from '../pages/AlertsPage'
import { alertFixture, captureFixture, flowFixture } from '../test/fixtures'
import { renderPage } from '../test/harness'
import type { Alert } from '../types/api'

// jsdom lacks URL.createObjectURL — required by the export success path.
beforeEach(() => {
  if (typeof URL.createObjectURL !== 'function') {
    URL.createObjectURL = () => 'blob:mock-url'
    URL.revokeObjectURL = () => {}
  }
})

afterEach(cleanup)

/** toCsv: RFC 4180 escaping + row assembly. */
describe('toCsv', () => {
  it('joins headers and rows with commas and CRLF terminators', () => {
    const csv = toCsv(['A', 'B'], [
      [1, 'x'],
      [2, 'y'],
    ])
    expect(csv).toBe('A,B\r\n1,x\r\n2,y\r\n')
  })

  it('quotes fields containing commas and doubles embedded quotes', () => {
    const csv = toCsv(['Title'], [['Beaconing: 192.168.1.42 → 185.234.72.19, "suspicious"']])
    expect(csv).toBe('Title\r\n"Beaconing: 192.168.1.42 → 185.234.72.19, ""suspicious"""\r\n')
  })

  it('neutralizes CSV formula injection (=, +, -, @ prefixes)', () => {
    const csv = toCsv(['Domain'], [['=cmd|"/c calc"!A1'], ['+SUM(A1:A2)'], ['-2+1'], ['@x(y)']])
    expect(csv).toBe(
      'Domain\r\n"\'=cmd|""/c calc""!A1"\r\n\'+SUM(A1:A2)\r\n\'-2+1\r\n\'@x(y)\r\n',
    )
  })

  it('quotes fields containing newlines so row structure is preserved', () => {
    const csv = toCsv(['Note'], [['line1\nline2']])
    expect(csv).toBe('Note\r\n"line1\nline2"\r\n')
  })

  it('serializes arrays and objects as JSON, escaped when needed', () => {
    const csv = toCsv(['Answers', 'Evidence'], [
      [['1.2.3.4', '5.6.7.8'], { a: 'b,c' }],
    ])
    // JSON output contains quotes/commas → whole cell quoted, quotes doubled
    expect(csv).toBe(
      'Answers,Evidence\r\n' +
      '"[""1.2.3.4"",""5.6.7.8""]","{""a"":""b,c""}"\r\n',
    )
  })

  it('renders null/undefined as empty cells, booleans as true/false', () => {
    const csv = toCsv(['A', 'B', 'C'], [[null, undefined, true]])
    expect(csv).toBe('A,B,C\r\n,,true\r\n')
  })

  it('does not needlessly quote clean fields', () => {
    expect(toCsv(['IP'], [['192.168.1.42']])).toBe('IP\r\n192.168.1.42\r\n')
  })

  it('emits stable human-readable header rows for each dataset shape', () => {
    // header sets used by the six export tables (subset sanity check)
    const flowHeaders = [
      'First Seen', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
      'Protocol', 'App Protocol', 'Direction', 'State', 'Packets', 'Bytes',
      'Retransmissions', 'Resets', 'Duration (s)',
    ]
    const csv = toCsv(flowHeaders, [])
    expect(csv).toBe(
      'First Seen,Source IP,Source Port,Destination IP,Destination Port,Protocol,App Protocol,Direction,State,Packets,Bytes,Retransmissions,Resets,Duration (s)\r\n',
    )
  })
})

/** csvTime: epoch seconds → ISO 8601; null-safe. */
describe('csvTime', () => {
  it('converts epoch seconds to ISO 8601 UTC', () => {
    expect(csvTime(0)).toBe('1970-01-01T00:00:00.000Z')
    expect(csvTime(1700000030)).toBe('2023-11-14T22:13:50.000Z')
  })
  it('returns empty string for null/undefined', () => {
    expect(csvTime(null)).toBe('')
    expect(csvTime(undefined)).toBe('')
  })
})

/** downloadCsv: DOM-level download via a clicked anchor. */
describe('downloadCsv', () => {
  it('creates a blob URL, clicks a download anchor, and revokes the URL', () => {
    const created: string[] = []
    const revoked: string[] = []
    const anchors: HTMLAnchorElement[] = []
    const objectUrl = 'blob:mock-url'

    const origCreate = URL.createObjectURL
    const origRevoke = URL.revokeObjectURL
    const protoClick = HTMLAnchorElement.prototype.click
    URL.createObjectURL = () => {
      created.push(objectUrl)
      return objectUrl
    }
    URL.revokeObjectURL = (u: string) => revoked.push(u)
    HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
      anchors.push(this)
    }

    try {
      downloadCsv('flows-2026-09-13.csv', 'A,B\r\n1,2\r\n')
      expect(created).toEqual([objectUrl])
      expect(revoked).toEqual([objectUrl])
      expect(anchors).toHaveLength(1)
      expect(anchors[0].download).toBe('flows-2026-09-13.csv')
      expect(anchors[0].href).toBe(objectUrl)
    } finally {
      URL.createObjectURL = origCreate
      URL.revokeObjectURL = origRevoke
      HTMLAnchorElement.prototype.click = protoClick
    }
  })
})

/**
 * Page-level export behavior via FlowsPage (paged endpoint, 500-cap loop):
 * - requests carry the active filters
 * - pages through the full total
 * - success toast carries the row count
 * - empty result: info toast, no download anchor
 */
describe('useCsvExport — FlowsPage', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    toastMock.success.mockReset()
    toastMock.info.mockReset()
  })

  const page = (items: unknown[], total: number, offset = 0) =>
    new Response(JSON.stringify({ items, total, offset, limit: 500 }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })

  /**
   * Seed FlowsPage with captures + the first table page preloaded (so the
   * export button is enabled — it is disabled while the table is loading).
   * `fetch` handles the export's re-query at the 500 cap.
   */
  function seedFlows() {
    return renderPage(<FlowsPage />, {
      initialEntries: ['/flows'],
      queries: [
        { queryKey: ['captures'], data: [captureFixture()] },
        {
          queryKey: ['flows', 'cap1', '', '', 'first_seen', 'asc', 0],
          data: { items: [flowFixture()], total: 1, offset: 0, limit: 50 },
        },
      ],
    })
  }

  it('exports all filtered rows across pages and toasts the count', async () => {
    const f1 = Array.from({ length: 500 }, (_, i) => flowFixture({ id: `f${i}` }))
    const f2 = Array.from({ length: 250 }, (_, i) => flowFixture({ id: `g${i}` }))
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('offset=500')) return page(f2, 750, 500)
      return page(f1, 750, 0)
    })

    seedFlows()
    await clickExportWhenEnabled('Export flows to CSV')

    await vi.waitFor(() => {
      expect(toastMock.success).toHaveBeenCalledWith('Exported 750 flows to CSV', { id: 'export-flows' })
    })
    // two pages fetched at the 500 cap: offset 0 then offset 500
    const exportUrls = fetchMock.mock.calls.map(([u]) => String(u)).filter((u) => u.includes('/flows?'))
    expect(exportUrls.some((u) => u.includes('limit=500') && u.includes('offset=0'))).toBe(true)
    expect(exportUrls.some((u) => u.includes('limit=500') && u.includes('offset=500'))).toBe(true)
  })

  /** Click helper: waits until the export button is enabled (table loaded), then clicks. */
  async function clickExportWhenEnabled(ariaLabel: string) {
    const btn = (await vi.waitFor(() => {
      const el = document.querySelector(`button[aria-label="${ariaLabel}"]`) as HTMLButtonElement
      if (!el || el.disabled) throw new Error('export button not ready')
      return el
    })) as HTMLButtonElement
    await act(async () => {
      btn.click()
    })
  }

  it('carries the active transport/direction filters in the export request', async () => {
    fetchMock.mockImplementation(async () => page([flowFixture()], 1))

    seedFlows()
    // apply the TCP filter first, let the table settle, then export
    const tcpBtn = [...document.querySelectorAll('button')].find(
      (b) => b.textContent === 'TCP',
    ) as HTMLButtonElement
    await act(async () => {
      tcpBtn.click()
    })
    await clickExportWhenEnabled('Export flows to CSV')

    await vi.waitFor(() => {
      expect(toastMock.success).toHaveBeenCalled()
    })
    const exportUrl = fetchMock.mock.calls
      .map(([u]) => String(u))
      .find((u) => u.includes('/flows?') && u.includes('limit=500'))
    expect(exportUrl).toContain('transport=TCP')
  })

  it('empty result → info toast and no download anchor appended', async () => {
    fetchMock.mockImplementation(async () => page([], 0))

    seedFlows()
    const before = document.querySelectorAll('a[download]').length
    await clickExportWhenEnabled('Export flows to CSV')
    await vi.waitFor(() => {
      expect(toastMock.info).toHaveBeenCalledWith(
        'Nothing to export — no rows match the current filters',
        { id: 'export-flows' },
      )
    })
    expect(toastMock.success).not.toHaveBeenCalled()
    expect(document.querySelectorAll('a[download]').length).toBe(before)
  })

  it('API failure during export → error toast with backend detail', async () => {
    fetchMock.mockImplementation(async () =>
      new Response(JSON.stringify({ detail: 'capture is being re-analyzed' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    seedFlows()
    await clickExportWhenEnabled('Export flows to CSV')
    await vi.waitFor(() => {
      expect(toastMock.error).toHaveBeenCalledWith(
        'Export failed — capture is being re-analyzed',
        { id: 'export-flows' },
      )
    })
  })
})

/** Alerts: client-side unconfirmed filter applies to the exported set. */
describe('useCsvExport — AlertsPage client filter', () => {
  const fetchMock = vi.fn()

  /** Click helper: waits until the alerts export button is enabled. */
  async function clickExportWhenEnabled() {
    const btn = (await vi.waitFor(() => {
      const el = document.querySelector('button[aria-label="Export alerts to CSV"]') as HTMLButtonElement
      if (!el || el.disabled) throw new Error('export button not ready')
      return el
    })) as HTMLButtonElement
    await act(async () => {
      btn.click()
    })
  }

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock)
    fetchMock.mockReset()
    toastMock.success.mockReset()
  })

  function seedAlerts(items: Alert[]) {
    return renderPage(<AlertsPage />, {
      initialEntries: ['/alerts'],
      queries: [
        { queryKey: ['captures'], data: [captureFixture()] },
        { queryKey: ['alerts', 'cap1', ''], data: { items, total: items.length, offset: 0, limit: 100 } },
        { queryKey: ['captureDetail', 'cap1'], data: captureFixture() },
      ],
    })
  }

  it('filters confirmed/false-positive alerts out of the export when checkbox is on', async () => {
    const confirmed = alertFixture({ id: 'a-confirmed', tags: ['confirmed'] })
    const fresh = alertFixture({ id: 'a-fresh', tags: [] })
    fetchMock.mockImplementation(async () =>
      new Response(JSON.stringify({ items: [confirmed, fresh], total: 2, offset: 0, limit: 500 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )

    seedAlerts([confirmed, fresh])

    // enable the client-side "hide confirmed & false-positives" filter
    const checkbox = document.querySelector('input[type="checkbox"]') as HTMLInputElement
    await act(async () => {
      checkbox.click()
    })
    await clickExportWhenEnabled()

    await vi.waitFor(() => {
      // only the untriaged alert is exported
      expect(toastMock.success).toHaveBeenCalledWith('Exported 1 alerts to CSV', { id: 'export-alerts' })
    })
  })

  it('exports all alerts (server severity filter in request) when checkbox is off', async () => {
    const critical = alertFixture({ id: 'a-1', severity: 'critical' })
    const high = alertFixture({ id: 'a-2', severity: 'high' })
    fetchMock.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input)
      const items = url.includes('severity=critical') ? [critical] : [critical, high]
      return new Response(JSON.stringify({ items, total: items.length, offset: 0, limit: 500 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })

    seedAlerts([critical, high])

    // select the critical severity filter (label may carry a count)
    const criticalBtn = [...document.querySelectorAll('button')].find(
      (b) => (b.textContent ?? '').startsWith('critical'),
    ) as HTMLButtonElement
    await act(async () => {
      criticalBtn.click()
    })
    await clickExportWhenEnabled()

await vi.waitFor(() => {
      expect(toastMock.success).toHaveBeenCalledWith('Exported 1 alerts to CSV', { id: 'export-alerts' })
    })
    const exportUrl = fetchMock.mock.calls
      .map(([u]) => String(u))
      .find((u) => u.includes('/alerts?') && u.includes('limit=500'))
    expect(exportUrl).toContain('severity=critical')
  })
})
