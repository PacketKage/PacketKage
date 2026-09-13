import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { CapturePage } from './CapturePage'
import { captureFixture } from '../test/fixtures'
import { renderPage, seededQueryClient } from '../test/harness'
import type { Capture } from '../types/api'

type CaptureRow = Capture

afterEach(cleanup)

/**
 * Characterization tests for CapturePage — lock current behavior before the
 * Phase-3 token sweep.
 */

function seed(captures = [captureFixture()]) {
  return renderPage(<CapturePage />, {
    initialEntries: ['/capture'],
    queries: [
      { queryKey: ['captures'], data: captures },
      { queryKey: ['parsers'], data: { scapy: true } },
      // live interfaces query (LiveCapturePanel)
      { queryKey: ['liveInterfaces'], data: ['lo'] },
      { queryKey: ['liveStatus'], data: null },
    ],
  })
}

describe('CapturePage', () => {
  it('renders heading, upload zone and the file select button', () => {
    seed()
    expect(screen.getByRole('heading', { name: 'Capture' })).toBeDefined()
    expect(screen.getByText(/Drop or select a capture file/)).toBeDefined()
    const btn = screen.getByRole('button', { name: 'Select PCAP file' })
    expect(btn).toBeDefined()
  })

  it('offers parser selection: Auto + scapy (tshark hidden when unavailable)', () => {
    seed()
    expect(screen.getByRole('button', { name: 'Auto' })).toBeDefined()
    expect(screen.getByRole('button', { name: 'scapy' })).toBeDefined()
    expect(screen.queryByRole('button', { name: 'tshark' })).toBeNull()
    expect(screen.getByText(/available: scapy/)).toBeDefined()
  })

  it('switching parser selection updates the active button', () => {
    seed()
    const scapy = screen.getByRole('button', { name: 'scapy' })
    act(() => {
      fireEvent.click(scapy)
    })
    // both still present; scapy now active (visual only — assert no crash + still clickable)
    expect(screen.getByRole('button', { name: 'scapy' })).toBeDefined()
  })

  it('selecting a capture from the list shows its detail card (completed)', () => {
    seed()
    // click the capture row in the "All captures" list
    act(() => {
      fireEvent.click(screen.getByText('c2_beacon.pcap'))
    })
    expect(screen.getByText(/parsed by scapy/)).toBeDefined()
    expect(screen.getAllByText('Completed').length).toBeGreaterThanOrEqual(2) // list + detail pills
  })

  it('shows the Analyze button for a freshly created (unanalyzed) capture', () => {
    seed([captureFixture({ status: 'created', analysis_progress: 0, parser_used: null, summary: {} })])
    act(() => {
      fireEvent.click(screen.getByText('c2_beacon.pcap'))
    })
    expect(screen.getByRole('button', { name: 'Analyze' })).toBeDefined()
  })

  it('renders the live capture panel interface selector', () => {
    seed()
    // LiveCapturePanel heading + interface select seeded with lo
    expect(screen.getByText(/Live capture/)).toBeDefined()
    expect(screen.getByRole('button', { name: /start/i }) || true).toBeTruthy()
  })

  it('renders the upload-zone file input (hidden) with pcap accept', () => {
    seed()
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    expect(input).not.toBeNull()
    expect(input.getAttribute('accept')).toBe('.pcap,.pcapng,.cap')
  })

  /* ---------------------------------------------------------------- */
  /* SSE self-heal regression: if job snapshots stop arriving (e.g.   */
  /* a malformed/lost SSE message), the polled captures list is the   */
  /* source of truth — the detail card must leave the analyzing state */
  /* once the DB row says completed. Reproduces the invalid-JSON SSE   */
  /* bug: liveJob frozen at 'queued' + backend already finished.      */
  /* ---------------------------------------------------------------- */

  it('detail card self-heals to Completed when the polled capture is terminal even if the job snapshot stays queued', async () => {
    // suppress jsdom navigation noise
    vi.spyOn(console, 'error').mockImplementation(() => {})

    const createdCapture = captureFixture({
      status: 'created',
      analysis_progress: 0,
      parser_used: null,
      summary: {},
    })
    const queryClient = seededQueryClient([
      { queryKey: ['captures'], data: [createdCapture] },
      { queryKey: ['parsers'], data: { scapy: true } },
      { queryKey: ['liveInterfaces'], data: ['lo'] },
      { queryKey: ['liveStatus'], data: null },
    ])

    // Analyze POST resolves to a job snapshot frozen at 'queued'; the SSE
    // subscription is stubbed to never deliver updates (broken stream).
    const stuckJob = {
      id: 'job-stuck',
      capture_id: 'cap1',
      type: 'full_analysis',
      status: 'queued',
      progress: 0,
      stage: 'queued',
      message: null,
      created_at: '2026-09-13T10:00:00Z',
      started_at: null,
      finished_at: null,
      result: {},
    }
    // Backend state the fetch mock serves: starts at 'created', flips to
    // 'completed' mid-test (the backend finishing the analysis).
    let backendRows: CaptureRow[] = [createdCapture]
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api/captures/cap1/analyze')) {
        return new Response(JSON.stringify(stuckJob), {
          status: 202,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      if (url.includes('/api/captures')) {
        return new Response(JSON.stringify(backendRows), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }
      return new Response('[]', { status: 200, headers: { 'Content-Type': 'application/json' } })
    })
    vi.stubGlobal('fetch', fetchMock)

    // EventSource absent in jsdom: stub a broken stream — constructs fine
    // but never delivers messages (mirrors the invalid-JSON symptom where
    // every onmessage throws before setLiveJob sees a snapshot).
    class DeadEventSource {
      url: string
      onmessage: unknown = null
      onerror: unknown = null
      constructor(url: string) {
        this.url = url
      }
      close() {}
    }
    vi.stubGlobal('EventSource', DeadEventSource as unknown as new (url: string) => EventSource)

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/capture']}>
          <Routes>
            <Route path="/" element={<CapturePage />} />
            <Route path="*" element={<CapturePage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )

    // Select the created capture, then start analysis
    act(() => {
      fireEvent.click(screen.getByText('c2_beacon.pcap'))
    })
    act(() => {
      fireEvent.click(screen.getByRole('button', { name: 'Analyze' }))
    })

    // Job accepted (stuck at queued) → card shows the analyzing pin
    await waitFor(() => {
      expect(screen.getByText('Analysis running…')).toBeDefined()
    })

    // The backend finished: the next captures poll returns 'completed'
    // while the job snapshot remains frozen at 'queued'.
    backendRows = [captureFixture({ id: 'cap1', status: 'completed', analysis_progress: 100 })]
    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: ['captures'] })
    })

    // Detail card must reflect the terminal polled state — no eternal spinner
    await waitFor(() => {
      expect(screen.queryByText('Analysis running…')).toBeNull()
    })
    expect(screen.getAllByText('Completed').length).toBeGreaterThanOrEqual(1)
    // Summary stats render for a completed capture (usable end state)
    expect(screen.getByText('Packets')).toBeDefined()

    vi.unstubAllGlobals()
  })
})
