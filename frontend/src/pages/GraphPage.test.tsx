import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, screen } from '@testing-library/react'

// jsdom has no 2d canvas — cytoscape cannot mount. The canvas behavior is
// covered by e2e/graph.spec.ts; these tests lock the page chrome only.
vi.mock('cytoscape', () => {
  const cytoscapeMock: any = vi.fn(() => ({
    destroy: () => {},
    on: () => {},
    nodes: () => ({ on: () => {} }),
    edges: () => ({ on: () => {} }),
    layout: () => ({ run: () => {} }),
    resize: () => {},
    fit: () => {},
    elements: () => ({ remove: () => {} }),
    style: () => ({ fromString: () => ({ applyTo: () => {} }) }),
  }))
  cytoscapeMock.use = () => {}
  return { default: cytoscapeMock }
})

import { GraphPage } from './GraphPage'
import {
  captureFixture,
  evidenceGraphFixture,
  graphFixture,
  graphV2BlastFixture,
  graphV2PathsFixture,
  timelinePageFixture,
} from '../test/fixtures'
import { renderPage } from '../test/harness'

afterEach(cleanup)

function seed(queries: { queryKey: unknown[]; data: unknown }[] = []) {
  return renderPage(<GraphPage />, {
    initialEntries: ['/graph'],
    queries: [
      { queryKey: ['captures'], data: [captureFixture()] },
      ...queries,
    ],
  })
}

describe('GraphPage — investigation workspace', () => {
  it('renders heading and default Investigate mode with graph stats', () => {
    seed([
      { queryKey: ['graph', 'cap1'], data: graphFixture() },
      { queryKey: ['evidenceGraph', 'cap1'], data: evidenceGraphFixture() },
    ])
    expect(screen.getByRole('heading', { name: 'Network Graph' })).toBeDefined()
    expect(screen.getByRole('tab', { name: 'Investigate' })).toBeDefined()
    expect(screen.getByText(/2 hosts · 1 domains · 1 services · 4 edges/)).toBeDefined()
  })

  it('renders all five mode tabs', () => {
    seed()
    for (const label of ['Investigate', 'Attack Path', 'Blast Radius', 'Timeline', 'Evidence']) {
      expect(screen.getByRole('tab', { name: label })).toBeDefined()
    }
  })

  it('shows the no-captures state when none analyzed', () => {
    renderPage(<GraphPage />, {
      initialEntries: ['/graph'],
      queries: [{ queryKey: ['captures'], data: [] }],
    })
    expect(screen.getByText(/No analyzed captures/i)).toBeDefined()
  })

  it('switches to Attack Path mode and finds bounded paths', async () => {
    seed([
      { queryKey: ['evidenceGraph', 'cap1'], data: evidenceGraphFixture() },
      {
        queryKey: ['graphPaths', 'cap1', 'host:192.168.1.42', 'host:185.234.72.19'],
        data: graphV2PathsFixture,
      },
    ])
    ;(await screen.findByRole('tab', { name: 'Attack Path' })).click()
    const source = (await screen.findByLabelText('Source host')) as HTMLSelectElement
    const target = (await screen.findByLabelText('Target host')) as HTMLSelectElement
    // host pickers populated from the evidence graph
    expect(source.textContent).toContain('192.168.1.42')
    // drive the flow: pick source + target, find paths
    fireEvent.change(source, { target: { value: 'host:192.168.1.42' } })
    fireEvent.change(target, { target: { value: 'host:185.234.72.19' } })
    ;(await screen.findByText('Find paths')).click()
    expect(await screen.findByText('path 1')).toBeDefined()
    expect(screen.getByText('1 hop')).toBeDefined()
    expect(screen.getByText('2 hops')).toBeDefined()
    expect(screen.getAllByText('inferred')).toHaveLength(2)
  })

  it('switches to Blast Radius mode and renders rings + summary', async () => {
    seed([
      { queryKey: ['evidenceGraph', 'cap1'], data: evidenceGraphFixture() },
      {
        queryKey: ['graphBlast', 'cap1', 'host:192.168.1.42', 2],
        data: graphV2BlastFixture,
      },
    ])
    ;(await screen.findByRole('tab', { name: 'Blast Radius' })).click()
    const host = (await screen.findByLabelText('Blast radius start host')) as HTMLSelectElement
    expect(host.textContent).toContain('192.168.1.42')
    fireEvent.change(host, { target: { value: 'host:192.168.1.42' } })
    ;(await screen.findByText('Compute blast radius')).click()
    // summary cards render from the fixture
    expect(await screen.findByText('Alert-flagged')).toBeDefined()
    expect(await screen.findByText('Reachable nodes')).toBeDefined()
  })

  it('switches to Timeline mode and lists events', async () => {
    seed([
      {
        queryKey: ['graphTimeline', 'cap1'],
        data: timelinePageFixture,
      },
    ])
    ;(await screen.findByRole('tab', { name: 'Timeline' })).click()
    expect(await screen.findByText(/Chronological event stream/)).toBeDefined()
    expect(screen.getByText('Beaconing: 192.168.1.42 → 185.234.72.19')).toBeDefined()
  })

  it('switches to Evidence mode and renders the evidence chain', async () => {
    seed([{ queryKey: ['evidenceGraph', 'cap1'], data: evidenceGraphFixture() }])
    ;(await screen.findByRole('tab', { name: 'Evidence' })).click()
    // chain step labels — one chain per alert-backed edge (fixture: 2)
    const conclusions = await screen.findAllByText('Conclusion')
    expect(conclusions.length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('Detections').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('Flows / Observations').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('PCAP reference').length).toBeGreaterThanOrEqual(2)
    // flow deep links to the flows page
    const flowLinks = screen.getAllByText('flow1'.slice(0, 8))
    expect(flowLinks.length).toBeGreaterThan(0)
    for (const link of flowLinks) {
      expect((link as HTMLAnchorElement).getAttribute('href')).toContain('/flows?capture_id=cap1&flow=flow1')
    }
  })

  it('Evidence mode shows the honest empty state for clean captures', async () => {
    seed([{ queryKey: ['evidenceGraph', 'cap1'], data: evidenceGraphFixture({ edges: [] }) }])
    ;(await screen.findByRole('tab', { name: 'Evidence' })).click()
    expect(
      await screen.findByText(/No alert-backed relationships in this capture/),
    ).toBeDefined()
  })
})
