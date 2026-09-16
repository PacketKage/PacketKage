import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, screen } from '@testing-library/react'

// jsdom has no 2d canvas — cytoscape cannot mount. The canvas behavior is
// covered by e2e/graph.spec.ts; these tests lock the page chrome + selection
// wiring (v2 ids flow straight to the panels — no host: prefix rewriting).
let cyHandlers: Record<string, (e: any) => void> = {}
vi.mock('cytoscape', () => {
  const cytoscapeMock: any = vi.fn(() => ({
    destroy: () => {},
    on: (event: string, selector: any, cb?: (e: any) => void) => {
      // cy.on('tap', 'node', cb) / cy.on('tap', 'edge', cb)
      if (typeof selector === 'string' && cb) cyHandlers[`${event}:${selector}`] = cb
      return {}
    },
    nodes: () => ({ on: () => {} }),
    edges: () => ({ on: () => {} }),
    layout: () => ({ run: () => {} }),
    resize: () => {},
    fit: () => {},
    elements: () => ({ filter: () => [], map: () => [], remove: () => {} }),
    add: () => {},
    getElementById: () => ({ empty: () => true, isNode: () => false, length: 0, position: () => ({ x: 0, y: 0 }) }),
    animate: () => {},
    style: () => ({ fromJson: () => {} }),
  }))
  cytoscapeMock.use = () => {}
  return { default: cytoscapeMock }
})

import { GraphPage } from './GraphPage'
import {
  captureFixture,
  evidenceGraphFixture,
  graphV2BlastFixture,
  graphV2NodeDetailFixture,
  graphV2PathsFixture,
  timelinePageFixture,
} from '../test/fixtures'
import { renderPage } from '../test/harness'

afterEach(() => {
  cleanup()
  cyHandlers = {}
})

function seed(queries: { queryKey: unknown[]; data: unknown }[] = []) {
  return renderPage(<GraphPage />, {
    initialEntries: ['/graph'],
    queries: [
      { queryKey: ['captures'], data: [captureFixture()] },
      ...queries,
    ],
  })
}

// The Investigate canvas queries the evidence graph with an explicit node cap.
const v2Canvas = (over: object = {}) => ({
  queryKey: ['evidenceGraph', 'cap1', 300] as unknown[],
  data: evidenceGraphFixture(over as never),
})
const v2Mode = (over: object = {}) => ({
  queryKey: ['evidenceGraph', 'cap1'] as unknown[],
  data: evidenceGraphFixture(over as never),
})

describe('GraphPage — investigation workspace', () => {
  it('renders heading and default Investigate mode with v2 graph stats', () => {
    seed([v2Canvas(), v2Mode()])
    expect(screen.getByRole('heading', { name: 'Network Graph' })).toBeDefined()
    expect(screen.getByRole('tab', { name: 'Investigate' })).toBeDefined()
    expect(screen.getByText(/^8 nodes · 6 edges/)).toBeDefined()
    expect(screen.getByText('2 alert-backed')).toBeDefined()
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

  describe('Investigate filter rail', () => {
    it('renders node-kind, relationship and provenance toggles with counts', () => {
      seed([v2Canvas(), v2Mode()])
      // node kinds present in the v2 fixture
      expect(screen.getByText('Nodes')).toBeDefined()
      for (const kind of ['host', 'domain', 'service', 'alert', 'incident', 'case', 'capture']) {
        expect(screen.getByText(kind)).toBeDefined()
      }
      expect(screen.getByText('Edges')).toBeDefined()
      // relationship labels (sorted)
      for (const label of ['dns query', 'exposes', 'flow', 'includes', 'resolves to', 'triggered']) {
        expect(screen.getByText(label)).toBeDefined()
      }
      expect(screen.getByText('Provenance')).toBeDefined()
      expect(screen.getByText('observed')).toBeDefined()
      expect(screen.getByText('correlated')).toBeDefined()
      // provenance "enriched" has no edges in the fixture → hidden
      expect(screen.queryByText('enriched')).toBeNull()
    })

    it('toggles a relationship filter off (excludes those edges from shown count)', () => {
      seed([v2Canvas(), v2Mode()])
      // all 8 nodes + 6 edges shown
      expect(screen.getByText('14 shown')).toBeDefined()
      fireEvent.click(screen.getByText('flow'))
      // FLOW edge (+ its count) hidden, node count unchanged
      expect(screen.getByText('13 shown')).toBeDefined()
    })

    it('toggles a node kind filter off (hides those nodes + incident edges)', () => {
      const g = evidenceGraphFixture()
      seed([
        { queryKey: ['evidenceGraph', 'cap1', 300], data: g },
        { queryKey: ['evidenceGraph', 'cap1'], data: g },
      ])
      expect(screen.getByText('14 shown')).toBeDefined()
      fireEvent.click(screen.getByText('service'))
      // 1 service node gone; only EXPOSES edge touched it → 14 - 1 - 1 = 12
      expect(screen.getByText('12 shown')).toBeDefined()
    })

    it('hides the enriched provenance toggle when no enriched edges exist', () => {
      seed([v2Canvas(), v2Mode()])
      expect(screen.queryByText('enriched')).toBeNull()
    })
  })

  describe('search box + quick filters', () => {
    it('search filters nodes and locating a result opens the detail panel', () => {
      seed([
        { queryKey: ['evidenceGraph', 'cap1', 300], data: evidenceGraphFixture() },
        { queryKey: ['evidenceGraph', 'cap1'], data: evidenceGraphFixture() },
        {
          queryKey: ['graphNode', 'cap1', 'host:192.168.1.42'] as unknown[],
          data: graphV2NodeDetailFixture(),
        },
      ])
      const search = () => screen.getByRole('textbox', { name: 'Search graph nodes' })
      fireEvent.change(search(), { target: { value: 'evil' } })
      // the c2 domain matches on label/id
      expect(screen.getByRole('option', { name: /c2\.evil\.example/ })).toBeDefined()
      // no-match state
      fireEvent.change(search(), { target: { value: 'zzz-no-such-node' } })
      expect(screen.getByText('no matches')).toBeDefined()
      // type an ip that matches the host (highest importance rank first)
      fireEvent.change(search(), { target: { value: '192.' } })
      const result = screen.getByText('192.168.1.42')
      expect(result).toBeDefined()
      fireEvent.click(result)
      // query cleared and the NodeDetailPanel hydrated that exact node
      expect((search() as HTMLInputElement).value).toBe('')
      expect(screen.getByText('192.168.1.42')).toBeDefined()
      expect(screen.getByText('workstation')).toBeDefined()
    })

    it('quick filter presets apply provenance and kind combos', () => {
      seed([v2Canvas(), v2Mode()])
      expect(screen.getByText('14 shown')).toBeDefined()
      // Observed only → the 2 correlated edges vanish: 8 nodes + 4 edges
      fireEvent.click(screen.getByRole('button', { name: 'Observed' }))
      expect(screen.getByText('12 shown')).toBeDefined()
      // Alerts → alert + incident backbone only
      fireEvent.click(screen.getByRole('button', { name: 'Alerts' }))
      expect(screen.getByText('2 shown')).toBeDefined()
      // All → back to the full graph
      fireEvent.click(screen.getByRole('button', { name: 'All' }))
      expect(screen.getByText('14 shown')).toBeDefined()
    })

    it('fit view button re-centers the canvas', () => {
      seed([v2Canvas(), v2Mode()])
      const fit = screen.getByRole('button', { name: 'Fit graph to view' })
      expect(fit).toBeDefined()
      expect(() => fireEvent.click(fit)).not.toThrow()
    })
  })

  describe('selection wiring (v2 ids flow straight to panels)', () => {
    it('node tap passes the full v2 node id (no host: prefix rewrite)', () => {
      seed([
        {
          queryKey: ['graphNode', 'cap1', 'host:192.168.1.42'],
          data: graphV2NodeDetailFixture(),
        },
      ])
      // Investigate canvas requires the capped-graph seed to mount cy
      const g = evidenceGraphFixture()
      // re-render with capped seed: easiest via the same seed call pattern
      cleanup()
      seed([
        { queryKey: ['evidenceGraph', 'cap1', 300], data: g },
        { queryKey: ['evidenceGraph', 'cap1'], data: g },
        {
          queryKey: ['graphNode', 'cap1', 'host:192.168.1.42'] as unknown[],
          data: graphV2NodeDetailFixture(),
        },
      ])
      // simulate Cytoscape node tap
      const tap = cyHandlers['tap:node']
      expect(tap).toBeDefined()
      act(() => tap({ target: { id: () => 'host:192.168.1.42' } }))
      // NodeDetailPanel hydrates that exact id → node label renders
      expect(screen.getByText('192.168.1.42')).toBeDefined()
      expect(screen.getByText('workstation')).toBeDefined()
    })

    it('edge tap stores the v2 edge id and opens the provenance modal', () => {
      const g = evidenceGraphFixture()
      seed([
        { queryKey: ['evidenceGraph', 'cap1', 300], data: g },
        { queryKey: ['evidenceGraph', 'cap1'], data: g },
        {
          queryKey: ['graphEdge', 'cap1', 'cap1:host:192.168.1.42->host:185.234.72.19:FLOW'] as unknown[],
          data: g.edges[0],
        },
      ])
      const tap = cyHandlers['tap:edge']
      expect(tap).toBeDefined()
      tap({ target: { id: () => 'cap1:host:192.168.1.42->host:185.234.72.19:FLOW' } })
      // provenance panel reads the v2 edge directly (relationship + provenance chips)
      expect(screen.getByText('flow')).toBeDefined()
      expect(screen.getByText('observed')).toBeDefined()
    })
  })

  describe('status strip', () => {
    it('shows load-more when the graph is truncated and grows the node cap', () => {
      const g = evidenceGraphFixture({ truncated: true })
      seed([
        { queryKey: ['evidenceGraph', 'cap1', 300] as unknown[], data: g },
        { queryKey: ['evidenceGraph', 'cap1'] as unknown[], data: g },
        // the grown cap resolves back to the full (non-truncated) graph
        { queryKey: ['evidenceGraph', 'cap1', 600] as unknown[], data: evidenceGraphFixture() },
      ])
      const loadMore = screen.getByRole('button', { name: /load more nodes/ })
      expect(loadMore).toBeDefined()
      // clicking grows the limit → seeded 600-key resolves → full count shown
      fireEvent.click(loadMore)
      expect(screen.getByText(/showing 8 of 8 nodes/)).toBeDefined()
    })

    it('renders provenance counts in the status strip', () => {
      seed([v2Canvas(), v2Mode()])
      expect(screen.getByText(/observed 4/)).toBeDefined()
      expect(screen.getByText(/correlated 2/)).toBeDefined()
    })
  })

  it('switches to Attack Path mode and finds bounded paths', async () => {
    seed([
      v2Mode(),
      {
        queryKey: ['graphPaths', 'cap1', 'host:192.168.1.42', 'host:185.234.72.19'],
        data: graphV2PathsFixture,
      },
    ])
    ;(await screen.findByRole('tab', { name: 'Attack Path' })).click()
    const source = (await screen.findByLabelText('Source host')) as HTMLSelectElement
    const target = (await screen.findByLabelText('Target host')) as HTMLSelectElement
    expect(source.textContent).toContain('192.168.1.42')
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
      v2Mode(),
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
    seed([v2Mode()])
    ;(await screen.findByRole('tab', { name: 'Evidence' })).click()
    const conclusions = await screen.findAllByText('Conclusion')
    expect(conclusions.length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('Detections').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('Flows / Observations').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('PCAP reference').length).toBeGreaterThanOrEqual(2)
    const flowLinks = screen.getAllByText('flow1'.slice(0, 8))
    expect(flowLinks.length).toBeGreaterThan(0)
    for (const link of flowLinks) {
      expect((link as HTMLAnchorElement).getAttribute('href')).toContain('/flows?capture_id=cap1&flow=flow1')
    }
  })

  it('Evidence mode shows the honest empty state for clean captures', async () => {
    seed([v2Mode({ edges: [] })])
    ;(await screen.findByRole('tab', { name: 'Evidence' })).click()
    expect(
      await screen.findByText(/No alert-backed relationships in this capture/),
    ).toBeDefined()
  })
})