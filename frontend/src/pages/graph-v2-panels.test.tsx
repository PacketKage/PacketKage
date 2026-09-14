import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

vi.mock('cytoscape', () => {
  const cytoscapeMock: any = vi.fn(() => ({}))
  cytoscapeMock.use = () => {}
  return { default: cytoscapeMock }
})

import { EdgeProvenancePanel, EvidenceChainList, MitreChip, NodeDetailPanel } from './graph-v2-panels'
import {
  evidenceGraphFixture,
  graphV2EdgeDetailFixture,
  graphV2NodeDetailFixture,
} from '../test/fixtures'

afterEach(cleanup)

function renderWithQueries(queries: { queryKey: unknown[]; data: unknown }[], ui: React.ReactNode) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity, staleTime: Infinity } },
  })
  for (const { queryKey, data } of queries) {
    queryClient.setQueryData(queryKey, data)
  }
  return render(
    <MemoryRouter>
      <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>
    </MemoryRouter>,
  )
}

describe('EdgeProvenancePanel', () => {
  it('renders provenance metadata, explanation, alerts with MITRE, and flows', () => {
    const edge = graphV2EdgeDetailFixture()
    renderWithQueries(
      [{ queryKey: ['graphEdge', 'cap1', edge.id], data: edge }],
      <EdgeProvenancePanel edge={edge} captureId="cap1" />,
    )
    // identity chips
    expect(screen.getByText('flow')).toBeDefined()
    expect(screen.getByText('observed')).toBeDefined()
    expect(screen.getAllByText(/4444/).length).toBeGreaterThan(0)
    // why-suspicious explanation (real alert text)
    expect(screen.getByText(/Why is this relationship suspicious\?/)).toBeDefined()
    expect(screen.getByText(/1 alert\(s\) touch this relationship: beaconing/)).toBeDefined()
    // joined alert with reasons + MITRE chip
    expect(screen.getAllByText('Regular intervals:').length).toBeGreaterThan(0)
    expect(screen.getByText(/jitter 4\.2%/)).toBeDefined()
    // internal classification renders as a PK chip — never as an ATT&CK ID
    expect(screen.getByText('PK · Scheduled Beaconing')).toBeDefined()
    expect(screen.queryByText(/C1091/)).toBeNull()
    // contributing flows with deep link (anchor href contains the flow route)
    const flowLink = document.querySelector<HTMLAnchorElement>(
      `a[href="/flows?capture_id=cap1&flow=flow1"]`,
    )
    expect(flowLink).toBeTruthy()
    expect(flowLink!.textContent).toContain('packets')
    // raw reference counts (counts are in separate spans — match the line)
    const refsLine = screen.getAllByText(
      (_content, el) =>
        !!el?.textContent?.match(/flow refs/) &&
        (el.textContent?.includes('alert refs') ?? false),
    )
    expect(refsLine.length).toBeGreaterThan(0)
    expect(refsLine[0].textContent).toContain('2')
    expect(refsLine[0].textContent).toContain('3 packet refs')
  })

  it('renders the honest not-suspicious state when no alerts back the edge', () => {
    const edge = graphV2EdgeDetailFixture({
      alert_ids: [],
      alerts: [],
      explanation: null,
    })
    renderWithQueries(
      [{ queryKey: ['graphEdge', 'cap1', edge.id], data: edge }],
      <EdgeProvenancePanel edge={edge} captureId="cap1" />,
    )
    expect(
      screen.getByText(/No alerts in this capture touch this relationship/),
    ).toBeDefined()
  })

  it('shows missing-evidence emptiness (no flows/alerts) without erroring', () => {
    const edge = graphV2EdgeDetailFixture({ flows: [], alerts: [] })
    renderWithQueries(
      [{ queryKey: ['graphEdge', 'cap1', edge.id], data: edge }],
      <EdgeProvenancePanel edge={edge} captureId="cap1" />,
    )
    expect(screen.queryByText(/Contributing flows/)).toBeNull()
  })
})

describe('NodeDetailPanel', () => {
  it('renders host metadata, relationships, and blast/path actions', () => {
    const detail = graphV2NodeDetailFixture()
    renderWithQueries(
      [{ queryKey: ['graphNode', 'cap1', 'host:192.168.1.42'], data: detail }],
      <NodeDetailPanel
        nodeId="host:192.168.1.42"
        captureId="cap1"
        onClose={() => {}}
        onBlast={() => {}}
        onPath={() => {}}
      />,
    )
    expect(screen.getByText('192.168.1.42')).toBeDefined()
    expect(screen.getByText('host')).toBeDefined()
    expect(screen.getByText('internal')).toBeDefined()
    expect(screen.getByText('Blast radius →')).toBeDefined()
    expect(screen.getByText('Attack path from here →')).toBeDefined()
    // incident relationships with provenance chips
    expect(screen.getByText('flow')).toBeDefined()
    expect(screen.getAllByText('observed').length).toBeGreaterThan(0)
  })
})

describe('EvidenceChainList', () => {
  it('renders the 5-step chain for alert-backed relationships with deep links', () => {
    const graph = evidenceGraphFixture()
    renderWithQueries([], <EvidenceChainList graph={graph} captureId="cap1" />)
    for (const step of ['Conclusion', 'Detections', 'Evidence', 'Flows / Observations', 'PCAP reference']) {
      expect(screen.getAllByText(step).length).toBeGreaterThanOrEqual(2) // one per chain
    }
    // alert + flow deep links point at the real pages
    const alertLink = screen.getAllByText('alert1'.slice(0, 8))[0].closest('a')
    expect(alertLink?.getAttribute('href')).toContain('/alerts?capture_id=cap1&alert=alert1')
    const flowLink = screen.getAllByText('flow1'.slice(0, 8))[0].closest('a')
    expect(flowLink?.getAttribute('href')).toContain('/flows?capture_id=cap1&flow=flow1')
  })

  it('renders the honest empty state when nothing is alert-backed', () => {
    renderWithQueries(
      [],
      <EvidenceChainList graph={evidenceGraphFixture({ edges: [] })} captureId="cap1" />,
    )
    expect(screen.getByText(/No alert-backed relationships in this capture/)).toBeDefined()
  })
})

describe('MitreChip — official vs internal classification rendering', () => {
  it('renders official ATT&CK mappings as technique chips', () => {
    render(
      <MitreChip
        mitre={{ source: 'mitre', technique_id: 'T1046', technique: 'Network Service Discovery', tactic: 'Discovery' }}
      />,
    )
    expect(screen.getByText('T1046 · Network Service Discovery')).toBeDefined()
  })

  it('renders internal classifications as PK chips without any technique ID', () => {
    render(
      <MitreChip
        mitre={{ source: 'packetkage', technique_id: null, technique: 'Scheduled Beaconing', tactic: 'Command and Control' }}
      />,
    )
    expect(screen.getByText('PK · Scheduled Beaconing')).toBeDefined()
    expect(screen.queryByText(/C1091/)).toBeNull()
    expect(screen.queryByText(/T\d{4}/)).toBeNull()
  })

  it('never renders an internal-style ID (C1091) as a MITRE technique, even if the payload claims mitre source', () => {
    render(
      <MitreChip
        mitre={{ source: 'mitre', technique_id: 'C1091', technique: 'Scheduled Beaconing', tactic: 'Command and Control' }}
      />,
    )
    // adversarial/stale payload: must fall back to internal styling, never
    // render "C1091 · ..." as an official ATT&CK mapping
    expect(screen.queryByText('C1091 · Scheduled Beaconing')).toBeNull()
    expect(screen.getByText('PK · Scheduled Beaconing')).toBeDefined()
  })

  it('renders a malformed technique ID claimed as official as internal, not ATT&CK', () => {
    render(
      <MitreChip
        mitre={{ source: 'mitre', technique_id: 'T10', technique: 'Bogus Technique', tactic: 'Discovery' }}
      />,
    )
    expect(screen.queryByText('T10 · Bogus Technique')).toBeNull()
    expect(screen.getByText('PK · Bogus Technique')).toBeDefined()
  })

  it('renders nothing when there is no mapping', () => {
    const { container } = render(<MitreChip mitre={null} />)
    expect(container.querySelector('span')).toBeNull()
  })
})
