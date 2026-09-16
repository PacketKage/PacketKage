import { describe, expect, it } from 'vitest'
import type { GraphV2 } from '../types/api'
import {
  computeNodeMetrics,
  computeTier,
  edgeCurveForTier,
  hubEdgeIds,
  hubEdgeFactor,
  labeledNodeIds,
  layoutForTier,
  leafDomainIds,
  nodeSize,
  repulsionFor,
  elasticityFor,
} from './graph-scaling'

const graph = (nodes: unknown[], edges: unknown[]): GraphV2 => ({
  nodes: nodes as GraphV2['nodes'],
  edges: edges as GraphV2['edges'],
  stats: {
    node_count: (nodes as unknown[]).length,
    total_nodes: (nodes as unknown[]).length,
    edge_count: (edges as unknown[]).length,
    total_edges_in_capture: (edges as unknown[]).length,
    relationships: [],
    provenance_classes: [],
    alert_backed_edges: 0,
  },
  truncated: false,
})

describe('computeTier', () => {
  it('detail for small graphs', () => {
    expect(computeTier(80)).toBe('detail')
    expect(computeTier(1)).toBe('detail')
  })
  it('balanced for medium graphs', () => {
    expect(computeTier(81)).toBe('balanced')
    expect(computeTier(300)).toBe('balanced')
  })
  it('scale for large graphs', () => {
    expect(computeTier(301)).toBe('scale')
    expect(computeTier(1000)).toBe('scale')
  })
})

describe('importance + node size', () => {
  it('alert hosts dominate plain hubs', () => {
    const g = graph(
      [
        { id: 'host:plain', kind: 'host', alert_count: 0, bytes_sent: 10000, bytes_received: 0 },
        { id: 'host:alert', kind: 'host', alert_count: 1, bytes_sent: 0, bytes_received: 0 },
      ],
      [],
    )
    const m = computeNodeMetrics(g)
    expect(m.scores.get('host:alert')!).toBeGreaterThan(m.scores.get('host:plain')!)
  })

  it('nodeSize grows with score but is capped', () => {
    expect(nodeSize(0)).toBe(18)
    expect(nodeSize(10)).toBeGreaterThan(nodeSize(0))
    expect(nodeSize(1e9)).toBe(44)
  })
})

describe('labeledNodeIds', () => {
  const hosts = [
    { id: 'host:h1', kind: 'host', label: 'h1', alert_count: 2 },
    { id: 'host:h2', kind: 'host', label: 'h2', alert_count: 0 },
    { id: 'domain:d1', kind: 'domain', label: 'd1' },
    { id: 'domain:d2', kind: 'domain', label: 'd2' },
    { id: 'domain:d3', kind: 'domain', label: 'd3' },
  ]
  const edges = [
    { id: 'e1', source: 'host:h2', target: 'domain:d1', relationship: 'DNS_QUERY', ...edgeBase },
    { id: 'e2', source: 'host:h2', target: 'domain:d2', relationship: 'DNS_QUERY', ...edgeBase },
  ]
  const g = graph(hosts, edges)

  it('detail tier labels everything', () => {
    const m = computeNodeMetrics(g)
    expect(labeledNodeIds(m, 'detail', g).size).toBe(5)
  })

  it('balanced/scale tiers always include alert hosts within the limit', () => {
    const m = computeNodeMetrics(g)
    const labeled = labeledNodeIds(m, 'balanced', g)
    expect(labeled.size).toBeLessThanOrEqual(40)
    expect(labeled.has('host:h1')).toBe(true) // alert host always labeled
  })

  it('scale tier caps labels at alert hosts only', () => {
    const many = Array.from({ length: 50 }, (_, i) => ({
      id: `host:h${i}`,
      kind: 'host',
      label: `h${i}`,
      alert_count: i === 7 ? 1 : 0,
    }))
    const g2 = graph(many, [])
    const m = computeNodeMetrics(g2)
    const labeled = labeledNodeIds(m, 'scale', g2)
    expect(labeled.size).toBe(1)
    expect(labeled.has('host:h7')).toBe(true)
  })
})

describe('hub-aware layout multipliers', () => {
  it('repulsion grows with degree up to 3x', () => {
    expect(repulsionFor(0, 9000)).toBe(9000)
    expect(repulsionFor(40, 9000)).toBe(18000)
    expect(repulsionFor(80, 9000)).toBe(27000)
    expect(repulsionFor(500, 9000)).toBe(27000) // capped
  })

  it('hub edges are stretched, regular edges are not', () => {
    expect(hubEdgeFactor(5)).toBe(1)
    expect(hubEdgeFactor(21)).toBe(1.3)
  })

  it('hub edges get stretchier elasticity', () => {
    expect(elasticityFor(true)).toBeLessThan(elasticityFor(false))
  })

  it('hubEdgeIds marks edges touching degree>15 nodes', () => {
    const g = graph(
      [
        { id: 'host:hub', kind: 'host', label: 'hub' },
        { id: 'host:plain', kind: 'host', label: 'plain' },
        { id: 'host:a', kind: 'host', label: 'a' },
        { id: 'host:b', kind: 'host', label: 'b' },
      ],
      [
        { id: 'e1', source: 'host:hub', target: 'host:a', relationship: 'FLOW', ...edgeBase },
        { id: 'e2', source: 'host:plain', target: 'host:b', relationship: 'FLOW', ...edgeBase },
      ],
    )
    const m = computeNodeMetrics(g)
    const hubEdges = hubEdgeIds(m.degrees, g)
    expect(hubEdges.size).toBe(0) // degree 1 — no hubs yet

    // now make 'hub' a real hub
    const g2 = graph(
      [
        { id: 'host:hub', kind: 'host', label: 'hub' },
        { id: 'host:plain', kind: 'host', label: 'plain' },
        ...Array.from({ length: 16 }, (_, i) => ({ id: `host:n${i}`, kind: 'host', label: `n${i}` })),
      ],
      [
        ...Array.from({ length: 16 }, (_, i) => ({
          id: `he${i}`, source: 'host:hub', target: `host:n${i}`, relationship: 'FLOW', ...edgeBase,
        })),
        { id: 'e2', source: 'host:plain', target: 'host:hub', relationship: 'FLOW', ...edgeBase },
      ],
    )
    const m2 = computeNodeMetrics(g2)
    const hubEdges2 = hubEdgeIds(m2.degrees, g2)
    expect(hubEdges2.has('he0')).toBe(true)
    expect(hubEdges2.has('e2')).toBe(true)
  })

  it('scale tier curves hub edges, straightens the rest', () => {
    const hubEdges = new Set(['e1'])
    const curve = edgeCurveForTier('scale', hubEdges) as unknown as (edge: { id: () => string }) => string
    expect(typeof curve).toBe('function')
    expect(curve({ id: () => 'e1' })).toBe('bezier')
    expect(curve({ id: () => 'e2' })).toBe('straight')
    // non-scale tiers: flat bezier, not a function
    expect(edgeCurveForTier('balanced')).toBe('bezier')
    expect(edgeCurveForTier('detail')).toBe('bezier')
  })
})

describe('leafDomainIds', () => {
  it('returns degree<=1 domains only', () => {
    const g = graph(
      [
        { id: 'domain:leaf', kind: 'domain', label: 'leaf' },
        { id: 'domain:hub', kind: 'domain', label: 'hub' },
        { id: 'host:host1', kind: 'host', label: 'host1' },
        { id: 'host:host2', kind: 'host', label: 'host2' },
      ],
      [
        { id: 'e1', source: 'host:host1', target: 'domain:leaf', relationship: 'DNS_QUERY', ...edgeBase },
        { id: 'e2', source: 'host:host1', target: 'domain:hub', relationship: 'DNS_QUERY', ...edgeBase },
        { id: 'e3', source: 'host:host2', target: 'domain:hub', relationship: 'DNS_QUERY', ...edgeBase },
      ],
    )
    const m = computeNodeMetrics(g)
    const leaves = leafDomainIds(m, g)
    expect(leaves.has('domain:leaf')).toBe(true)
    expect(leaves.has('domain:hub')).toBe(false)
    expect(leaves.has('host:host1')).toBe(false)
  })
})

describe('layout + viewport per tier', () => {
  type AnyLayout = { quality?: string; animate?: boolean; gravity?: number; nodeRepulsion: (node?: any) => number }

  it('scale tier uses draft quality, no animation, lower gravity, degree-aware repulsion', () => {
    const l = layoutForTier(500, 'scale') as unknown as AnyLayout
    expect(l.quality).toBe('draft')
    expect(l.animate).toBe(false)
    expect(l.gravity).toBe(0.12)
    const l2 = layoutForTier(500, 'scale', new Map([['host:hub', 80]])) as unknown as AnyLayout
    expect(l2.nodeRepulsion({ data: (k: string) => (k === 'id' ? 'host:hub' : undefined) })).toBeGreaterThan(
      l2.nodeRepulsion({ data: (k: string) => (k === 'id' ? 'host:plain' : undefined) }),
    )
  })

  it('balanced keeps default animation and moderate gravity', () => {
    const l = layoutForTier(150, 'balanced') as unknown as AnyLayout
    expect(l.animate).toBe(true)
    expect(l.gravity).toBe(0.2)
  })

  it('detail tier is unchanged (no gravity override, flat repulsion)', () => {
    const l = layoutForTier(30, 'detail') as unknown as AnyLayout
    expect(l.nodeRepulsion()).toBe(9000)
    expect(l.gravity).toBeUndefined()
  })
})

// Shared edge fields the graph-scaling functions never touch — present so the
// fixture rows stay shape-complete (post-Phase-3 sweep will delta against these).
const edgeBase = {
  provenance: 'observed' as const,
  first_seen: 1700000000,
  last_seen: 1700000100,
  count: 1,
  packets: 1,
  bytes: 100,
  flow_ids: [],
  alert_ids: [],
  packet_refs: [],
}