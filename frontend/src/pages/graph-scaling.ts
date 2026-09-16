import type { GraphV2, GraphV2Node } from '../types/api'

/**
 * Adaptive-visualization logic for the evidence graph (v2).
 *
 * The graph renders in one of three tiers based on visible node count, so a
 * small PCAP stays fully detailed while a large capture automatically switches
 * to a scalable representation (draft layout, selective labels, collapsed
 * leaf nodes) instead of an unreadable hairball.
 */

export type Tier = 'detail' | 'balanced' | 'scale'

export const TIER_LIMITS = { balanced: 80, scale: 300 } as const

export function computeTier(visibleNodeCount: number): Tier {
  if (visibleNodeCount > TIER_LIMITS.scale) return 'scale'
  if (visibleNodeCount > TIER_LIMITS.balanced) return 'balanced'
  return 'detail'
}

/** node id → incident edge count (both directions). */
export function buildDegreeMap(graph: GraphV2): Map<string, number> {
  const deg = new Map<string, number>()
  for (const e of graph.edges) {
    deg.set(e.source, (deg.get(e.source) ?? 0) + 1)
    deg.set(e.target, (deg.get(e.target) ?? 0) + 1)
  }
  return deg
}

export const KIND_ALERT_WEIGHT = { host: 1, domain: 0.6, service: 0.6, alert: 0.4 } as const

/**
 * Importance score driving node size, label selection and top-N ordering.
 * Alert-flagged nodes dominate, then connectivity, then traffic volume.
 */
export function importanceScore(node: Pick<GraphV2Node, 'kind' | 'alert_count' | 'bytes_sent' | 'bytes_received'>, degree: number): number {
  let score = degree * 5
  const alerts = node.alert_count ?? 0
  if (alerts > 0) score += 100 * alerts
  const bytes = (node.bytes_sent ?? 0) + (node.bytes_received ?? 0)
  if (bytes > 0) score += 4 * Math.log2(1 + bytes)
  return score
}

export interface NodeMetrics {
  scores: Map<string, number>
  degrees: Map<string, number>
  /** node ids ranked by importance, highest first */
  ranked: string[]
}

export function computeNodeMetrics(graph: GraphV2): NodeMetrics {
  const degrees = buildDegreeMap(graph)
  const scores = new Map<string, number>()
  for (const n of graph.nodes) {
    scores.set(n.id, importanceScore(n, degrees.get(n.id) ?? 0))
  }
  const ranked = [...graph.nodes]
    .map((n) => n.id)
    .sort((a, b) => (scores.get(b) ?? 0) - (scores.get(a) ?? 0))
  return { scores, degrees, ranked }
}

/** Max label count per tier: detail shows everything, scale shows alerts only. */
export const LABEL_LIMITS: Record<Tier, number | null> = {
  detail: null,
  balanced: 40,
  scale: 0,
}

/**
 * Node ids whose labels are shown.
 * detail → all; balanced → top-40 + alerts; scale → alerts only (hover and
 * selection reveal the rest — permanent labels are the hairball's fuel).
 */
export function labeledNodeIds(metrics: NodeMetrics, tier: Tier, graph: GraphV2): Set<string> {
  const labeled = new Set<string>()
  for (const n of graph.nodes) {
    if ((n.alert_count ?? 0) > 0) labeled.add(n.id)
  }
  const limit = LABEL_LIMITS[tier]
  if (limit === null) {
    for (const n of graph.nodes) labeled.add(n.id)
    return labeled
  }
  if (limit === 0) return labeled
  for (const id of metrics.ranked) {
    if (labeled.size >= limit) break
    labeled.add(id)
  }
  return labeled
}

/** degree ≤ 1 domain/kind nodes — pure label noise at scale (DGA junk etc.). */
export function leafDomainIds(metrics: NodeMetrics, graph: GraphV2): Set<string> {
  const leaves = new Set<string>()
  for (const n of graph.nodes) {
    if (n.kind === 'domain' && (metrics.degrees.get(n.id) ?? 0) <= 1) {
      leaves.add(n.id)
    }
  }
  return leaves
}

/** Node size by importance: 18px floor … 44px cap. */
export function nodeSize(score: number): number {
  return Math.min(44, 18 + 4 * Math.log2(1 + Math.max(0, score)))
}

/** Degree from which a node is treated as a hub (fan-out zone). */
export const HUB_DEGREE = 15
/** Degree from which an edge is stretched away from its endpoint hub. */
export const HUB_EDGE_DEGREE = 20

/**
 * Degree-aware repulsion: hubs push neighbors up to 3x harder so their many
 * connections get breathing room instead of stacking on top of each other.
 */
export function repulsionFor(degree: number, base: number): number {
  return Math.round(base * (1 + Math.min(2, degree / 40)))
}

/** Edge-length multiplier: edges fanning out of a hub are stretched. */
export function hubEdgeFactor(degree: number): number {
  return degree > HUB_EDGE_DEGREE ? 1.3 : 1
}

/** Hub edges stretch more; regular edges keep fcose's springiness. */
export function elasticityFor(isHubEdge: boolean): number {
  return isHubEdge ? 0.3 : 0.45
}

/** Edges touching a hub node (degree > HUB_DEGREE) get curved at scale. */
export function hubEdgeIds(degrees: Map<string, number>, graph: GraphV2): Set<string> {
  const hubs = new Set<string>()
  for (const [id, deg] of degrees) {
    if (deg > HUB_DEGREE) hubs.add(id)
  }
  const ids = new Set<string>()
  for (const e of graph.edges) {
    if (hubs.has(e.source) || hubs.has(e.target)) {
      ids.add(e.id)
    }
  }
  return ids
}

/** Layout parameters scale with node count so large graphs keep spreading. */
export function layoutForTier(nodeCount: number, tier: Tier, degrees?: Map<string, number>) {
  const spread = Math.sqrt(nodeCount / 50)
  const deg = (node: { data: (k: string) => any }) => degrees?.get(node.data('id')) ?? 0
  const idealEdgeLength = (edge: { data: (k: string) => any, source: () => any, target: () => any }) => {
    const packetLen = (90 - Math.min(40, Math.log2(1 + (edge.data('packets') ?? 0)) * 10)) * Math.min(spread, 2)
    const srcDeg = degrees?.get(edge.source().id()) ?? 0
    const dstDeg = degrees?.get(edge.target().id()) ?? 0
    return (
      packetLen *
      hubEdgeFactor(srcDeg) *
      hubEdgeFactor(dstDeg)
    )
  }
  const edgeElasticity = (edge: { source: () => any, target: () => any }) => {
    const srcDeg = degrees?.get(edge.source().id()) ?? 0
    const dstDeg = degrees?.get(edge.target().id()) ?? 0
    return elasticityFor(srcDeg > HUB_EDGE_DEGREE || dstDeg > HUB_EDGE_DEGREE)
  }
  const common = {
    name: 'fcose' as const,
    padding: 30,
    idealEdgeLength,
    edgeElasticity,
  }
  if (tier === 'detail') {
    return {
      ...common,
      quality: 'default' as const,
      animate: true,
      animationDuration: 500,
      fit: true,
      nodeSeparation: 120,
      nodeRepulsion: () => 9000,
    }
  }
  if (tier === 'balanced') {
    return {
      ...common,
      quality: 'default' as const,
      animate: true,
      animationDuration: 400,
      fit: true,
      gravity: 0.2,
      nodeSeparation: Math.round(120 * Math.min(spread, 1.8)),
      nodeRepulsion: (node: { data: (k: string) => any }) =>
        repulsionFor(deg(node), 9000 * Math.min(spread, 1.8)),
    }
  }
  return {
    ...common,
    quality: 'draft' as const,
    animate: false,
    randomize: true,
    fit: true,
    gravity: 0.12,
    nodeSeparation: Math.round(120 * Math.min(spread, 2)),
    nodeRepulsion: (node: { data: (k: string) => any }) =>
      repulsionFor(deg(node), 9000 * Math.min(spread, 2)),
  }
}

/** Cytoscape viewport options for smooth pan/zoom at each tier. */
export function viewportForTier(tier: Tier) {
  if (tier === 'detail') {
    return {
      hideLabelsOnViewport: false,
      textureOnViewport: false,
      hideEdgesOnViewport: false,
      pixelRatio: undefined as number | undefined,
    }
  }
  return {
    hideLabelsOnViewport: true,
    textureOnViewport: tier === 'scale',
    hideEdgesOnViewport: tier === 'scale',
    pixelRatio: tier === 'scale' ? 1 : undefined,
  }
}

/**
 * Edge curve at scale: hub edges fan out as beziers so the many connections
 * around high-degree nodes don't overlap into one wedge; bulk edges stay
 * cheap straight lines. Balanced/detail keep bezier everywhere.
 */
export function edgeCurveForTier(tier: Tier, hubEdges?: Set<string>) {
  if (tier !== 'scale') return 'bezier' as const
  return (edge: { id: () => string }) => (hubEdges?.has(edge.id()) ? 'bezier' : 'straight') as 'bezier' | 'straight'
}