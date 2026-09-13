import { useEffect, useMemo, useRef, useState } from 'react'
import { X } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import fcose from 'cytoscape-fcose'
import { api } from '../api/client'
import { CapturePicker } from '../components/CapturePicker'
import { ErrorState } from '../components/states'
import { SkeletonRow, formatBytes } from '../components/ui'
import { useSelectedCapture } from '../hooks/captures'
import { useTheme } from '../hooks/theme'
import type { Graph, GraphNodeData } from '../types/api'
import {
  computeNodeMetrics,
  computeTier,
  edgeCurveForTier,
  hubEdgeIds,
  labeledNodeIds,
  layoutForTier,
  leafDomainIds,
  nodeSize,
  viewportForTier,
  HUB_DEGREE,
} from './graph-scaling'

cytoscape.use(fcose)

// Theme-aware palette: same hue identities across themes (sky=host/DNS,
// violet=domain/TLS, emerald=service/EXPOSES, amber=HTTP) but each theme
// gets values tuned for its canvas — dark-mode brights / light-mode deeps.
const DARK_PALETTE = {
  nodeFills: { host: '#1e293b', domain: '#1e1b2e', service: '#17251f' },
  label: '#94a3b8',
  fallbackEdge: '#f472b6',
  edges: {
    DNS: '#38bdf8',
    RESOLVES_TO: '#64748b',
    HTTP: '#fbbf24',
    HTTPS: '#fbbf24',
    TLS: '#a78bfa',
    TCP: '#475569',
    UDP: '#7c3aed',
    EXPOSES: '#34d399',
  },
}

const LIGHT_PALETTE = {
  nodeFills: { host: '#e0f2fe', domain: '#ede9fe', service: '#d1fae5' },
  label: '#64748b',
  fallbackEdge: '#db2777',
  edges: {
    DNS: '#0284c7',
    RESOLVES_TO: '#94a3b8',
    HTTP: '#d97706',
    HTTPS: '#d97706',
    TLS: '#7c3aed',
    TCP: '#94a3b8',
    UDP: '#6d28d9',
    EXPOSES: '#059669',
  },
}

const nodeBorderColor = (type: string, theme: string) =>
  theme === 'light'
    ? { host: '#0284c7', domain: '#7c3aed', service: '#059669' }[type] ?? '#0284c7'
    : { host: '#38bdf8', domain: '#a78bfa', service: '#34d399' }[type] ?? '#38bdf8'

const KNOWN_EDGE_TYPES = ['DNS', 'RESOLVES_TO', 'HTTP', 'TLS', 'TCP', 'UDP', 'EXPOSES']
// HTTP and HTTPS share a color/toggle; HTTPS maps onto the HTTP filter
const filterForEdge = (type: string) => (type === 'HTTPS' ? 'HTTP' : type)
const edgeColor = (type: string, palette: GraphPalette): string =>
  (palette.edges as Record<string, string>)[type] ?? palette.fallbackEdge
const edgeLabel = (type: string) =>
  type === 'RESOLVES_TO' ? 'resolves to' : type.toLowerCase()

type EdgeGroup = { key: string; color: string; label: string; count: number }

type GraphPalette = typeof DARK_PALETTE

// Group the actual edge types found in this graph into toggle entries:
// known types get their canonical toggle; anything else (QUIC, C2-PORT, …)
// becomes its own toggle so no edge is implicitly hidden.
function buildEdgeGroups(graph: Graph, palette: GraphPalette): EdgeGroup[] {
  const counts = new Map<string, { count: number; original: string }>()
  for (const e of graph.edges) {
    const key = filterForEdge(e.data.type)
    const cur = counts.get(key)
    if (cur) {
      cur.count += 1
    } else {
      counts.set(key, { count: 1, original: e.data.type })
    }
  }
  const groups: EdgeGroup[] = [...KNOWN_EDGE_TYPES, ...[...counts.keys()].filter(
    (k) => !KNOWN_EDGE_TYPES.includes(k),
  )]
    .filter((key) => counts.has(key))
    .map((key) => {
      const { count } = counts.get(key)!
      return { key, color: edgeColor(key, palette), label: edgeLabel(key), count }
    })
  return groups
}

interface VisibleElements {
  elements: ElementDefinition[]
  visibleIds: Set<string>
  hiddenLeafCount: number
  tier: 'detail' | 'balanced' | 'scale'
}

export function GraphPage() {
  const { analyzed, effectiveCaptureId, setCaptureId } = useSelectedCapture()
  const { theme } = useTheme()
  const palette = theme === 'light' ? LIGHT_PALETTE : DARK_PALETTE
  const [selectedNode, setSelectedNode] = useState<GraphNodeData | null>(null)
  const [edgeFilters, setEdgeFilters] = useState<Set<string> | null>(null)
  const [nodeFilters, setNodeFilters] = useState<Set<string>>(
    () => new Set(['domain', 'service']),
  )
  const [showLeaves, setShowLeaves] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const cyCaptureRef = useRef<string | null>(null)

  const { data: graph, isError, refetch } = useQuery({
    queryKey: ['graph', effectiveCaptureId],
    queryFn: () => api.getGraph(effectiveCaptureId!),
    enabled: !!effectiveCaptureId,
  })

  const edgeGroups = useMemo(
    () => (graph ? buildEdgeGroups(graph, palette) : []),
    [graph, palette],
  )
  const metrics = useMemo(() => (graph ? computeNodeMetrics(graph) : null), [graph])
  const leaves = useMemo(() => (graph && metrics ? leafDomainIds(metrics, graph) : null), [graph, metrics])

  // null = all enabled (fresh capture); user toggles carve out exclusions.
  // Memoized: a fresh Set every render would recompute `visible` and re-run
  // the cytoscape diff/stylesheet effect on every unrelated state change.
  const activeEdgeFilters = useMemo(
    () => edgeFilters ?? new Set(edgeGroups.map((g) => g.key)),
    [edgeFilters, edgeGroups],
  )
  const toggleEdgeFilter = (key: string) => {
    setEdgeFilters(toggleInSet(activeEdgeFilters, key))
  }

  // Visible elements after node/edge filters and (at scale) leaf collapsing.
  // Tier is decided from the PRE-collapse node count — collapsing leaves is
  // what the scale tier does, so it can't depend on its own output.
  const visible = useMemo<VisibleElements>(() => {
    if (!graph) return { elements: [], visibleIds: new Set(), hiddenLeafCount: 0, tier: 'detail' }
    const preCollapseTier = tierOf(graph, nodeFilters)
    const collapseLeaves = !showLeaves && preCollapseTier === 'scale'
    const nodes = graph.nodes.filter((n) => {
      if (n.data.type !== 'host' && n.data.type && !nodeFilters.has(n.data.type)) return false
      if (collapseLeaves && leaves?.has(n.data.id)) return false
      return true
    })
    const nodeIds = new Set(nodes.map((n) => n.data.id))
    const edges = graph.edges.filter(
      (e) =>
        activeEdgeFilters.has(filterForEdge(e.data.type)) &&
        nodeIds.has(e.data.source) &&
        nodeIds.has(e.data.target),
    )
    // count only domain-type leaves actually excluded by collapsing (not ones
    // already hidden by the node-type filter — "show" can't reveal those)
    const hiddenLeafCount =
      collapseLeaves && leaves
        ? [...leaves].filter((id) => {
            const n = graph.nodes.find((node) => node.data.id === id)
            return !!n && n.data.type === 'domain' && !nodeIds.has(id)
          }).length
        : 0
    return {
      elements: [
        ...nodes.map((n) => ({ data: { ...n.data } })),
        ...edges.map((e) => ({ data: { ...e.data } })),
      ] as ElementDefinition[],
      visibleIds: nodeIds,
      hiddenLeafCount,
      tier: collapseLeaves
        ? 'scale'
        : computeTier(nodeIds.size || 1),
    }
  }, [graph, nodeFilters, activeEdgeFilters, showLeaves, leaves])

  const tier = visible.tier

  // Fresh capture → reset user overrides
  useEffect(() => {
    setEdgeFilters(null)
    setShowLeaves(false)
    setSelectedNode(null)
  }, [effectiveCaptureId])

  // Persistent instance per capture: filter toggles diff elements in/out and
  // run an incremental layout instead of destroying the whole graph, so zoom
  // position survives and big graphs stay responsive.
  useEffect(() => {
    if (!graph || !metrics || !containerRef.current) return

    const isNewCapture = cyRef.current === null || cyCaptureRef.current !== effectiveCaptureId
    const labeled = labeledNodeIds(metrics, tier, graph)
    const hubEdges = tier === 'scale' ? hubEdgeIds(metrics.degrees, graph) : new Set<string>()
    const curveStyle = edgeCurveForTier(tier, hubEdges)

    const cyStyle: cytoscape.StylesheetStyle[] = [
      {
        selector: 'node',
        style: {
          label: (ele: any) => (labeled.has(ele.data('id')) ? ele.data('label') : ''),
          'background-color': (ele: { data: (k: string) => any }) =>
            palette.nodeFills[ele.data('type') as keyof typeof palette.nodeFills] ?? palette.nodeFills.host,
          'border-color': (ele: { data: (k: string) => any }) =>
            ele.data('alert_count') > 0
              ? '#ef4444'
              : nodeBorderColor(ele.data('type'), theme),
          'border-width': (ele: { data: (k: string) => any }) =>
            ele.data('alert_count') > 0 ? 3 : 1.5,
          color: palette.label,
          'font-size': 9,
          'font-family': "'JetBrains Mono Variable', ui-monospace, monospace",
          width: (ele: any) => nodeSize(metrics.scores.get(ele.data('id')) ?? 0),
          height: (ele: any) => nodeSize(metrics.scores.get(ele.data('id')) ?? 0),
          'min-zoomed-font-size': 9,
        },
      },
      {
        selector: 'node:selected',
        style: { 'border-width': 4, 'border-color': '#f59e0b', label: 'data(label)' },
      },
      {
        selector: 'node.highlighted',
        style: { label: 'data(label)', 'z-index': 9999 },
      },
      {
        selector: 'edge',
        style: {
          width: (ele: { data: (k: string) => number }) =>
            Math.min(1 + Math.log2(1 + (ele.data('packets') ?? 1)), 6),
          'line-color': (ele: { data: (k: string) => any }) =>
            edgeColor(ele.data('type'), palette),
          'target-arrow-shape': 'triangle',
          'arrow-scale': 0.7,
          'curve-style': curveStyle,
          opacity: 0.75,
        },
      },
      {
        selector: 'edge:selected',
        style: { opacity: 1, width: 4 },
      },
    ]

    if (isNewCapture) {
      cyRef.current?.destroy()
      const cy = cytoscape({
        container: containerRef.current,
        elements: visible.elements,
        style: cyStyle,
        layout: layoutForTier(visible.visibleIds.size, tier, metrics.degrees),
        ...viewportForTier(tier),
      })
      cy.on('tap', 'node', (e) => {
        setSelectedNode(e.target.data() as GraphNodeData)
      })
      cy.on('tap', 'edge', () => setSelectedNode(null))
      cy.on('mouseover', 'node', (e) => e.target.addClass('highlighted'))
      cy.on('mouseout', 'node', (e) => e.target.removeClass('highlighted'))
      cyRef.current = cy
      cyCaptureRef.current = effectiveCaptureId
      cy.fit(undefined, 30)
    } else {
      const cy = cyRef.current
      if (!cy) return

      // diff: remove vanished, add new, keep positions of survivors
      const wanted = new Set(visible.elements.map((el) => el.data.id))
      const toRemove = cy.elements().filter((el: any) => !wanted.has(el.data().id))
      const existing = new Set(cy.elements().map((el: any) => el.data().id))
      const toAdd = visible.elements.filter((el) => !existing.has(el.data.id))
      if (toRemove.length > 0) cy.remove(toRemove)

      const addedNodes = toAdd.filter((el: any) => 'source' in el.data === false && 'target' in el.data === false)
      if (addedNodes.length > 0) {
        cy.add(toAdd)
        // Seed new nodes beside a connected neighbor when possible; fcose's
        // incremental (randomize:false) path crashes on added nodes, so small
        // deltas are positioned locally and only large deltas re-layout.
        // Hub-adjacent nodes fan out at an angle around the hub instead of
        // jittering on top of each other.
        const smallDelta = addedNodes.length <= 30
        if (smallDelta) {
          const seedFan = new Map<string, number>() // hub id → next angle slot
          for (const el of addedNodes) {
            const node = cy.getElementById(String(el.data.id))
            if (node.empty() || !node.isNode()) continue
            const edge = node.connectedEdges()[0]
            if (!edge || edge.empty()) {
              node.position({ x: Math.random() * 200 - 100, y: Math.random() * 200 - 100 })
              continue
            }
            const other = edge.source().id() === node.id() ? edge.target() : edge.source()
            const base = other.position()
            const isHub = (metrics.degrees.get(other.id()) ?? 0) > HUB_DEGREE
            if (isHub) {
              const slot = seedFan.get(other.id()) ?? 0
              seedFan.set(other.id(), slot + 1)
              const angle = (slot / 8) * 2 * Math.PI + (node.id().charCodeAt(0) % 10) / 10
              const radius = nodeSize(metrics.scores.get(other.id()) ?? 0) + 70
              node.position({
                x: base.x + Math.cos(angle) * radius,
                y: base.y + Math.sin(angle) * radius,
              })
            } else {
              node.position({ x: base.x + (Math.random() * 60 - 30), y: base.y + (Math.random() * 60 - 30) })
            }
          }
        } else {
          try {
            cy.layout(layoutForTier(visible.visibleIds.size, tier, metrics.degrees)).run()
          } catch {
            // layout is cosmetic; never let it take the page down
          }
          cy.fit(undefined, 30)
        }
      } else if (toAdd.length > 0) {
        cy.add(toAdd)
      }
      cy.style().fromJson(cyStyle)
    }
  }, [visible, tier, metrics, graph, effectiveCaptureId, palette, theme])

  // container ref may not be mounted on first effect run for a new capture
  useEffect(() => {
    return () => {
      cyRef.current?.destroy()
      cyRef.current = null
      cyCaptureRef.current = null
    }
  }, [])

  return (
    <div className="flex h-full flex-col p-8">
      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <h1 className="text-2xl font-semibold text-fg">Network Graph</h1>
        {graph && (
          <span className="text-xs text-fg-subtle">
            {graph.stats.host_count} hosts · {graph.stats.domain_count} domains ·{' '}
            {graph.stats.service_count} services · {graph.stats.edge_count} edges
            <span className="ml-2 rounded bg-surface-3 px-1.5 py-0.5 text-xs text-fg-muted">
              {tier}
            </span>
          </span>
        )}
        <div className="ml-auto">
          <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={setCaptureId} />
        </div>
      </div>

      <div className="relative flex-1 overflow-hidden rounded-xl border border-border bg-bg">
        <div ref={containerRef} className="h-full w-full" />

        {/* legend / filters */}
        <div className="absolute left-3 top-3 space-y-1 rounded-lg bg-surface-2/90 p-3 text-xs ring-1 ring-border">
          <div className="mb-1 font-medium text-fg-muted">Edges</div>
          {edgeGroups.map((g) => {
            const active = activeEdgeFilters.has(g.key)
            return (
              <button
                key={g.key}
                onClick={() => toggleEdgeFilter(g.key)}
                className={`flex items-center gap-2 text-left transition-opacity ${
                  active ? 'text-fg-subtle' : 'text-fg-subtle opacity-40'
                }`}
              >
                <span
                  className="inline-block h-0.5 w-5"
                  style={{ background: g.color, opacity: active ? 1 : 0.3 }}
                />
                <span className="flex-1">{g.label}</span>
                <span className="text-fg-subtle">{g.count}</span>
              </button>
            )
          })}
          <div className="mt-2 mb-1 font-medium text-fg-muted">Nodes</div>
          {(
            [
              ['host', 'host', nodeBorderColor('host', theme)],
              ['domain', 'domain', nodeBorderColor('domain', theme)],
              ['service', 'service', nodeBorderColor('service', theme)],
            ] as const
          ).map(([type, label, ring]) => {
            const active = type === 'host' || nodeFilters.has(type)
            return (
              <button
                key={type}
                disabled={type === 'host'}
                onClick={() => setNodeFilters(toggleInSet(nodeFilters, type))}
                className={`flex items-center gap-2 text-left transition-opacity ${
                  active ? 'text-fg-subtle' : 'text-fg-subtle opacity-40'
                }`}
              >
                <span
                  className="h-3 w-3 rounded-full ring-1"
                  style={{ boxShadow: `inset 0 0 0 1px ${ring}`, opacity: active ? 1 : 0.3 }}
                />
                {label}
              </button>
            )
          })}
          {visible.hiddenLeafCount > 0 && (
            <button
              onClick={() => setShowLeaves(true)}
              className="mt-2 block w-full rounded border border-border-strong px-1.5 py-1 text-left text-fg-muted hover:border-fg-subtle hover:text-fg"
            >
              {visible.hiddenLeafCount} leaf domains hidden — show
            </button>
          )}
          <div className="mt-2 border-t border-border pt-1.5 text-fg-subtle">
            {visible.elements.length > 0
              ? `${visible.elements.length} shown`
              : 'nothing matches filters'}
          </div>
        </div>

        {!graph && !isError && (
          <div
            className="absolute inset-0 flex items-center justify-center"
            role="status"
            aria-label="Building graph…"
          >
            <span className="sr-only">Building graph…</span>
            {analyzed.length ? (
              <div className="h-full w-full p-12" aria-hidden>
                <div className="relative h-full w-full overflow-hidden rounded-lg">
                  {/* scattered node placeholders across the viewport */}
                  {[
                    'left-[15%] top-[22%]',
                    'left-[68%] top-[18%]',
                    'left-[42%] top-[45%]',
                    'left-[80%] top-[55%]',
                    'left-[25%] top-[68%]',
                    'left-[58%] top-[78%]',
                  ].map((pos) => (
                    <div
                      key={pos}
                      className={`absolute ${pos} flex items-center gap-3`}
                    >
                      <SkeletonRow className="h-10 w-10 rounded-full" />
                      <SkeletonRow className="w-24" />
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <span className="text-sm text-fg-subtle">No analyzed captures yet.</span>
            )}
          </div>
        )}
        {isError && !graph && (
          <div className="absolute inset-0 flex items-center justify-center">
            <ErrorState message="Graph request failed." onRetry={() => void refetch()} />
          </div>
        )}

        {/* Node detail panel */}
        {selectedNode && (
          <div className="absolute right-3 top-3 z-10 w-72 rounded-xl border border-border-strong bg-surface-2/95 p-4 shadow-xl">
            <div className="mb-2 flex items-start justify-between">
              <div className="font-mono text-sm font-semibold text-fg">
                {selectedNode.id}
              </div>
              <button onClick={() => setSelectedNode(null)} aria-label="Close" className="text-fg-subtle hover:text-fg-muted">
                <X size={16} aria-hidden />
              </button>
            </div>
            <div className="space-y-1.5 text-xs">
              <Row label="Type" value={selectedNode.type ?? '—'} />
              {selectedNode.hostname && <Row label="Hostname" value={selectedNode.hostname} />}
              {selectedNode.role && <Row label="Role" value={selectedNode.role} />}
              {selectedNode.type === 'host' && (
                <>
                  <Row
                    label="Traffic"
                    value={`↑ ${formatBytes(selectedNode.bytes_sent ?? 0)} · ↓ ${formatBytes(
                      selectedNode.bytes_received ?? 0,
                    )}`}
                  />
                  <Row
                    label="Alerts"
                    value={String(selectedNode.alert_count ?? 0)}
                    tone={(selectedNode.alert_count ?? 0) > 0 ? 'red' : undefined}
                  />
                </>
              )}
              {selectedNode.type === 'service' && (
                <>
                  <Row label="Service" value={selectedNode.service ?? '—'} />
                  <Row label="Port" value={String(selectedNode.port ?? '—')} />
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// tier before `visible` exists (used to decide leaf collapsing)
function tierOf(graph: Graph, nodeFilters: Set<string>): 'detail' | 'balanced' | 'scale' {
  const kept = graph.nodes.filter(
    (n) => n.data.type === 'host' || !n.data.type || nodeFilters.has(n.data.type),
  )
  return computeTier(kept.length)
}

function toggleInSet(current: Iterable<string>, name: string): Set<string> {
  const next = new Set(current)
  if (next.has(name)) {
    next.delete(name)
  } else {
    next.add(name)
  }
  return next
}

function Row({ label, value, tone }: { label: string; value: string; tone?: 'red' }) {
  return (
    <div className="flex justify-between gap-2">
      <span className="text-fg-subtle">{label}</span>
      <span className={`font-mono ${tone === 'red' ? 'text-danger' : 'text-fg-muted'}`}>
        {value}
      </span>
    </div>
  )
}
