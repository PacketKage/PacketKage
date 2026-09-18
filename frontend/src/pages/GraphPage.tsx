import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import cytoscape, {
  type Core,
  type EdgeSingular,
  type ElementDefinition,
  type NodeSingular,
} from 'cytoscape'
import fcose from 'cytoscape-fcose'
import { api } from '../api/client'
import { CapturePicker } from '../components/CapturePicker'
import { ErrorState } from '../components/states'
import { Badge, SkeletonRow, Spinner } from '../components/ui'
import { useSelectedCapture } from '../hooks/captures'
import { useTheme } from '../hooks/theme'
import { useT } from '../i18n/LocaleContext'
import type {
  GraphNodeKind,
  GraphProvenance,
  GraphV2,
  GraphV2Edge,
} from '../types/api'
import {
  EdgeProvenancePanel,
  EvidenceChainList,
  NodeDetailPanel,
} from './graph-v2-panels'
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
  type Tier,
} from './graph-scaling'

cytoscape.use(fcose)

// Theme-aware palettes. Node kind colors stay identical across themes (sky=host,
// violet=domain, emerald=service, red=alert, orange=incident, pink=case,
// teal=capture); fills swap dark-deep / light-wash per theme.
type KindStyle = { color: string; fill: string; shape: cytoscape.Css.NodeShape }

const KIND_COLORS: Record<GraphNodeKind, string> = {
  host: '#38bdf8',
  domain: '#a78bfa',
  service: '#34d399',
  alert: '#ef4444',
  incident: '#fb923c',
  case: '#f472b6',
  capture: '#2dd4bf',
}

const KIND_FILLS_DARK: Record<GraphNodeKind, string> = {
  host: '#1e293b',
  domain: '#1e1b2e',
  service: '#17251f',
  alert: '#3b0f14',
  incident: '#3b2008',
  case: '#3b1130',
  capture: '#0f2e2c',
}

const KIND_FILLS_LIGHT: Record<GraphNodeKind, string> = {
  host: '#e0f2fe',
  domain: '#ede9fe',
  service: '#d1fae5',
  alert: '#fee2e2',
  incident: '#ffedd5',
  case: '#fce7f3',
  capture: '#ccfbf1',
}

const KIND_SHAPES: Record<GraphNodeKind, cytoscape.Css.NodeShape> = {
  host: 'ellipse',
  domain: 'diamond',
  service: 'hexagon',
  alert: 'triangle',
  incident: 'octagon',
  case: 'round-rectangle',
  capture: 'rectangle',
}

// relationship → edge color; anything not listed falls back to a neutral.
const RELATIONSHIP_COLORS: Record<string, string> = {
  FLOW: '#475569',
  DNS_QUERY: '#38bdf8',
  RESOLVES_TO: '#64748b',
  TLS_SNI: '#a78bfa',
  HTTP_HOST: '#fbbf24',
  EXPOSES: '#34d399',
  TRIGGERED: '#ef4444',
  TARGETS: '#fb923c',
  GROUPS: '#f472b6',
  INCLUDES: '#e879f9',
}

// provenance → line style: solid = seen in traffic, dashed = correlation,
// dotted = enrichment/inference.
const PROVENANCE_LINE: Record<GraphProvenance, 'solid' | 'dashed' | 'dotted'> = {
  observed: 'solid',
  correlated: 'dashed',
  enriched: 'dotted',
}

const RELATIONSHIP_KEYS: Record<string, string> = {
  DNS_QUERY: 'graph.relationship.dns_query',
  RESOLVES_TO: 'graph.relationship.resolves_to',
  TLS_SNI: 'graph.relationship.tls_sni',
  HTTP_HOST: 'graph.relationship.http_host',
  FLOW: 'graph.relationship.flow',
  EXPOSES: 'graph.relationship.exposes',
  TRIGGERED: 'graph.relationship.triggered',
  TARGETS: 'graph.relationship.targets',
  GROUPS: 'graph.relationship.groups',
  INCLUDES: 'graph.relationship.includes',
}

const PROV_KEYS: Record<GraphProvenance, string> = {
  observed: 'graph_panels.provenance.observed',
  correlated: 'graph_panels.provenance.correlated',
  enriched: 'graph_panels.provenance.enriched',
}

const relationshipLabel = (r: string, t: (key: string) => string) =>
  RELATIONSHIP_KEYS[r] ? t(RELATIONSHIP_KEYS[r]) : r.replaceAll('_', ' ').toLowerCase()

// Backend caps (mirrors GraphCaps in evidence_graph.py).
const CANVAS_DEFAULT_LIMIT = 300
const CANVAS_HARD_LIMIT = 1000

type RelationGroup = { relationship: string; color: string; label: string; count: number }

function buildRelationGroups(graph: GraphV2, t: (key: string) => string): RelationGroup[] {
  const counts = new Map<string, number>()
  for (const e of graph.edges) {
    counts.set(e.relationship, (counts.get(e.relationship) ?? 0) + 1)
  }
  return [...counts.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([relationship, count]) => ({
      relationship,
      color: RELATIONSHIP_COLORS[relationship] ?? '#94a3b8',
      label: relationshipLabel(relationship, t),
      count,
    }))
}

function kindStyle(kind: GraphNodeKind, theme: string): KindStyle {
  return {
    color: KIND_COLORS[kind] ?? '#94a3b8',
    fill: (theme === 'light' ? KIND_FILLS_LIGHT : KIND_FILLS_DARK)[kind] ?? '#1e293b',
    shape: KIND_SHAPES[kind] ?? 'ellipse',
  }
}

function presentKinds(graph: GraphV2): Set<GraphNodeKind> {
  return new Set(graph.nodes.map((n) => n.kind))
}

function presentProvenance(graph: GraphV2): Set<GraphProvenance> {
  return new Set(graph.edges.map((e) => e.provenance))
}

function toggleInSet<T extends string>(current: Iterable<T>, name: T): Set<T> {
  const next = new Set<T>(current)
  if (next.has(name)) {
    next.delete(name)
  } else {
    next.add(name)
  }
  return next
}

export type GraphMode = 'investigate' | 'attack-path' | 'blast' | 'timeline' | 'evidence'

const MODES: { id: GraphMode; labelKey: string }[] = [
  { id: 'investigate', labelKey: 'graph.mode.investigate' },
  { id: 'attack-path', labelKey: 'graph.mode.attack_path' },
  { id: 'blast', labelKey: 'graph.mode.blast' },
  { id: 'timeline', labelKey: 'graph.mode.timeline' },
  { id: 'evidence', labelKey: 'graph.mode.evidence' },
]

/**
 * Graph 2.0 workspace: five investigation modes over one capture.
 * The Investigate canvas renders Graph v2 natively — node/edge ids ARE the
 * v2 ids (`host:…`, `domain:…`, `alert:…`, …) — so selection flows straight
 * into the v2 detail panels with no id rewriting.
 */
export function GraphPage() {
  const { analyzed, effectiveCaptureId, setCaptureId } = useSelectedCapture()
  const [mode, setMode] = useState<GraphMode>('investigate')
  const t = useT()

  return (
    <div className="flex h-full flex-col p-8">
      {/* header: title + capture picker */}
      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <h1 className="text-2xl font-semibold text-fg">{t('graph.title')}</h1>
        {analyzed.length > 0 && (
          <span className="text-xs text-fg-subtle">{t('graph.subtitle')}</span>
        )}
        <div className="ml-auto">
          <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={setCaptureId} />
        </div>
      </div>

      {/* mode toolbar */}
      <div className="mb-4 flex flex-wrap gap-1.5" role="tablist" aria-label={t('graph.modes_aria')}>
        {MODES.map((m) => (
          <button
            key={m.id}
            role="tab"
            aria-selected={mode === m.id}
            onClick={() => setMode(m.id)}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium ring-1 transition ${
              mode === m.id
                ? 'bg-accent-soft text-accent ring-accent-ring'
                : 'text-fg-muted ring-border-strong hover:text-fg'
            }`}
          >
            {t(m.labelKey)}
          </button>
        ))}
      </div>

      {/* mode content */}
      <div className="min-h-0 flex-1">
        {mode === 'investigate' && (
          <InvestigateCanvas onModeChange={setMode} captureId={effectiveCaptureId} />
        )}
        {mode === 'attack-path' && <AttackPathMode captureId={effectiveCaptureId} />}
        {mode === 'blast' && <BlastRadiusMode captureId={effectiveCaptureId} />}
        {mode === 'timeline' && <TimelineMode captureId={effectiveCaptureId} />}
        {mode === 'evidence' && <EvidenceMode captureId={effectiveCaptureId} />}
      </div>
    </div>
  )
}

// ---------------- Attack Path mode ----------------

function AttackPathMode({ captureId }: { captureId: string | null }) {
  const t = useT()
  const { data: graph } = useQuery({
    queryKey: ['evidenceGraph', captureId],
    queryFn: () => api.getEvidenceGraph(captureId!),
    enabled: !!captureId,
  })
  const hosts = (graph?.nodes ?? []).filter((n) => n.kind === 'host')
  const [source, setSource] = useState('')
  const [target, setTarget] = useState('')
  const [query, setQuery] = useState<{ source: string; target: string } | null>(null)

  const { data: paths, isLoading, isError } = useQuery({
    queryKey: ['graphPaths', captureId, query?.source, query?.target],
    queryFn: () => api.getGraphPaths(captureId!, query!.source, query!.target),
    enabled: !!query && !!captureId,
  })

  if (!graph) {
    return (
      <div className="flex h-full min-h-[240px] items-center justify-center">
        <Spinner size={24} />
      </div>
    )
  }
  if (!hosts.length) {
    return <ErrorlessEmpty text={t('graph.attack.no_hosts')} />
  }
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3 rounded-xl border border-border bg-surface-2/50 p-4">
        <label className="text-xs text-fg-subtle">
          {t('graph.attack.source')}
          <select
            aria-label={t('graph.attack.source')}
            value={source}
            onChange={(e) => setSource(e.target.value)}
            className="mt-1 block rounded-lg border border-border-strong bg-surface-2 px-2 py-1.5 text-xs text-fg"
          >
            <option value="">{t('common.select')}</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>{h.label}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-fg-subtle">
          {t('graph.attack.target')}
          <select
            aria-label={t('graph.attack.target')}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="mt-1 block rounded-lg border border-border-strong bg-surface-2 px-2 py-1.5 text-xs text-fg"
          >
            <option value="">{t('common.select')}</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>{h.label}</option>
            ))}
          </select>
        </label>
        <button
          disabled={!source || !target || source === target}
          onClick={() => setQuery({ source, target })}
          className="rounded-lg bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent ring-1 ring-accent/30 transition hover:bg-accent/20 disabled:pointer-events-none disabled:opacity-50"
        >
          {t('graph.attack.find_paths')}
        </button>
        <p className="ml-auto max-w-sm text-xs text-fg-subtle">{t('graph.attack.hint')}</p>
      </div>

      {isLoading && <div className="p-6 text-center"><Spinner size={20} /></div>}
      {isError && <ErrorState message={t('graph.attack.search_failed')} />}
      {paths && (
        <div className="space-y-3">
          {paths.paths.length === 0 && (
            <ErrorlessEmpty
              text={
                paths.reason === 'unknown node'
                  ? t('graph.attack.unknown_node')
                  : t('graph.attack.no_path')
              }
            />
          )}
          {paths.paths.map((p, i) => (
            <div key={i} className="rounded-xl border border-border bg-surface-2/50 p-4">
              <div className="mb-2 flex items-center gap-2">
                <Badge tone="accent">{t('graph.attack.path', { n: i + 1 })}</Badge>
                <Badge tone="neutral">{t('graph.attack.hops', { count: p.length })}</Badge>
                <Badge tone="warning">{t('graph.attack.inferred')}</Badge>
              </div>
              <ol className="flex flex-wrap items-center gap-2">
                {p.nodes.map((nid, j) => {
                  const node = graph.nodes.find((n) => n.id === nid)
                  return (
                    <li key={nid} className="flex items-center gap-2">
                      <span className="rounded-lg bg-surface-3/60 px-2 py-1 font-mono text-xs text-fg-muted ring-1 ring-border">
                        {node?.label ?? nid}
                      </span>
                      {j < p.nodes.length - 1 && <span className="text-fg-subtle">→</span>}
                    </li>
                  )
                })}
              </ol>
            </div>
          ))}
          {paths.truncated && (
            <p className="text-xs text-fg-subtle">{t('graph.attack.truncated')}</p>
          )}
        </div>
      )}
    </div>
  )
}

// ---------------- Blast Radius mode ----------------

function BlastRadiusMode({ captureId }: { captureId: string | null }) {
  const t = useT()
  const { data: graph } = useQuery({
    queryKey: ['evidenceGraph', captureId],
    queryFn: () => api.getEvidenceGraph(captureId!),
    enabled: !!captureId,
  })
  const hosts = (graph?.nodes ?? []).filter((n) => n.kind === 'host')
  const [host, setHost] = useState('')
  const [depth, setDepth] = useState(2)
  const [query, setQuery] = useState<{ host: string; depth: number } | null>(null)

  const { data: blast, isLoading, isError } = useQuery({
    queryKey: ['graphBlast', captureId, query?.host, query?.depth],
    queryFn: () => api.getGraphBlast(captureId!, query!.host, query!.depth),
    enabled: !!query && !!captureId,
  })

  if (!graph) {
    return (
      <div className="flex h-full min-h-[240px] items-center justify-center">
        <Spinner size={24} />
      </div>
    )
  }
  if (!hosts.length) {
    return <ErrorlessEmpty text={t('graph.blast.no_hosts')} />
  }
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3 rounded-xl border border-border bg-surface-2/50 p-4">
        <label className="text-xs text-fg-subtle">
          {t('graph.blast.start')}
          <select
            aria-label={t('graph.blast.aria_start')}
            value={host}
            onChange={(e) => setHost(e.target.value)}
            className="mt-1 block rounded-lg border border-border-strong bg-surface-2 px-2 py-1.5 text-xs text-fg"
          >
            <option value="">{t('common.select')}</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>{h.label}</option>
            ))}
          </select>
        </label>
        <label className="text-xs text-fg-subtle">
          {t('graph.blast.depth')}
          <select
            aria-label={t('graph.blast.aria_depth')}
            value={depth}
            onChange={(e) => setDepth(Number(e.target.value))}
            className="mt-1 block rounded-lg border border-border-strong bg-surface-2 px-2 py-1.5 text-xs text-fg"
          >
            <option value={1}>1</option>
            <option value={2}>2</option>
            <option value={3}>3</option>
          </select>
        </label>
        <button
          disabled={!host}
          onClick={() => setQuery({ host, depth })}
          className="rounded-lg bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent ring-1 ring-accent/30 transition hover:bg-accent/20 disabled:pointer-events-none disabled:opacity-50"
        >
          {t('graph.blast.compute')}
        </button>
        <p className="ml-auto max-w-sm text-xs text-fg-subtle">{t('graph.blast.hint')}</p>
      </div>

      {isLoading && <div className="p-6 text-center"><Spinner size={20} /></div>}
      {isError && <ErrorState message={t('graph.blast.failed')} />}
      {blast && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <SummaryCard label={t('graph.blast.reachable')} value={blast.summary.reachable_nodes} />
            <SummaryCard label={t('graph.blast.alert_flagged')} value={blast.summary.alert_flagged.length} tone="red" />
            <SummaryCard label={t('graph.blast.hosts')} value={blast.summary.by_kind.host ?? 0} />
            <SummaryCard label={t('graph.blast.domains')} value={blast.summary.by_kind.domain ?? 0} />
          </div>
          {Object.entries(blast.rings)
            .sort(([a], [b]) => Number(a) - Number(b))
            .map(([ring, ids]) => (
              <div key={ring} className="rounded-xl border border-border bg-surface-2/50 p-4">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-fg-subtle">
                  {t('graph.blast.hop', { ring, count: ids.length })}
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {ids.map((nid) => {
                    const node = graph.nodes.find((n) => n.id === nid)
                    const flagged = blast.summary.alert_flagged.includes(nid)
                    return (
                      <span
                        key={nid}
                        className={`rounded-lg px-2 py-1 font-mono text-xs ring-1 ${
                          flagged
                            ? 'bg-danger/10 text-danger ring-danger/30'
                            : 'bg-surface-3/60 text-fg-muted ring-border'
                        }`}
                      >
                        {node?.label ?? nid}
                        {flagged ? ' ⚠' : ''}
                      </span>
                    )
                  })}
                </div>
              </div>
            ))}
          {blast.truncated && (
            <p className="text-xs text-warning">{t('graph.blast.truncated')}</p>
          )}
        </div>
      )}
    </div>
  )
}

function SummaryCard({ label, value, tone }: { label: string; value: number; tone?: 'red' }) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/50 p-3">
      <div className="text-xs uppercase tracking-wider text-fg-subtle">{label}</div>
      <div className={`mt-1 text-xl font-semibold tabular-nums ${tone === 'red' ? 'text-danger' : 'text-fg'}`}>
        {value.toLocaleString()}
      </div>
    </div>
  )
}

// ---------------- Timeline mode ----------------

function TimelineMode({ captureId }: { captureId: string | null }) {
  const t = useT()
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['graphTimeline', captureId],
    queryFn: () => api.getTimeline(captureId!, { limit: 500 }),
    enabled: !!captureId,
  })
  if (isLoading) return <div className="p-6 text-center"><Spinner size={20} /></div>
  if (isError) return <ErrorState message={t('graph.timeline.failed')} onRetry={() => void refetch()} />
  if (!data) return <ErrorlessEmpty text={t('graph.select_capture')} />
  const events = data.items
  if (!events.length) {
    return <ErrorlessEmpty text={t('graph.timeline.empty')} />
  }
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-surface-2/50">
      <div className="border-b border-border px-4 py-3 text-sm font-medium text-fg">
        {t('graph.timeline.stream', {
          total: data.total.toLocaleString(),
          shown: events.length,
        })}
      </div>
      <div className="max-h-[60vh] divide-y divide-border/60 overflow-y-auto">
        {events.map((ev) => (
          <div key={ev.id} className="flex items-center gap-3 px-4 py-2 text-xs">
            <span className="w-20 shrink-0 font-mono tabular-nums text-fg-subtle">
              {new Date(ev.timestamp * 1000).toLocaleTimeString()}
            </span>
            <Badge tone={ev.severity === 'critical' || ev.severity === 'high' ? 'danger' : ev.severity === 'medium' ? 'warning' : 'neutral'}>
              {ev.event_type}
            </Badge>
            <span className="min-w-0 flex-1 truncate text-fg-muted">{ev.label}</span>
            {ev.related_alert_id && (
              <span className="shrink-0 font-mono text-fg-subtle">{t('graph.timeline.alert', { id: ev.related_alert_id.slice(0, 8) })}</span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

// ---------------- Evidence mode ----------------

function EvidenceMode({ captureId }: { captureId: string | null }) {
  const t = useT()
  const { data: graph, isLoading, isError, refetch } = useQuery({
    queryKey: ['evidenceGraph', captureId],
    queryFn: () => api.getEvidenceGraph(captureId!),
    enabled: !!captureId,
  })
  if (isLoading) return <div className="p-6 text-center"><Spinner size={20} /></div>
  if (isError) return <ErrorState message={t('graph.evidence.failed')} onRetry={() => void refetch()} />
  if (!graph) return <ErrorlessEmpty text={t('graph.select_capture')} />
  return (
    <div className="max-h-full overflow-y-auto pr-1">
      <EvidenceChainList graph={graph} captureId={captureId!} />
    </div>
  )
}

function ErrorlessEmpty({ text }: { text: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/50 p-12 text-center text-sm text-fg-muted">
      {text}
    </div>
  )
}

// ---------------- Investigate canvas (Graph v2 only) ----------------

interface VisibleElements {
  elements: ElementDefinition[]
  visibleIds: Set<string>
  hiddenLeafCount: number
  tier: Tier
}

function InvestigateCanvas({
  onModeChange,
  captureId: effectiveCaptureId,
}: {
  onModeChange: (mode: GraphMode) => void
  captureId: string | null
}) {
  const { analyzed } = useSelectedCapture()
  const { theme } = useTheme()
  const t = useT()
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [selectedEdge, setSelectedEdge] = useState<GraphV2Edge | null>(null)
  // null = all enabled (fresh capture); user toggles carve out exclusions.
  const [kindFilters, setKindFilters] = useState<Set<GraphNodeKind> | null>(null)
  const [relationFilters, setRelationFilters] = useState<Set<string> | null>(null)
  const [provenanceFilters, setProvenanceFilters] = useState<Set<GraphProvenance> | null>(null)
  const [showLeaves, setShowLeaves] = useState(false)
  const [limit, setLimit] = useState(CANVAS_DEFAULT_LIMIT)
  const [searchQuery, setSearchQuery] = useState('')
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const cyCaptureRef = useRef<string | null>(null)

  // Graph v2 is the ONLY source for the canvas. `limit` grows for large
  // captures (status strip "load more"); the API returns `truncated` when a
  // bigger subgraph exists.
  const { data: graph, isError, refetch } = useQuery({
    queryKey: ['evidenceGraph', effectiveCaptureId, limit],
    queryFn: () => api.getEvidenceGraph(effectiveCaptureId!, { limit }),
    enabled: !!effectiveCaptureId,
  })

  // Fresh capture → reset user overrides and node cap
  useEffect(() => {
    setKindFilters(null)
    setRelationFilters(null)
    setProvenanceFilters(null)
    setShowLeaves(false)
    setSelectedNodeId(null)
    setSelectedEdge(null)
    setLimit(CANVAS_DEFAULT_LIMIT)
    setSearchQuery('')
  }, [effectiveCaptureId])

  const relationGroups = useMemo(
    () => (graph ? buildRelationGroups(graph, t) : []),
    [graph, t],
  )

  // One-tap filter presets: All (default), Observed-only (solid lines) and
  // Alert-focused (alert + incident backbone).
  type Preset = 'all' | 'observed' | 'alerts'
  const PRESETS: { id: Preset; labelKey: string }[] = [
    { id: 'all', labelKey: 'graph.preset.all' },
    { id: 'observed', labelKey: 'graph.preset.observed' },
    { id: 'alerts', labelKey: 'graph.preset.alerts' },
  ]
  const applyPreset = (preset: Preset) => {
    if (preset === 'all') {
      setKindFilters(null)
      setRelationFilters(null)
      setProvenanceFilters(null)
    } else if (preset === 'observed') {
      setKindFilters(null)
      setRelationFilters(null)
      setProvenanceFilters(new Set(['observed']))
    } else {
      setKindFilters(new Set(['alert', 'incident']))
      setRelationFilters(null)
      setProvenanceFilters(null)
    }
  }
  const activePreset: Preset =
    kindFilters === null && relationFilters === null && provenanceFilters === null
      ? 'all'
      : provenanceFilters?.has('observed') && provenanceFilters.size === 1 && kindFilters === null && relationFilters === null
        ? 'observed'
        : kindFilters?.has('alert') && kindFilters?.has('incident') && relationFilters === null && provenanceFilters === null
          ? 'alerts'
          : 'all'
  const metrics = useMemo(() => (graph ? computeNodeMetrics(graph) : null), [graph])
  const leaves = useMemo(() => (graph && metrics ? leafDomainIds(metrics, graph) : null), [graph, metrics])

  // Highlight matches across label, id, ip and domain — case-insensitive and
  // ranked by importance so the interesting node is the first hit.
  const searchResults = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q || !graph || !metrics) return []
    return graph.nodes
      .filter((n) => {
        const hay = [n.label, n.id, n.ip, n.hostname].filter(Boolean).join(' ').toLowerCase()
        return hay.includes(q)
      })
      .sort((a, b) => (metrics.scores.get(b.id) ?? 0) - (metrics.scores.get(a.id) ?? 0))
      .slice(0, 8)
  }, [searchQuery, graph, metrics])

  const activeKindFilters = useMemo(
    () => kindFilters ?? (graph ? presentKinds(graph) : new Set<GraphNodeKind>()),
    [kindFilters, graph],
  )
  const activeRelationFilters = useMemo(
    () => relationFilters ?? new Set(relationGroups.map((g) => g.relationship)),
    [relationFilters, relationGroups],
  )
  const activeProvenanceFilters = useMemo(
    () => provenanceFilters ?? (graph ? presentProvenance(graph) : new Set<GraphProvenance>()),
    [provenanceFilters, graph],
  )

  // Visible elements after kind/relationship/provenance filters and (at scale)
  // leaf collapsing. Tier is decided from the PRE-collapse count — collapsing
  // leaves is what the scale tier does, so it can't depend on its own output.
  const visible = useMemo<VisibleElements>(() => {
    if (!graph) return { elements: [], visibleIds: new Set(), hiddenLeafCount: 0, tier: 'detail' }
    const preCollapseTier = computeTier(graph.stats.total_nodes ?? graph.nodes.length)
    const collapseLeaves = !showLeaves && preCollapseTier === 'scale'
    const nodes = graph.nodes.filter((n) => {
      if (!activeKindFilters.has(n.kind)) return false
      if (collapseLeaves && leaves?.has(n.id)) return false
      return true
    })
    const nodeIds = new Set(nodes.map((n) => n.id))
    const edges = graph.edges.filter(
      (e) =>
        activeRelationFilters.has(e.relationship) &&
        activeProvenanceFilters.has(e.provenance) &&
        nodeIds.has(e.source) &&
        nodeIds.has(e.target),
    )
    // count only domain-type leaves actually excluded by collapsing (not ones
    // already hidden by the kind filter — "show" can't reveal those)
    const hiddenLeafCount =
      collapseLeaves && leaves
        ? [...leaves].filter((id) => {
            const n = graph.nodes.find((node) => node.id === id)
            return !!n && n.kind === 'domain' && !nodeIds.has(id)
          }).length
        : 0
    return {
      elements: [
        ...nodes.map((n) => ({ data: { ...n } })),
        ...edges.map((e) => ({ data: { ...e } })),
      ] as ElementDefinition[],
      visibleIds: nodeIds,
      hiddenLeafCount,
      tier: collapseLeaves
        ? 'scale'
        : computeTier(nodeIds.size || 1),
    }
  }, [graph, activeKindFilters, activeRelationFilters, activeProvenanceFilters, showLeaves, leaves])

  const tier = visible.tier

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
          label: (ele: NodeSingular) => (labeled.has(ele.data('id') as string) ? ele.data('label') as string : ''),
          'background-color': (ele: NodeSingular) => kindStyle(ele.data('kind') as GraphNodeKind, theme).fill,
          'border-color': (ele: NodeSingular) =>
            (ele.data('alert_count') as number) > 0
              ? '#ef4444'
              : kindStyle(ele.data('kind') as GraphNodeKind, theme).color,
          'border-width': (ele: NodeSingular) =>
            (ele.data('alert_count') as number) > 0 ? 3 : 1.5,
          shape: (ele: NodeSingular) => kindStyle(ele.data('kind') as GraphNodeKind, theme).shape,
          color: theme === 'light' ? '#334155' : '#94a3b8',
          'font-size': 9,
          'font-family': "'JetBrains Mono Variable', ui-monospace, monospace",
          width: (ele: NodeSingular) => nodeSize(metrics.scores.get(ele.data('id') as string) ?? 0),
          height: (ele: NodeSingular) => nodeSize(metrics.scores.get(ele.data('id') as string) ?? 0),
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
          width: (ele: EdgeSingular) =>
            Math.min(1 + Math.log2(1 + (ele.data('packets') as number ?? 1)), 6),
          'line-color': (ele: EdgeSingular) =>
            (ele.data('alert_ids') as string[]).length > 0
              ? '#ef4444'
              : RELATIONSHIP_COLORS[ele.data('relationship') as string] ?? '#94a3b8',
          'line-style': (ele: EdgeSingular) =>
            PROVENANCE_LINE[ele.data('provenance') as GraphProvenance] ?? 'solid',
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
      // Node tap → v2 node id flows straight to the detail panel (no rewriting).
      cy.on('tap', 'node', (e) => {
        setSelectedNodeId(e.target.id() as string)
        setSelectedEdge(null)
      })
      // Edge tap → the v2 edge id IS the cytoscape id; hydrate the row from
      // the loaded graph for the provenance panel.
      cy.on('tap', 'edge', (e) => {
        const edge = graph.edges.find((x) => x.id === e.target.id()) ?? null
        setSelectedNodeId(null)
        setSelectedEdge(edge)
      })
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
      const toRemove = cy.elements().filter((el: NodeSingular) => !wanted.has(el.data().id))
      const existing = new Set(cy.elements().map((el: NodeSingular) => el.data().id))
      const toAdd = visible.elements.filter((el) => !existing.has(el.data.id))
      if (toRemove.length > 0) cy.remove(toRemove)

      const addedNodes = toAdd.filter((el: ElementDefinition) => !('source' in el.data))
      if (addedNodes.length > 0) {
        cy.add(toAdd)
        const smallDelta = addedNodes.length <= 30
        if (smallDelta) {
          const seedFan = new Map<string, number>()
          for (const el of addedNodes) {
            const node = cy.getElementById(String(el.data.id) as string)
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
  }, [visible, tier, metrics, graph, effectiveCaptureId, theme])

  // Locate a node in the canvas: select it, then pan/zoom to its position so
  // the search box is a real investigation tool on large graphs.
  const focusNode = (nodeId: string) => {
    setSelectedNodeId(nodeId)
    setSelectedEdge(null)
    setSearchQuery('')
    const cy = cyRef.current
    if (!cy) return
    const ele = cy.getElementById(nodeId)
    if (ele.length > 0) {
      cy.animate({ center: { eles: ele }, zoom: { level: 2, position: ele.position() }, duration: 250 } as never)
      ele.addClass('highlighted')
    }
  }

  // container ref may not be mounted on first effect run for a new capture
  useEffect(() => {
    return () => {
      cyRef.current?.destroy()
      cyRef.current = null
      cyCaptureRef.current = null
    }
  }, [])

  const selectedNode = selectedNodeId ? graph?.nodes.find((n) => n.id === selectedNodeId) ?? null : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* mode-scoped stats line */}
      {graph && (
        <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-fg-subtle">
          <span>
            {t('graph.canvas.stats_n_e', {
              nodes: graph.stats.node_count,
              edges: graph.stats.edge_count,
            })} ·{' '}
            <span className="text-danger">
              {t('graph.canvas.stats_alert', { alerts: graph.stats.alert_backed_edges })}
            </span>
          </span>
          <span className="rounded bg-surface-3 px-1.5 py-0.5 text-fg-muted">{tier}</span>
          <button
            onClick={() => cyRef.current?.fit(undefined, 30)}
            aria-label={t('graph.canvas.fit_aria')}
            className="rounded bg-surface-3 px-1.5 py-0.5 text-fg-muted transition hover:text-fg"
          >
            {t('graph.canvas.fit')}
          </button>
          <span className="ml-auto">{t('graph.canvas.hint')}</span>
        </div>
      )}

      <div className="relative min-h-0 flex-1 overflow-hidden rounded-xl border border-border bg-bg">
        <div ref={containerRef} className="h-full w-full" />

        {/* left filter rail */}
        {graph && (
          <div className="absolute left-3 top-3 w-44 space-y-1 rounded-lg bg-surface-2/90 p-3 text-xs ring-1 ring-border">
            {/* search: locate a node by label / id / ip and jump to it */}
            <div className="relative mb-2">
              <input
                aria-label={t('graph.canvas.search_aria')}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={t('graph.canvas.search_placeholder')}
                className="w-full rounded border border-border-strong bg-bg px-2 py-1 text-fg placeholder:text-fg-muted focus:border-accent focus:outline-none"
              />
              {searchQuery.trim() !== '' && (
                <div
                  className="absolute z-30 mt-1 w-full overflow-hidden rounded border border-border-strong bg-surface-2 shadow-xl"
                  role="listbox"
                >
                  {searchResults.length > 0 ? (
                    searchResults.map((n) => (
                      <button
                        key={n.id}
                        role="option"
                        onClick={() => focusNode(n.id)}
                        className="flex w-full items-center justify-between gap-2 px-2 py-1 text-left hover:bg-surface-3"
                      >
                        <span className="flex-1 truncate font-mono text-fg-subtle">{n.label}</span>
                        <span className="capitalize text-fg-muted">{n.kind}</span>
                      </button>
                    ))
                  ) : (
                    <div className="px-2 py-1 text-fg-muted">{t('graph.canvas.no_matches')}</div>
                  )}
                </div>
              )}
            </div>

            {/* quick filter presets */}
            <div className="mb-2 flex flex-wrap gap-1">
              {PRESETS.map((p) => (
                <button
                  key={p.id}
                  onClick={() => applyPreset(p.id)}
                  aria-pressed={activePreset === p.id}
                  className={`rounded px-1.5 py-0.5 ring-1 transition ${
                    activePreset === p.id
                      ? 'bg-accent-soft text-accent ring-accent-ring'
                      : 'text-fg-muted ring-border-strong hover:text-fg'
                  }`}
                >
                  {t(p.labelKey)}
                </button>
              ))}
            </div>

            <div className="mb-1 font-medium text-fg-muted">{t('graph.canvas.nodes')}</div>
            {graph.stats.node_count > 0 && activeKindFilters.size > 0 && (
              <div>
                {([...activeKindFilters].sort() as GraphNodeKind[]).map((kind) => {
                  const count = graph.nodes.filter((n) => n.kind === kind).length
                  if (count === 0) return null
                  const active = activeKindFilters.has(kind)
                  return (
                    <button
                      key={kind}
                      onClick={() => setKindFilters(toggleInSet(activeKindFilters, kind))}
                      className={`flex w-full items-center gap-2 text-left transition-opacity ${
                        active ? 'text-fg-subtle' : 'text-fg-subtle opacity-40'
                      }`}
                    >
                      <span
                        className="inline-block h-2.5 w-2.5 rounded-[2px] ring-1"
                        style={{
                          background: kindStyle(kind, theme).fill,
                          boxShadow: `inset 0 0 0 1px ${kindStyle(kind, theme).color}`,
                          opacity: active ? 1 : 0.3,
                        }}
                      />
                      <span className="flex-1 capitalize">{kind}</span>
                      <span className="text-fg-subtle">{count}</span>
                    </button>
                  )
                })}
              </div>
            )}

            <div className="mb-1 mt-2 font-medium text-fg-muted">{t('graph.canvas.edges')}</div>
            {relationGroups.length > 0 && (
              <div>
                {relationGroups.map((g) => {
                  const active = activeRelationFilters.has(g.relationship)
                  return (
                    <button
                      key={g.relationship}
                      onClick={() => setRelationFilters(toggleInSet(activeRelationFilters, g.relationship))}
                      className={`flex w-full items-center gap-2 text-left transition-opacity ${
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
              </div>
            )}

            <div className="mb-1 mt-2 font-medium text-fg-muted">{t('graph.canvas.provenance')}</div>
            {graph.edges.length > 0 && (
              <div>
                {(['observed', 'correlated', 'enriched'] as GraphProvenance[]).map((prov) => {
                  const count = graph.edges.filter((e) => e.provenance === prov).length
                  if (count === 0) return null
                  const active = activeProvenanceFilters.has(prov)
                  return (
                    <button
                      key={prov}
                      onClick={() => setProvenanceFilters(toggleInSet(activeProvenanceFilters, prov))}
                      className={`flex w-full items-center gap-2 text-left transition-opacity ${
                        active ? 'text-fg-subtle' : 'text-fg-subtle opacity-40'
                      }`}
                    >
                      <span className="inline-block h-2.5 w-5 border-t-2 border-fg-subtle" style={{ borderStyle: PROVENANCE_LINE[prov] }} />
                      <span className="flex-1">{t(PROV_KEYS[prov])}</span>
                      <span className="text-fg-subtle">{count}</span>
                    </button>
                  )
                })}
              </div>
            )}

            {visible.hiddenLeafCount > 0 && (
              <button
                onClick={() => setShowLeaves(true)}
                className="mt-2 block w-full rounded border border-border-strong px-1.5 py-1 text-left text-fg-muted hover:border-fg-subtle hover:text-fg"
              >
                {t('graph.canvas.leaves_hidden', { count: visible.hiddenLeafCount })}
              </button>
            )}
            <div className="mt-2 border-t border-border pt-1.5 text-fg-subtle">
              {visible.elements.length > 0
                ? t('graph.canvas.shown', { count: visible.elements.length })
                : t('graph.canvas.nothing')}
            </div>
          </div>
        )}

        {/* right slide-in inspector panel (node OR edge) */}
        {(selectedNode || selectedEdge) && (
          <div className="absolute bottom-3 right-3 top-3 z-10 flex w-80 flex-col overflow-hidden rounded-xl border border-border-strong bg-surface-2/95 shadow-xl">
            {selectedEdge ? (
              <>
                <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
                  <div className="min-w-0 truncate font-mono text-xs text-fg-subtle">
                    {selectedEdge.source} → {selectedEdge.target}
                  </div>
                  <button
                    onClick={() => setSelectedEdge(null)}
                    aria-label={t('graph.canvas.close_inspector')}
                    className="ml-2 shrink-0 text-fg-subtle hover:text-fg-muted"
                  >
                    ✕
                  </button>
                </div>
                <div className="min-h-0 flex-1 overflow-y-auto">
                  <EdgeProvenancePanel edge={selectedEdge} captureId={effectiveCaptureId!} />
                </div>
              </>
            ) : (
              selectedNode && (
                <NodeDetailPanel
                  nodeId={selectedNode.id}
                  captureId={effectiveCaptureId!}
                  onClose={() => setSelectedNodeId(null)}
                  onBlast={(id) => {
                    setSelectedNodeId(null)
                    onModeChange('blast')
                    void id
                  }}
                  onPath={(id) => {
                    setSelectedNodeId(null)
                    onModeChange('attack-path')
                    void id
                  }}
                />
              )
            )}
          </div>
        )}

        {!graph && !isError && (
          <div
            className="absolute inset-0 flex items-center justify-center"
            role="status"
            aria-label={t('graph.canvas.building')}
          >
            <span className="sr-only">{t('graph.canvas.building')}</span>
            {analyzed.length ? (
              <div className="h-full w-full p-12" aria-hidden>
                <div className="relative h-full w-full overflow-hidden rounded-lg">
                  {[
                    'left-[15%] top-[22%]',
                    'left-[68%] top-[18%]',
                    'left-[42%] top-[45%]',
                    'left-[80%] top-[55%]',
                    'left-[25%] top-[68%]',
                    'left-[58%] top-[78%]',
                  ].map((pos) => (
                    <div key={pos} className={`absolute ${pos} flex items-center gap-3`}>
                      <SkeletonRow className="h-10 w-10 rounded-full" />
                      <SkeletonRow className="w-24" />
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <span className="text-sm text-fg-subtle">{t('graph.canvas.no_analyzed')}</span>
            )}
          </div>
        )}
        {isError && !graph && (
          <div className="absolute inset-0 flex items-center justify-center">
            <ErrorState message={t('graph.canvas.failed')} onRetry={() => void refetch()} />
          </div>
        )}
      </div>

      {/* bottom status strip */}
      {graph && (
        <div className="mt-2 flex flex-wrap items-center gap-3 text-xs text-fg-subtle">
          <span>
            {t('graph.canvas.status', {
              shown: visible.visibleIds.size,
              total: graph.stats.total_nodes ?? graph.stats.node_count,
              edges: graph.stats.total_edges_in_capture,
            })}
          </span>
          {['observed', 'correlated', 'enriched'].map((prov) => {
            const count = graph.edges.filter((e) => e.provenance === prov).length
            if (count === 0) return null
            return (
              <span key={prov} className="inline-flex items-center gap-1.5">
                <span
                  className="inline-block h-2.5 w-5 border-t-2 border-fg-subtle"
                  style={{ borderStyle: PROVENANCE_LINE[prov as GraphProvenance] }}
                />
                {t(PROV_KEYS[prov as GraphProvenance])} {count}
              </span>
            )
          })}
          {graph.truncated && (
            <button
              onClick={() => setLimit((l) => Math.min(l + CANVAS_DEFAULT_LIMIT, CANVAS_HARD_LIMIT))}
              disabled={limit >= CANVAS_HARD_LIMIT}
              className="rounded bg-accent/10 px-2 py-0.5 font-medium text-accent ring-1 ring-accent/30 transition hover:bg-accent/20 disabled:pointer-events-none disabled:opacity-50"
            >
              {t('graph.canvas.load_more')}
            </button>
          )}
        </div>
      )}
    </div>
  )
}