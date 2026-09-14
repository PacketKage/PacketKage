/**
 * Evidence Graph 2.0 — investigation workspace panels.
 *
 * Shared rendering for v2 modes (Investigate, Attack Path, Blast Radius,
 * Timeline, Evidence). Every displayed claim is backed by real PacketKage
 * data joined at render time: node metadata hydrates from source tables,
 * edge provenance carries flow/alert/packet references, and the Evidence
 * Chain walks Conclusion → Detection → Evidence → Flows → PCAP reference.
 */
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { AlertTriangle, ArrowRight, ExternalLink, ShieldQuestion } from 'lucide-react'
import { api } from '../api/client'
import type {
  GraphProvenance,
  GraphV2,
  GraphV2Edge,
  GraphV2Node,
  GraphV2NodeDetail,
  MappedClassification,
} from '../types/api'
import { Badge, formatBytes, formatTime } from '../components/ui'
import { EvidenceTable } from '../components/EvidenceTable'

// ---- shared chips ----------------------------------------------------------

const PROVENANCE_TONE: Record<GraphProvenance, 'neutral' | 'info' | 'accent' | 'warning'> = {
  observed: 'info',
  correlated: 'accent',
  enriched: 'warning',
}
const PROVENANCE_LABEL: Record<GraphProvenance, string> = {
  observed: 'observed',
  correlated: 'correlated',
  enriched: 'enriched',
}

export function ProvenanceChip({ provenance }: { provenance: GraphProvenance }) {
  return <Badge tone={PROVENANCE_TONE[provenance] ?? 'neutral'}>{PROVENANCE_LABEL[provenance]}</Badge>
}

export function RelationshipChip({ relationship }: { relationship: string }) {
  return <Badge tone="neutral">{relationship.replaceAll('_', ' ').toLowerCase()}</Badge>
}

/** Official ATT&CK technique/sub-technique pattern: T1046, T1557.002, … */
const OFFICIAL_MITRE_ID = /^T\d{4}(\.\d{3})?$/

export function MitreChip({ mitre }: { mitre: MappedClassification | null | undefined }) {
  if (!mitre) return null
  // Official ATT&CK styling ONLY for mitre-source entries with a valid
  // T-patterned ID — anything else (internal classification, or a stale/
  // adversarial payload claiming an internal ID like C1091) renders as a
  // PacketKage-internal chip and can never pass as an ATT&CK mapping.
  const official =
    mitre.source === 'mitre' && !!mitre.technique_id && OFFICIAL_MITRE_ID.test(mitre.technique_id)
  if (official) {
    return (
      <Badge tone="warning" className="font-mono" title="MITRE ATT&CK technique">
        {mitre.technique_id} · {mitre.technique}
      </Badge>
    )
  }
  // Internal chip always shows the classification NAME — a suspect/
  // malformed technique_id is never displayed, even as a PK label
  return (
    <Badge
      tone="neutral"
      className="font-mono"
      title="PacketKage internal classification — not a MITRE ATT&CK technique"
    >
      PK · {mitre.technique}
    </Badge>
  )
}

const SEVERITY_TONE: Record<string, string> = {
  critical: 'bg-danger/10 text-danger ring-danger/30',
  high: 'bg-danger/10 text-danger ring-danger/30',
  medium: 'bg-warning/10 text-warning ring-warning/30',
  low: 'bg-info/10 text-info ring-info/30',
  info: 'bg-fg/10 text-fg-muted ring-fg/20',
}

export function SeverityChip({ severity }: { severity: string }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ${SEVERITY_TONE[severity] ?? SEVERITY_TONE.info}`}>
      {severity}
    </span>
  )
}

// ---- edge provenance panel (inside modal) -----------------------------------

/** "Why is this relationship suspicious?" + the evidence chain for one edge. */
export function EdgeProvenancePanel({ edge, captureId }: { edge: GraphV2Edge; captureId: string }) {
  const { data: detail, isLoading, isError } = useQuery({
    queryKey: ['graphEdge', captureId, edge.id],
    queryFn: () => api.getGraphEdge(captureId, edge.id),
  })
  const e = detail ?? edge

  return (
    <div className="space-y-4">
      {/* relationship identity */}
      <div className="flex flex-wrap items-center gap-2">
        <RelationshipChip relationship={e.relationship} />
        <ProvenanceChip provenance={e.provenance} />
        {e.protocol && <Badge tone="neutral">{e.protocol}{e.port ? `:${e.port}` : ''}</Badge>}
        <Badge tone="neutral">{e.count} observation{e.count === 1 ? '' : 's'}</Badge>
      </div>

      {/* timeline of the relationship */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="rounded-lg bg-surface-2/60 p-2 ring-1 ring-border">
          <div className="text-fg-subtle">First seen</div>
          <div className="mt-0.5 font-mono text-fg-muted">{formatTime(e.first_seen)}</div>
        </div>
        <div className="rounded-lg bg-surface-2/60 p-2 ring-1 ring-border">
          <div className="text-fg-subtle">Last seen</div>
          <div className="mt-0.5 font-mono text-fg-muted">{formatTime(e.last_seen)}</div>
        </div>
      </div>
      {(e.packets > 0 || e.bytes > 0) && (
        <div className="flex gap-3 text-xs text-fg-muted">
          <span className="tabular-nums">{e.packets.toLocaleString()} packets</span>
          <span className="tabular-nums">{formatBytes(e.bytes)}</span>
        </div>
      )}

      {/* why suspicious — only real alert evidence */}
      {e.explanation ? (
        <div className="rounded-lg border border-warning/30 bg-warning/5 p-3">
          <div className="mb-1 flex items-center gap-1.5 text-sm font-medium text-warning">
            <ShieldQuestion size={14} aria-hidden />
            Why is this relationship suspicious?
          </div>
          <p className="text-xs leading-relaxed text-fg-muted">{e.explanation}</p>
        </div>
      ) : (
        <div className="rounded-lg border border-border bg-surface-2/40 p-3 text-xs text-fg-subtle">
          <div className="mb-1 flex items-center gap-1.5 font-medium text-fg-muted">
            <ShieldQuestion size={14} aria-hidden />
            Why is this relationship suspicious?
          </div>
          No alerts in this capture touch this relationship. It is rendered from
          observed traffic only, with no suspicion claim.
        </div>
      )}

      {/* alerts evidence */}
      {isLoading && <p className="text-xs text-fg-subtle">Loading evidence…</p>}
      {isError && <p className="text-xs text-danger">Evidence request failed.</p>}
      {e.alerts && e.alerts.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-fg-subtle">
            Detections ({e.alerts.length})
          </h4>
          {e.alerts.map((a) => (
            <div key={a.id} className="rounded-lg border border-border bg-surface-2/50 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityChip severity={a.severity} />
                <span className="text-sm font-medium text-fg">{a.title}</span>
                <span className="ml-auto font-mono text-xs text-fg-subtle">score {a.score}</span>
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                <MitreChip mitre={a.mitre} />
              </div>
              {a.reasons?.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {a.reasons.map((r, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-fg-muted">
                      <AlertTriangle size={11} className="mt-0.5 shrink-0 text-warning" aria-hidden />
                      <span>
                        <span className="text-fg">{r.reason}:</span> {r.detail}{' '}
                        <span className="text-fg-subtle">(weight {r.weight})</span>
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {a.explanation && (
                <p className="mt-2 text-xs leading-relaxed text-fg-subtle">{a.explanation}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* flows evidence → evidence chain drill-down */}
      {e.flows && e.flows.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-fg-subtle">
            Contributing flows ({e.flows.length})
            {e.flow_ids.length > e.flows.length && (
              <span className="ml-2 font-normal normal-case text-fg-subtle">
                showing first {e.flows.length} of {e.flow_ids.length}
              </span>
            )}
          </h4>
          <div className="space-y-1.5">
            {e.flows.map((f) => (
              <div
                key={f.id}
                className="flex flex-wrap items-center gap-2 rounded-lg bg-surface-2/50 px-3 py-2 text-xs ring-1 ring-border"
              >
                <span className="font-mono text-fg-muted">
                  {f.source_ip} <ArrowRight size={10} className="inline" aria-hidden /> {f.destination_ip}:{f.destination_port}
                </span>
                <Badge tone="neutral">{f.application_protocol ?? f.transport_protocol}</Badge>
                <span className="tabular-nums text-fg-subtle">{f.packets} pkts</span>
                <span className="tabular-nums text-fg-subtle">{formatBytes(f.bytes)}</span>
                <span className="text-fg-subtle">{formatTime(f.first_seen)}</span>
                <Link
                  to={`/flows?capture_id=${captureId}&flow=${f.id}`}
                  className="ml-auto inline-flex items-center gap-1 text-info hover:underline"
                >
                  packets <ExternalLink size={11} aria-hidden />
                </Link>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* raw references */}
      <div className="border-t border-border pt-2 text-xs text-fg-subtle">
        <span className="font-mono">{e.flow_ids.length}</span> flow refs ·{' '}
        <span className="font-mono">{e.alert_ids.length}</span> alert refs ·{' '}
        <span className="font-mono">{e.packet_refs.length}</span> packet refs
        {e.packet_refs.length > 0 && (
          <span className="ml-2 font-mono">
            (packets #{e.packet_refs.slice(0, 8).join(', #')}
            {e.packet_refs.length > 8 ? ', …' : ''})
          </span>
        )}
      </div>
    </div>
  )
}

// ---- node detail (v2) --------------------------------------------------------

export function NodeDetailPanel({
  nodeId,
  captureId,
  onClose,
  onBlast,
  onPath,
}: {
  nodeId: string
  captureId: string
  onClose: () => void
  onBlast: (nodeId: string) => void
  onPath: (nodeId: string) => void
}) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['graphNode', captureId, nodeId],
    queryFn: () => api.getGraphNode(captureId, nodeId),
  })

  if (isLoading) {
    return <div className="p-4 text-sm text-fg-subtle">Loading node…</div>
  }
  if (isError || !data) {
    return <div className="p-4 text-sm text-danger">Node not found in this capture.</div>
  }
  return <NodeDetailBody detail={data} onClose={onClose} onBlast={onBlast} onPath={onPath} />
}

function NodeDetailBody({
  detail,
  onClose,
  onBlast,
  onPath,
}: {
  detail: GraphV2NodeDetail
  onClose: () => void
  onBlast: (nodeId: string) => void
  onPath: (nodeId: string) => void
}) {
  const { node, edges, stats } = detail
  return (
    <div className="p-4">
      <div className="mb-3 flex items-start justify-between gap-2">
        <div>
          <div className="font-mono text-sm font-semibold text-fg">{node.label}</div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            <Badge tone="neutral">{node.kind}</Badge>
            {node.internal != null && (
              <Badge tone={node.internal ? 'success' : 'neutral'}>
                {node.internal ? 'internal' : 'external'}
              </Badge>
            )}
            {node.severity && <SeverityChip severity={node.severity} />}
            {node.role && <Badge tone="info">{node.role}</Badge>}
            <MitreChip mitre={node.mitre} />
          </div>
        </div>
        <button onClick={onClose} aria-label="Close" className="text-fg-subtle hover:text-fg-muted">
          ✕
        </button>
      </div>

      {node.kind === 'host' && (
        <div className="mb-3 grid grid-cols-2 gap-2 text-xs">
          <div className="rounded-lg bg-surface-2/60 p-2 ring-1 ring-border">
            <div className="text-fg-subtle">Sent</div>
            <div className="mt-0.5 font-mono tabular-nums text-fg-muted">{formatBytes(node.bytes_sent ?? 0)}</div>
          </div>
          <div className="rounded-lg bg-surface-2/60 p-2 ring-1 ring-border">
            <div className="text-fg-subtle">Received</div>
            <div className="mt-0.5 font-mono tabular-nums text-fg-muted">{formatBytes(node.bytes_received ?? 0)}</div>
          </div>
        </div>
      )}

      {node.reasons && node.reasons.length > 0 && (
        <div className="mb-3 rounded-lg border border-warning/30 bg-warning/5 p-3">
          <div className="mb-1 text-xs font-semibold uppercase tracking-wider text-warning">
            Detection reasons
          </div>
          <ul className="space-y-1">
            {node.reasons.map((r, i) => (
              <li key={i} className="text-xs text-fg-muted">
                <span className="text-fg">{r.reason}:</span> {r.detail}
              </li>
            ))}
          </ul>
        </div>
      )}
      {node.explanation && (
        <p className="mb-3 text-xs leading-relaxed text-fg-subtle">{node.explanation}</p>
      )}

      <div className="mb-3 flex flex-wrap gap-2">
        {node.kind === 'host' && (
          <>
            <button
              onClick={() => onBlast(node.id)}
              className="rounded-lg bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent ring-1 ring-accent/30 transition hover:bg-accent/20"
            >
              Blast radius →
            </button>
            <button
              onClick={() => onPath(node.id)}
              className="rounded-lg bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent ring-1 ring-accent/30 transition hover:bg-accent/20"
            >
              Attack path from here →
            </button>
          </>
        )}
      </div>

      <div className="mb-1.5 flex items-center justify-between">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-fg-subtle">
          Relationships ({edges.length})
        </h4>
        <span className="text-xs text-fg-subtle">
          {stats.alert_backed_edges} alert-backed
        </span>
      </div>
      <div className="max-h-64 space-y-1.5 overflow-y-auto pr-1">
        {edges.length === 0 && (
          <p className="text-xs text-fg-subtle">No relationships in this capture.</p>
        )}
        {edges.map((e) => (
          <div
            key={e.id}
            className="flex flex-wrap items-center gap-2 rounded-lg bg-surface-2/50 px-3 py-2 text-xs ring-1 ring-border"
          >
            <span className="font-mono text-fg-subtle">
              {e.source === node.id ? '→' : '←'} {e.source === node.id ? e.target : e.source}
            </span>
            <RelationshipChip relationship={e.relationship} />
            <ProvenanceChip provenance={e.provenance} />
            {e.alert_ids.length > 0 && <Badge tone="danger">{e.alert_ids.length} alerts</Badge>}
            <span className="ml-auto tabular-nums text-fg-subtle">{formatTime(e.last_seen)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ---- evidence chain ----------------------------------------------------------

/**
 * Evidence Chain: Conclusion → Detection → Evidence → Flow/Observation →
 * PCAP reference. Derived from the alert-backed edges of the v2 graph —
 * every row links to real PacketKage data (alerts + flow deep links).
 */
export function EvidenceChainList({ graph, captureId }: { graph: GraphV2; captureId: string }) {
  const suspicious = graph.edges.filter((e) => e.alert_ids.length > 0)
  if (!suspicious.length) {
    return (
      <div className="rounded-xl border border-border bg-surface-2/50 p-8 text-center text-sm text-fg-muted">
        No alert-backed relationships in this capture — nothing to trace.
      </div>
    )
  }
  return (
    <div className="space-y-3">
      <p className="text-xs text-fg-subtle">
        Each chain is assembled at render time from real alerts and flows — nothing
        here is inferred or external.
      </p>
      {suspicious.map((edge) => {
        const src = graph.nodes.find((n) => n.id === edge.source)
        const dst = graph.nodes.find((n) => n.id === edge.target)
        return (
          <div key={edge.id} className="rounded-xl border border-border bg-surface-2/50 p-4">
            <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
              <span className="font-mono font-semibold text-fg">
                {src?.label ?? edge.source}
              </span>
              <ArrowRight size={14} className="text-fg-subtle" aria-hidden />
              <span className="font-mono font-semibold text-fg">{dst?.label ?? edge.target}</span>
              <RelationshipChip relationship={edge.relationship} />
              <ProvenanceChip provenance={edge.provenance} />
            </div>
            {/* Chain: Conclusion → Detection → Evidence → Flows → PCAP */}
            <ol className="space-y-2">
              <ChainStep index={1} label="Conclusion">
                {edge.explanation ? (
                  <span className="text-xs text-fg-muted">{edge.explanation}</span>
                ) : (
                  <span className="text-xs text-fg-subtle">
                    Relationship flagged by {edge.alert_ids.length} alert(s).
                  </span>
                )}
              </ChainStep>
              <ChainStep index={2} label="Detections">
                <span className="text-xs text-fg-muted">
                  {edge.alert_ids.length} alert(s) — open the relationship for full reasons:
                </span>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {edge.alert_ids.slice(0, 10).map((aid) => (
                    <Link
                      key={aid}
                      to={`/alerts?capture_id=${captureId}&alert=${aid}`}
                      className="rounded bg-danger/10 px-2 py-0.5 font-mono text-xs text-danger ring-1 ring-danger/30 hover:bg-danger/20"
                    >
                      {aid.slice(0, 8)}
                    </Link>
                  ))}
                </div>
              </ChainStep>
              <ChainStep index={3} label="Evidence">
                <span className="text-xs text-fg-muted">
                  {edge.flow_ids.length} flow(s), {edge.packet_refs.length} packet reference(s)
                  backing this relationship.
                </span>
              </ChainStep>
              <ChainStep index={4} label="Flows / Observations">
                <div className="flex flex-wrap gap-1.5">
                  {edge.flow_ids.slice(0, 8).map((fid) => (
                    <Link
                      key={fid}
                      to={`/flows?capture_id=${captureId}&flow=${fid}`}
                      className="rounded bg-info/10 px-2 py-0.5 font-mono text-xs text-info ring-1 ring-info/30 hover:bg-info/20"
                    >
                      {fid.slice(0, 8)}
                    </Link>
                  ))}
                </div>
              </ChainStep>
              <ChainStep index={5} label="PCAP reference">
                <span className="text-xs text-fg-muted">
                  {edge.packet_refs.length > 0
                    ? `Packet ordinals #${edge.packet_refs.slice(0, 6).join(', #')}${edge.packet_refs.length > 6 ? ', …' : ''} — open any flow to view raw packet evidence.`
                    : 'Packet-level references live on the contributing flows — open one to view raw evidence.'}
                </span>
              </ChainStep>
            </ol>
          </div>
        )
      })}
    </div>
  )
}

function ChainStep({ index, label, children }: { index: number; label: string; children: React.ReactNode }) {
  return (
    <li className="flex items-start gap-3">
      <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent/10 font-mono text-[10px] font-semibold text-accent ring-1 ring-accent/30">
        {index}
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-xs font-semibold uppercase tracking-wider text-fg-subtle">{label}</div>
        <div className="mt-0.5">{children}</div>
      </div>
    </li>
  )
}

// ---- v2 node/edge palette (theme-aware, mirrors v1 hues) ---------------------

export const V2_NODE_KIND_STYLE: Record<string, { fill: string; ring: string; label: string }> = {
  host: { fill: '#38bdf8', ring: 'host', label: 'hosts' },
  domain: { fill: '#a78bfa', ring: 'domain', label: 'domains' },
  service: { fill: '#34d399', ring: 'service', label: 'services' },
  alert: { fill: '#f87171', ring: 'alert', label: 'alerts' },
  incident: { fill: '#fbbf24', ring: 'incident', label: 'incidents' },
  case: { fill: '#22d3ee', ring: 'case', label: 'cases' },
  capture: { fill: '#94a3b8', ring: 'capture', label: 'captures' },
}

/** Simple stat row reused by the v2 panels. */
export function StatLine({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-fg-subtle">{label}</span>
      <span className="font-mono tabular-nums text-fg-muted">{value}</span>
    </div>
  )
}

/** Fallback renderer for arbitrary evidence objects. */
export function EvidenceFallback({ data }: { data: Record<string, unknown> }) {
  return <EvidenceTable data={data} />
}

export type { GraphV2Node }
