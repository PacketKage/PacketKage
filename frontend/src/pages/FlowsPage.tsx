import { useEffect, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { ArrowDown, ArrowUp, Download } from 'lucide-react'
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table'
import { api } from '../api/client'
import { CapturePicker } from '../components/CapturePicker'
import { Modal } from '../components/Modal'
import { EmptyState, ErrorState, Pagination } from '../components/states'
import { SkeletonTable, formatBytes, formatTime } from '../components/ui'
import { useSelectedCapture } from '../hooks/captures'
import { fetchAllPages, useCsvExport } from '../hooks/useCsvExport'
import { csvTime } from '../utils/csv'
import type { Flow, PacketEvidence } from '../types/api'

const BADGE: Record<string, string> = {
  established: 'bg-accent/10 text-accent ring-accent/30',
  half_open: 'bg-warning/10 text-warning ring-warning/30',
  closed: 'bg-fg/10 text-fg-muted ring-fg/20',
  reset: 'bg-danger/10 text-danger ring-danger/30',
}

const DIR_LABEL: Record<string, string> = {
  outbound: '→ out',
  inbound: '← in',
  internal: '↔ int',
  unknown: '?',
}

const PAGE_SIZE = 50

export function FlowsPage() {
  const { analyzed, effectiveCaptureId, setCaptureId } = useSelectedCapture()
  const [transport, setTransport] = useState('')
  const [direction, setDirection] = useState('')
  const [offset, setOffset] = useState(0)
  const [sort, setSort] = useState('first_seen')
  const [order, setOrder] = useState('asc')
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(null)

  // Deep links: /flows?capture_id=…&flow=… opens that capture + flow's evidence modal
  const [searchParams] = useSearchParams()
  const deepCaptureId = searchParams.get('capture_id')
  const deepFlowId = searchParams.get('flow')
  useEffect(() => {
    if (deepCaptureId) {
      setCaptureId(deepCaptureId)
      setOffset(0)
    }
    if (deepFlowId) setSelectedFlowId(deepFlowId)
    // runs once per navigation; deep-link params stay in the URL harmlessly
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deepCaptureId, deepFlowId])

  const { data: page, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['flows', effectiveCaptureId, transport, direction, sort, order, offset],
    queryFn: () =>
      api.listFlows(
        effectiveCaptureId!,
        {
          transport: transport || undefined,
          direction: direction || undefined,
          sort,
          order,
        },
        { limit: PAGE_SIZE, offset },
      ),
    enabled: !!effectiveCaptureId,
  })

  const flows = page?.items ?? []

  // CSV export of every flow matching the current filters (paged at the cap)
  const flowExport = useCsvExport<Flow>({
    label: 'flows',
    headers: [
      'First Seen', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
      'Protocol', 'App Protocol', 'Direction', 'State', 'Packets', 'Bytes',
      'Retransmissions', 'Resets', 'Duration (s)',
    ],
    toRow: (f) => [
      csvTime(f.first_seen), f.source_ip, f.source_port, f.destination_ip, f.destination_port,
      f.transport_protocol, f.application_protocol, f.direction, f.tcp_state,
      f.packets, f.bytes, f.retransmissions, f.resets, f.duration,
    ],
    fetchAll: () =>
      fetchAllPages((p) =>
        api.listFlows(
          effectiveCaptureId!,
          {
            transport: transport || undefined,
            direction: direction || undefined,
            sort,
            order,
          },
          p,
        ),
      ),
  })

  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold text-fg">Flows</h1>
      <p className="mt-1 mb-6 text-sm text-fg-subtle">
        Reconstructed conversations — start from the flow, drill into the packet evidence.
      </p>

      {/* Capture picker + filters */}
      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={(id) => { setCaptureId(id); setOffset(0) }} />
        {['', 'TCP', 'UDP'].map((t) => (
          <button
            key={t}
            onClick={() => { setTransport(t); setOffset(0) }}
            className={`rounded-lg px-3 py-1.5 ring-1 transition ${
              transport === t
                ? 'bg-info/10 text-info ring-info/30'
                : 'text-fg-muted ring-border-strong hover:text-fg'
            }`}
          >
            {t || 'All'}
          </button>
        ))}
        <span className="ml-2 text-xs text-fg-subtle">direction:</span>
        {['', 'outbound', 'inbound', 'internal'].map((d) => (
          <button
            key={d}
            onClick={() => { setDirection(d); setOffset(0) }}
            className={`rounded-lg px-3 py-1.5 ring-1 transition ${
              direction === d
                ? 'bg-info/10 text-info ring-info/30'
                : 'text-fg-muted ring-border-strong hover:text-fg'
            }`}
          >
            {d || 'any'}
          </button>
        ))}
        <span className="ml-2 text-xs text-fg-subtle">sort:</span>
        <select
          aria-label="Sort by"
          value={sort}
          onChange={(e) => { setSort(e.target.value); setOffset(0) }}
          className="rounded-lg border border-border-strong bg-surface-2/50 px-2 py-1.5 text-xs text-fg-muted"
        >
          <option value="first_seen">first seen</option>
          <option value="bytes">bytes</option>
          <option value="packets">packets</option>
          <option value="duration">duration</option>
        </select>
        <button
          onClick={() => { setOrder(order === 'asc' ? 'desc' : 'asc'); setOffset(0) }}
          className="rounded-lg px-2.5 py-1.5 text-xs text-fg-muted ring-1 ring-border-strong hover:text-fg"
        >
          {order === 'asc' ? (<><ArrowUp size={12} className="inline" aria-hidden /> asc</>) : (<><ArrowDown size={12} className="inline" aria-hidden /> desc</>)}
        </button>
        <button
          onClick={flowExport.export}
          disabled={flowExport.isExporting || !effectiveCaptureId || isLoading}
          aria-label="Export flows to CSV"
          title="Export filtered flows to CSV"
          className="ml-auto inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs text-fg-muted ring-1 ring-border-strong transition hover:text-fg disabled:pointer-events-none disabled:opacity-50"
        >
          <Download size={12} aria-hidden />
          {flowExport.isExporting ? 'Exporting…' : 'CSV'}
        </button>
      </div>

      {!analyzed.length ? (
        <EmptyState>No analyzed captures yet — upload and analyze a PCAP first.</EmptyState>
      ) : isLoading ? (
        <SkeletonTable
          headers={['First Seen', 'Source', 'Dir', 'Destination', 'Proto', 'State', 'Packets', 'Bytes', 'Retrans', 'Resets', '']}
          widths={['w-20', 'w-36', 'w-12', 'w-36', 'w-16', 'w-20', 'w-16', 'w-16', 'w-14', 'w-12', 'w-16']}
          rows={8}
        />
      ) : isError ? (
        <ErrorState message={String(error)} onRetry={() => refetch()} />
      ) : !flows.length ? (
        <EmptyState>No flows match the current filters.</EmptyState>
      ) : (
        <FlowsTable
          flows={flows}
          onSelect={setSelectedFlowId}
          footer={
            page && (
              <Pagination
                offset={page.offset}
                limit={page.limit}
                total={page.total}
                onPageChange={setOffset}
              />
            )
          }
        />
      )}

      {selectedFlowId && (
        <FlowEvidenceModal flowId={selectedFlowId} onClose={() => setSelectedFlowId(null)} />
      )}
    </div>
  )
}

const col = createColumnHelper<Flow>()

function FlowsTable({
  flows,
  onSelect,
  footer,
}: {
  flows: Flow[]
  onSelect: (id: string) => void
  footer?: React.ReactNode
}) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- TanStack column defs are heterogeneously typed
  const columns: ColumnDef<Flow, any>[] = useMemo(
    () => [
      col.accessor('first_seen', {
        header: 'First Seen',
        cell: (c) => <span className="font-mono text-xs text-fg-muted">{formatTime(c.getValue())}</span>,
      }),
      col.accessor('source_ip', {
        header: 'Source',
        cell: (c) => (
          <span className="font-mono text-fg-muted">
            {c.getValue()}
            <span className="text-fg-subtle">:{c.row.original.source_port}</span>
          </span>
        ),
      }),
      col.accessor('direction', {
        header: 'Dir',
        cell: (c) => (
          <span className="text-xs text-fg-subtle">{DIR_LABEL[c.getValue()] ?? '?'}</span>
        ),
      }),
      col.accessor('destination_ip', {
        header: 'Destination',
        cell: (c) => (
          <span className="font-mono text-fg-muted">
            {c.getValue()}
            <span className="text-fg-subtle">:{c.row.original.destination_port}</span>
          </span>
        ),
      }),
      col.accessor('transport_protocol', {
        header: 'Proto',
        cell: (c) => {
          const t = c.getValue()
          const app = c.row.original.application_protocol
          return (
            <span className="flex items-center gap-1.5">
              <span
                className={`rounded px-1.5 py-0.5 text-xs font-bold ring-1 ${
                  t === 'TCP'
                    ? 'bg-info/10 text-info ring-info/30'
                    : 'bg-info/10 text-info ring-info/30'
                }`}
              >
                {t}
              </span>
              {app && <span className="text-xs text-fg-subtle">{app}</span>}
            </span>
          )
        },
      }),
      col.accessor('tcp_state', {
        header: 'State',
        cell: (c) => {
          const s = c.getValue()
          if (!s) return <span className="text-xs text-fg-subtle">—</span>
          return (
            <span className={`rounded-full px-2 py-0.5 text-xs ring-1 ${BADGE[s] ?? BADGE.closed}`}>
              {s}
            </span>
          )
        },
      }),
      col.accessor('packets', {
        header: 'Packets',
        cell: (c) => <span className="font-mono text-fg-muted tabular-nums">{c.getValue().toLocaleString()}</span>,
      }),
      col.accessor('bytes', {
        header: 'Bytes',
        cell: (c) => <span className="font-mono text-fg-muted tabular-nums">{formatBytes(c.getValue())}</span>,
      }),
      col.accessor('retransmissions', {
        header: 'Retrans',
        cell: (c) =>
          c.getValue() > 0 ? (
            <span className="font-mono text-warning tabular-nums">{c.getValue()}</span>
          ) : (
            <span className="font-mono text-fg-subtle tabular-nums">0</span>
          ),
      }),
      col.accessor('resets', {
        header: 'Resets',
        cell: (c) =>
          c.getValue() > 0 ? (
            <span className="font-mono text-danger tabular-nums">{c.getValue()}</span>
          ) : (
            <span className="font-mono text-fg-subtle tabular-nums">0</span>
          ),
      }),
      col.display({
        id: 'actions',
        header: '',
        cell: (c) => (
          <button
            onClick={() => onSelect(c.row.original.id)}
            className="rounded px-2 py-1 text-xs text-info ring-1 ring-info/30 hover:bg-info/10"
          >
            packets →
          </button>
        ),
      }),
    ],
    [onSelect],
  )

  const table = useReactTable<Flow>({
    data: flows,
    columns,
    getCoreRowModel: getCoreRowModel<Flow>(),
  })

  return (
    <div className="overflow-hidden rounded-xl border border-border bg-surface-2/50">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id} className="text-left text-xs uppercase tracking-wider text-fg-subtle">
                {hg.headers.map((h) => (
                  <th key={h.id} className="px-4 py-2.5 select-none">
                    {flexRender(h.column.columnDef.header, h.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                className="cursor-pointer border-t border-border/60 hover:bg-surface-3/30"
                onClick={() => onSelect(row.original.id)}
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-4 py-2">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {footer}
    </div>
  )
}

function FlowEvidenceModal({ flowId, onClose }: { flowId: string; onClose: () => void }) {
  const queryClient = useQueryClient()
  const { data: flow, isLoading, isError } = useQuery({
    queryKey: ['flow', flowId],
    queryFn: () => api.getFlow(flowId),
  })

  return (
    <Modal
      title={
        flow ? (
          <>
            <span className="font-mono">
              {flow.source_ip}:{flow.source_port}
            </span>
            <span className="mx-2 text-fg-subtle">→</span>
            <span className="font-mono">
              {flow.destination_ip}:{flow.destination_port}
            </span>
          </>
        ) : (
          'Loading flow…'
        )
      }
      subtitle={
        flow && (
          <>
            {flow.transport_protocol} · {flow.application_protocol ?? '—'} ·{' '}
            {flow.packets} packets · {formatBytes(flow.bytes)}
            {flow.retransmissions > 0 && (
              <span className="text-warning"> · {flow.retransmissions} retransmissions</span>
            )}
            {flow.resets > 0 && <span className="text-danger"> · {flow.resets} resets</span>}
          </>
        )
      }
      onClose={onClose}
      wide
    >
      {isError ? (
        <div className="p-12 text-center text-sm text-danger">
          Failed to load packet evidence.
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ['flow', flowId] })}
            className="ml-3 rounded-lg bg-surface-3 px-3 py-1 text-xs text-fg-muted ring-1 ring-border-strong hover:text-fg"
          >
            Retry
          </button>
        </div>
      ) : isLoading || !flow ? (
        <div className="p-4">
          <SkeletonTable
            headers={['Time', 'Source', 'Destination', 'Proto', 'Flags', 'Len', 'Info']}
            widths={['w-20', 'w-32', 'w-32', 'w-14', 'w-20', 'w-12', 'w-40']}
            rows={6}
            className="border-0"
          />
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-surface-2/50">
            <tr className="text-left text-xs uppercase tracking-wider text-fg-subtle">
              <th className="px-4 py-2.5">Time</th>
              <th className="px-4 py-2.5">Source</th>
              <th className="px-4 py-2.5">Destination</th>
              <th className="px-4 py-2.5">Proto</th>
              <th className="px-4 py-2.5">Flags</th>
              <th className="px-4 py-2.5">Len</th>
              <th className="px-4 py-2.5">Info</th>
            </tr>
          </thead>
          <tbody>
            {flow.packet_evidence.map((p: PacketEvidence, i: number) => (
              <EvidenceRow key={i} pkt={p} />
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  )
}

function EvidenceRow({ pkt }: { pkt: PacketEvidence }) {
  const info =
    (pkt.metadata['dns.query'] as string) ??
    (pkt.metadata['http.host'] as string) ??
    (pkt.metadata['http.method'] as string) ??
    (pkt.metadata['tls.sni'] as string) ??
    ''
  return (
    <tr className="border-t border-border/60 hover:bg-surface-3/30">
      <td className="px-4 py-2 font-mono text-xs text-fg-subtle">
        {formatTime(pkt.timestamp)}
      </td>
      <td className="px-4 py-2 font-mono text-xs text-fg-muted">
        {pkt.source_ip}
        {pkt.source_port != null && <span className="text-fg-subtle">:{pkt.source_port}</span>}
      </td>
      <td className="px-4 py-2 font-mono text-xs text-fg-muted">
        {pkt.destination_ip}
        {pkt.destination_port != null && (
          <span className="text-fg-subtle">:{pkt.destination_port}</span>
        )}
      </td>
      <td className="px-4 py-2 text-xs text-fg-muted">{pkt.protocol ?? '—'}</td>
      <td className="px-4 py-2">
        <span className="flex gap-1">
          {pkt.flags.map((f) => (
            <span
              key={f}
              className={`rounded px-1 text-xs font-bold ${
                f === 'RST'
                  ? 'bg-danger/20 text-danger'
                  : f === 'SYN'
                    ? 'bg-info/20 text-info'
                    : 'bg-surface-3/50 text-fg-muted'
              }`}
            >
              {f}
            </span>
          ))}
        </span>
      </td>
      <td className="px-4 py-2 text-xs text-fg-muted">{pkt.length}</td>
      <td className="max-w-[200px] truncate px-4 py-2 font-mono text-xs text-fg-subtle">
        {info || '—'}
      </td>
    </tr>
  )
}
