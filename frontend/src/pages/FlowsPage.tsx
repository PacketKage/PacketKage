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
import { translate } from '../i18n/locale'
import { useT } from '../i18n/LocaleContext'
import { csvTime } from '../utils/csv'
import type { Flow, PacketEvidence } from '../types/api'

const BADGE: Record<string, string> = {
  established: 'bg-accent/10 text-accent ring-accent/30',
  half_open: 'bg-warning/10 text-warning ring-warning/30',
  closed: 'bg-fg/10 text-fg-muted ring-fg/20',
  reset: 'bg-danger/10 text-danger ring-danger/30',
}

const DIR_KEY: Record<string, string> = {
  outbound: 'flows.direction.outbound',
  inbound: 'flows.direction.inbound',
  internal: 'flows.direction.internal',
  unknown: 'flows.direction.unknown',
}

const PAGE_SIZE = 50

export function FlowsPage() {
  const { analyzed, effectiveCaptureId, setCaptureId } = useSelectedCapture()
  const t = useT()
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
    label: translate('flows.csv.label'),
    headers: [
      translate('flows.csv.first_seen'), translate('flows.csv.source_ip'), translate('flows.csv.source_port'),
      translate('flows.csv.destination_ip'), translate('flows.csv.destination_port'),
      translate('flows.csv.protocol'), translate('flows.csv.app_protocol'), translate('flows.csv.direction'),
      translate('flows.csv.state'), translate('flows.csv.packets'), translate('flows.csv.bytes'),
      translate('flows.csv.retransmissions'), translate('flows.csv.resets'), translate('flows.csv.duration'),
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
      <h1 className="text-2xl font-semibold text-fg">{t('flows.title')}</h1>
      <p className="mt-1 mb-6 text-sm text-fg-subtle">{t('flows.subtitle')}</p>

      {/* Capture picker + filters */}
      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={(id) => { setCaptureId(id); setOffset(0) }} />
        {['', 'TCP', 'UDP'].map((tt) => (
          <button
            key={tt}
            onClick={() => { setTransport(tt); setOffset(0) }}
            className={`rounded-lg px-3 py-1.5 ring-1 transition ${
              transport === tt
                ? 'bg-info/10 text-info ring-info/30'
                : 'text-fg-muted ring-border-strong hover:text-fg'
            }`}
          >
            {tt || t('common.all')}
          </button>
        ))}
        <span className="ml-2 text-xs text-fg-subtle">{t('flows.direction')}</span>
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
            {d ? t(`flows.filter.${d}`) : t('common.any')}
          </button>
        ))}
        <span className="ml-2 text-xs text-fg-subtle">{t('flows.sort')}</span>
        <select
          aria-label={t('flows.sort.by')}
          value={sort}
          onChange={(e) => { setSort(e.target.value); setOffset(0) }}
          className="rounded-lg border border-border-strong bg-surface-2/50 px-2 py-1.5 text-xs text-fg-muted"
        >
          <option value="first_seen">{t('flows.sort.first_seen')}</option>
          <option value="bytes">{t('flows.sort.bytes')}</option>
          <option value="packets">{t('flows.sort.packets')}</option>
          <option value="duration">{t('flows.sort.duration')}</option>
        </select>
        <button
          onClick={() => { setOrder(order === 'asc' ? 'desc' : 'asc'); setOffset(0) }}
          className="rounded-lg px-2.5 py-1.5 text-xs text-fg-muted ring-1 ring-border-strong hover:text-fg"
        >
          {order === 'asc' ? (<><ArrowUp size={12} className="inline" aria-hidden /> {t('flows.order.asc')}</>) : (<><ArrowDown size={12} className="inline" aria-hidden /> {t('flows.order.desc')}</>)}
        </button>
        <button
          onClick={flowExport.export}
          disabled={flowExport.isExporting || !effectiveCaptureId || isLoading}
          aria-label={t('flows.export_aria')}
          title={t('flows.export_title')}
          className="ml-auto inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs text-fg-muted ring-1 ring-border-strong transition hover:text-fg disabled:pointer-events-none disabled:opacity-50"
        >
          <Download size={12} aria-hidden />
          {flowExport.isExporting ? t('common.exporting') : 'CSV'}
        </button>
      </div>

      {!analyzed.length ? (
        <EmptyState>{t('flows.empty.no_analyzed')}</EmptyState>
      ) : isLoading ? (
        <SkeletonTable
          headers={[
            t('flows.table.first_seen'), t('flows.table.source'), t('flows.table.dir'),
            t('flows.table.destination'), t('flows.table.proto'), t('flows.table.state'),
            t('flows.table.packets'), t('flows.table.bytes'), t('flows.table.retrans'),
            t('flows.table.resets'), '',
          ]}
          widths={['w-20', 'w-36', 'w-12', 'w-36', 'w-16', 'w-20', 'w-16', 'w-16', 'w-14', 'w-12', 'w-16']}
          rows={8}
        />
      ) : isError ? (
        <ErrorState message={String(error)} onRetry={() => refetch()} />
      ) : !flows.length ? (
        <EmptyState>{t('flows.empty.no_filtered')}</EmptyState>
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
  const t = useT()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- TanStack column defs are heterogeneously typed
  const columns: ColumnDef<Flow, any>[] = useMemo(
    () => [
      col.accessor('first_seen', {
        header: t('flows.table.first_seen'),
        cell: (c) => <span className="font-mono text-xs text-fg-muted">{formatTime(c.getValue())}</span>,
      }),
      col.accessor('source_ip', {
        header: t('flows.table.source'),
        cell: (c) => (
          <span className="font-mono text-fg-muted">
            {c.getValue()}
            <span className="text-fg-subtle">:{c.row.original.source_port}</span>
          </span>
        ),
      }),
      col.accessor('direction', {
        header: t('flows.table.dir'),
        cell: (c) => (
          <span className="text-xs text-fg-subtle">{translate(DIR_KEY[c.getValue()] ?? DIR_KEY.unknown)}</span>
        ),
      }),
      col.accessor('destination_ip', {
        header: t('flows.table.destination'),
        cell: (c) => (
          <span className="font-mono text-fg-muted">
            {c.getValue()}
            <span className="text-fg-subtle">:{c.row.original.destination_port}</span>
          </span>
        ),
      }),
      col.accessor('transport_protocol', {
        header: t('flows.table.proto'),
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
        header: t('flows.table.state'),
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
        header: t('flows.table.packets'),
        cell: (c) => <span className="font-mono text-fg-muted tabular-nums">{c.getValue().toLocaleString()}</span>,
      }),
      col.accessor('bytes', {
        header: t('flows.table.bytes'),
        cell: (c) => <span className="font-mono text-fg-muted tabular-nums">{formatBytes(c.getValue())}</span>,
      }),
      col.accessor('retransmissions', {
        header: t('flows.table.retrans'),
        cell: (c) =>
          c.getValue() > 0 ? (
            <span className="font-mono text-warning tabular-nums">{c.getValue()}</span>
          ) : (
            <span className="font-mono text-fg-subtle tabular-nums">0</span>
          ),
      }),
      col.accessor('resets', {
        header: t('flows.table.resets'),
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
            {t('flows.table.packet_evidence')}
          </button>
        ),
      }),
    ],
    [onSelect, t],
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
  const t = useT()
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
          t('flows.modal.loading')
        )
      }
      subtitle={
        flow && (
          <>
            {flow.transport_protocol} · {flow.application_protocol ?? '—'} ·{' '}
            {t('capture.detail.packets', { count: flow.packets })} · {formatBytes(flow.bytes)}
            {flow.retransmissions > 0 && (
              <span className="text-warning">{t('flows.modal.retransmissions', { count: flow.retransmissions })}</span>
            )}
            {flow.resets > 0 && <span className="text-danger">{t('flows.modal.resets', { count: flow.resets })}</span>}
          </>
        )
      }
      onClose={onClose}
      wide
    >
      {isError ? (
        <div className="p-12 text-center text-sm text-danger">
          {t('flows.modal.error')}
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
            headers={[
              t('flows.evidence.time'), t('flows.evidence.source'), t('flows.evidence.destination'),
              t('flows.evidence.proto'), t('flows.evidence.flags'), t('flows.evidence.len'), t('flows.evidence.info'),
            ]}
            widths={['w-20', 'w-32', 'w-32', 'w-14', 'w-20', 'w-12', 'w-40']}
            rows={6}
            className="border-0"
          />
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-surface-2/50">
            <tr className="text-left text-xs uppercase tracking-wider text-fg-subtle">
              <th className="px-4 py-2.5">{t('flows.evidence.time')}</th>
              <th className="px-4 py-2.5">{t('flows.evidence.source')}</th>
              <th className="px-4 py-2.5">{t('flows.evidence.destination')}</th>
              <th className="px-4 py-2.5">{t('flows.evidence.proto')}</th>
              <th className="px-4 py-2.5">{t('flows.evidence.flags')}</th>
              <th className="px-4 py-2.5">{t('flows.evidence.len')}</th>
              <th className="px-4 py-2.5">{t('flows.evidence.info')}</th>
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
