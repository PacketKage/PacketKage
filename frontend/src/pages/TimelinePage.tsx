import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { CapturePicker } from '../components/CapturePicker'
import { Modal } from '../components/Modal'
import { EvidenceTable } from '../components/EvidenceTable'
import { EmptyState, ErrorState, Pagination } from '../components/states'
import { SkeletonRow, SkeletonStatus, formatTime } from '../components/ui'
import { useDebouncedValue, useSelectedCapture } from '../hooks/captures'
import type { TimelineEvent } from '../types/api'

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-danger',
  high: 'bg-warning',
  medium: 'bg-warning',
  low: 'bg-info',
}

const PAGE_SIZE = 200

export function TimelinePage() {
  const { analyzed, effectiveCaptureId, setCaptureId } = useSelectedCapture()
  const [host, setHost] = useState('')
  const [eventType, setEventType] = useState('')
  const [severity, setSeverity] = useState('')
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<TimelineEvent | null>(null)
  const debouncedHost = useDebouncedValue(host)

  const { data: page, isLoading, isError, refetch } = useQuery({
    queryKey: ['timeline', effectiveCaptureId, debouncedHost, eventType, severity, offset],
    queryFn: () =>
      api.getTimeline(effectiveCaptureId!, {
        host: debouncedHost || undefined,
        eventType: eventType || undefined,
        severity: severity || undefined,
        limit: PAGE_SIZE,
        offset,
      }),
    enabled: !!effectiveCaptureId,
  })

  const events = page?.items ?? []

  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold text-fg">Timeline</h1>
      <p className="mt-1 mb-6 text-sm text-fg-subtle">
        Chronological events — filter to &quot;everything related to X between T1 and T2&quot;.
      </p>

      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={setCaptureId} />
        <input
          value={host}
          onChange={(e) => { setHost(e.target.value); setOffset(0) }}
          placeholder="host / IP / domain…"
          aria-label="Filter by host"
          className="w-56 rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg placeholder-fg-subtle focus:border-info/50 focus:outline-none"
        />
        <select
          value={eventType}
          onChange={(e) => { setEventType(e.target.value); setOffset(0) }}
          aria-label="Filter by event type"
          className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg"
        >
          <option value="">all types</option>
          <option value="dns_query">DNS queries</option>
          <option value="dns_response">DNS responses</option>
          <option value="tcp_connect">TCP connections</option>
          <option value="udp_session">UDP sessions</option>
          <option value="http_request">HTTP</option>
          <option value="tls_handshake">TLS</option>
          <option value="flow_failed">failures</option>
          <option value="tcp_reset">resets</option>
          <option value="alert">alerts</option>
        </select>
        <select
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setOffset(0) }}
          aria-label="Filter by severity"
          className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg"
        >
          <option value="">any severity</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
        </select>
      </div>

      {!analyzed.length ? (
        <div className="rounded-xl border border-border bg-surface-2/50 p-12 text-center text-sm text-fg-subtle">
          No analyzed captures yet.
        </div>
      ) : isLoading ? (
        <SkeletonStatus label="Building timeline…">
          <div
            className="overflow-hidden rounded-xl border border-border bg-surface-2/50"
            aria-hidden
          >
            <div className="border-b border-border px-4 py-3">
              <SkeletonRow className="w-24" />
            </div>
            <div className="divide-y divide-border/60">
              {Array.from({ length: 10 }, (_, i) => (
                <div key={i} className="flex items-center gap-3 px-4 py-2">
                  <SkeletonRow className="w-16" />
                  <SkeletonRow className={`${i % 2 ? 'w-2/3' : 'w-5/6'}`} />
                  <SkeletonRow className="ml-auto w-12 rounded" />
                </div>
              ))}
            </div>
          </div>
        </SkeletonStatus>
      ) : isError ? (
        <ErrorState message="Failed to load timeline events." onRetry={() => refetch()} />
      ) : !events.length ? (
        <EmptyState>No events match the current filters.</EmptyState>
      ) : (
        <div className="overflow-hidden rounded-xl border border-border bg-surface-2/50">
          <div className="border-b border-border px-4 py-3 text-sm text-fg-muted">
            {(page?.total ?? 0).toLocaleString()} events
          </div>
          <EventList events={events} onSelect={setSelected} />
          {page && (
            <Pagination
              offset={page.offset}
              limit={page.limit}
              total={page.total}
              onPageChange={setOffset}
            />
          )}
        </div>
      )}

      {selected && <EventDetailModal event={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

function EventList({
  events,
  onSelect,
}: {
  events: TimelineEvent[]
  onSelect: (e: TimelineEvent) => void
}) {
  return (
    <div className="max-h-[65vh] overflow-y-auto">
      {events.map((e) => {
        return (
          <button
            key={e.id}
            onClick={() => onSelect(e)}
            className="flex w-full items-center gap-3 border-t border-border/60 px-4 py-2 text-left hover:bg-surface-3/30"
          >
            <span className="w-16 shrink-0 font-mono text-xs text-fg-subtle">
              {formatTime(e.timestamp)}
            </span>
            <span className="min-w-0 flex-1 truncate text-sm text-fg-muted">{e.label}</span>
            {e.severity && (
              <span
                className={`h-1.5 w-1.5 shrink-0 rounded-full ${SEVERITY_DOT[e.severity] ?? 'bg-fg-subtle'}`}
                title={e.severity}
              />
            )}
            {e.protocol && (
              <span className="shrink-0 rounded bg-surface-3/60 px-1.5 py-0.5 font-mono text-xs text-fg-subtle">
                {e.protocol}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

function EventDetailModal({
  event,
  onClose,
}: {
  event: TimelineEvent
  onClose: () => void
}) {
  const { data: flow } = useQuery({
    queryKey: ['flow', event.related_flow_id],
    queryFn: () => api.getFlow(event.related_flow_id!),
    enabled: !!event.related_flow_id,
  })

  return (
    <Modal
      title={event.label}
      subtitle={`${new Date(event.timestamp * 1000).toLocaleString()} · ${event.event_type}`}
      onClose={onClose}
    >
      <div className="space-y-4 p-5">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <Field label="Source" value={event.source_ip ?? '—'} />
            <Field
              label="Destination"
              value={
                event.destination_ip
                  ? `${event.destination_ip}${event.destination_port ? ':' + event.destination_port : ''}`
                  : '—'
              }
            />
            <Field label="Protocol" value={event.protocol ?? '—'} />
            <Field label="Domain" value={event.domain ?? '—'} />
          </div>

          <div>
            <div className="mb-1.5 text-xs font-medium uppercase tracking-wider text-fg-subtle">
              Detail
            </div>
            <div className="overflow-auto rounded-lg bg-bg/60 p-3 ring-1 ring-border">
              <EvidenceTable data={event.detail} />
            </div>
          </div>

          {flow && (
            <div>
              <div className="mb-1.5 text-xs font-medium uppercase tracking-wider text-fg-subtle">
                Related flow evidence
              </div>
              <div className="rounded-lg bg-bg/60 p-3 font-mono text-xs text-fg-muted ring-1 ring-border">
                {flow.source_ip}:{flow.source_port} → {flow.destination_ip}:{flow.destination_port}{' '}
                {flow.transport_protocol}
                {' · '}
                {flow.packets} packets, {flow.bytes} bytes, state {flow.tcp_state ?? 'n/a'}
              </div>
            </div>
          )}
        </div>
    </Modal>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-fg-subtle">{label}</div>
      <div className="mt-0.5 font-mono text-fg-muted">{value}</div>
    </div>
  )
}
