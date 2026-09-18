import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { CapturePicker } from '../components/CapturePicker'
import { Modal } from '../components/Modal'
import { EvidenceTable } from '../components/EvidenceTable'
import { EmptyState, ErrorState, Pagination } from '../components/states'
import { SkeletonRow, SkeletonStatus, formatTime } from '../components/ui'
import { useDebouncedValue, useSelectedCapture } from '../hooks/captures'
import { useT } from '../i18n/LocaleContext'
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
  const t = useT()
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
      <h1 className="text-2xl font-semibold text-fg">{t('timeline.title')}</h1>
      <p className="mt-1 mb-6 text-sm text-fg-subtle">{t('timeline.subtitle')}</p>

      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={setCaptureId} />
        <input
          value={host}
          onChange={(e) => { setHost(e.target.value); setOffset(0) }}
          placeholder={t('timeline.host_placeholder')}
          aria-label={t('timeline.filter_host')}
          className="w-56 rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg placeholder-fg-subtle focus:border-info/50 focus:outline-none"
        />
        <select
          value={eventType}
          onChange={(e) => { setEventType(e.target.value); setOffset(0) }}
          aria-label={t('timeline.filter_type')}
          className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg"
        >
          <option value="">{t('timeline.all_types')}</option>
          <option value="dns_query">{t('timeline.type.dns_query')}</option>
          <option value="dns_response">{t('timeline.type.dns_response')}</option>
          <option value="tcp_connect">{t('timeline.type.tcp_connect')}</option>
          <option value="udp_session">{t('timeline.type.udp_session')}</option>
          <option value="http_request">{t('timeline.type.http_request')}</option>
          <option value="tls_handshake">{t('timeline.type.tls_handshake')}</option>
          <option value="flow_failed">{t('timeline.type.flow_failed')}</option>
          <option value="tcp_reset">{t('timeline.type.tcp_reset')}</option>
          <option value="alert">{t('timeline.type.alert')}</option>
        </select>
        <select
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setOffset(0) }}
          aria-label={t('timeline.filter_severity')}
          className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg"
        >
          <option value="">{t('timeline.any_severity')}</option>
          <option value="critical">{t('timeline.severity.critical')}</option>
          <option value="high">{t('timeline.severity.high')}</option>
          <option value="medium">{t('timeline.severity.medium')}</option>
        </select>
      </div>

      {!analyzed.length ? (
        <div className="rounded-xl border border-border bg-surface-2/50 p-12 text-center text-sm text-fg-subtle">
          {t('timeline.empty.no_analyzed')}
        </div>
      ) : isLoading ? (
        <SkeletonStatus label={t('timeline.skeleton')}>
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
        <ErrorState message={t('timeline.error')} onRetry={() => refetch()} />
      ) : !events.length ? (
        <EmptyState>{t('timeline.empty.no_events')}</EmptyState>
      ) : (
        <div className="overflow-hidden rounded-xl border border-border bg-surface-2/50">
          <div className="border-b border-border px-4 py-3 text-sm text-fg-muted">
            {t('timeline.events_count', { count: page?.total ?? 0 })}
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
  const t = useT()
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
            <Field label={t('timeline.detail.source')} value={event.source_ip ?? '—'} />
            <Field
              label={t('timeline.detail.destination')}
              value={
                event.destination_ip
                  ? `${event.destination_ip}${event.destination_port ? ':' + event.destination_port : ''}`
                  : '—'
              }
            />
            <Field label={t('timeline.detail.protocol')} value={event.protocol ?? '—'} />
            <Field label={t('timeline.detail.domain')} value={event.domain ?? '—'} />
          </div>

          <div>
            <div className="mb-1.5 text-xs font-medium uppercase tracking-wider text-fg-subtle">
              {t('timeline.detail.title')}
            </div>
            <div className="overflow-auto rounded-lg bg-bg/60 p-3 ring-1 ring-border">
              <EvidenceTable data={event.detail} />
            </div>
          </div>

          {flow && (
            <div>
              <div className="mb-1.5 text-xs font-medium uppercase tracking-wider text-fg-subtle">
                {t('timeline.detail.related_flow')}
              </div>
              <div className="rounded-lg bg-bg/60 p-3 font-mono text-xs text-fg-muted ring-1 ring-border">
                {t('timeline.detail.flow_info', {
                  source: `${flow.source_ip}:${flow.source_port}`,
                  destination: `${flow.destination_ip}:${flow.destination_port}`,
                  protocol: flow.transport_protocol,
                  packets: flow.packets,
                  bytes: flow.bytes,
                  state: flow.tcp_state ?? t('timeline.detail.state_na'),
                })}
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
