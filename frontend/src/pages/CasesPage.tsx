import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { EmptyState, ErrorState } from '../components/states'
import { mutateError, mutateSuccess } from '../components/toasts'
import { SkeletonRow, SkeletonStatus, StatusPill, formatBytes } from '../components/ui'
import { useCaptures } from '../hooks/captures'
import { useT } from '../i18n/LocaleContext'
import type { Case, TimelineEvent } from '../types/api'

export function CasesPage() {
  const queryClient = useQueryClient()
  const t = useT()
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null)
  const [newName, setNewName] = useState('')
  const [newDescription, setNewDescription] = useState('')
  const [createError, setCreateError] = useState<string | null>(null)

  const { data: cases, isLoading } = useQuery({ queryKey: ['cases'], queryFn: api.listCases })
  const { data: captures } = useCaptures()

  const { data: detail } = useQuery({
    queryKey: ['case', selectedCaseId],
    queryFn: () => api.getCase(selectedCaseId!),
    enabled: !!selectedCaseId,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['case'] })

  const createCase = useMutation({
    mutationFn: () => api.createCase(newName, newDescription || undefined),
    onSuccess: (c) => {
      setNewName('')
      setNewDescription('')
      setCreateError(null)
      setSelectedCaseId(c.id)
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      mutateSuccess(t('cases.created', { name: c.name }), 'case-create')
    },
    onError: (err) => {
      setCreateError(err.message)
      mutateError(t('cases.create.action'), err, 'case-create')
    },
  })

  const addCapture = useMutation({
    mutationFn: (captureId: string) => api.addCaptureToCase(selectedCaseId!, captureId),
    onSuccess: (_detail, captureId) => {
      invalidate()
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      mutateSuccess(t('cases.capture_added'), `case-add-${captureId}`)
    },
    onError: (err, captureId) =>
      mutateError(t('cases.add.action'), err, `case-add-${captureId}`),
  })

  const removeCapture = useMutation({
    mutationFn: (captureId: string) => api.removeCaptureFromCase(selectedCaseId!, captureId),
    onSuccess: (_detail, captureId) => {
      invalidate()
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      mutateSuccess(t('cases.capture_removed'), `case-remove-${captureId}`)
    },
    onError: (err, captureId) =>
      mutateError(t('cases.remove.action'), err, `case-remove-${captureId}`),
  })

  const closeCase = useMutation({
    mutationFn: () => api.closeCase(selectedCaseId!),
    onSuccess: () => {
      invalidate()
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      mutateSuccess(t('cases.closed_toast'), 'case-close')
    },
    onError: (err) => mutateError(t('cases.close.action'), err, 'case-close'),
  })

  const active: Case | null =
    detail ?? cases?.find((c) => c.id === selectedCaseId) ?? null
  const inCase = new Set(active?.capture_ids ?? [])
  const available = (captures ?? []).filter((c) => c.status === 'completed' && !inCase.has(c.id))

  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold text-fg">{t('cases.title')}</h1>
      <p className="mt-1 mb-6 text-sm text-fg-subtle">
        {t('cases.subtitle')}
      </p>

      {/* Create + case list */}
      <div className="mb-6 flex flex-wrap items-start gap-4">
        <div className="flex flex-1 flex-col gap-2">
          <div className="flex gap-2">
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder={t('cases.name_placeholder')}
              aria-label={t('cases.name_label')}
              className="flex-1 rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-sm text-fg placeholder-fg-subtle focus:border-accent/50 focus:outline-none"
            />
            <button
              disabled={!newName.trim() || createCase.isPending}
              onClick={() => createCase.mutate()}
              className="rounded-lg bg-accent/10 px-4 py-1.5 text-sm font-medium text-accent ring-1 ring-accent/30 hover:bg-accent/20 disabled:opacity-50"
            >
              {createCase.isPending ? t('cases.creating') : t('cases.create')}
            </button>
          </div>
          <input
            value={newDescription}
            onChange={(e) => setNewDescription(e.target.value)}
            placeholder={t('cases.description_placeholder')}
            aria-label={t('cases.description_label')}
            className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-sm text-fg placeholder-fg-subtle focus:border-accent/50 focus:outline-none"
          />
          {createError && <p className="text-xs text-danger">{createError}</p>}
        </div>

        <div className="w-72 space-y-1">
          {isLoading ? (
            <SkeletonStatus label={t('cases.skeleton')}>
              <div className="space-y-1" aria-hidden>
                {Array.from({ length: 4 }, (_, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 rounded-lg px-3 py-2 ring-1 ring-border"
                  >
                    <SkeletonRow className="flex-1" />
                    <SkeletonRow className="w-10" />
                  </div>
                ))}
              </div>
            </SkeletonStatus>
          ) : !cases?.length ? (
            <p className="rounded-lg border border-border bg-surface-2/50 p-4 text-xs text-fg-subtle">
              {t('cases.empty.no_cases')}
            </p>
          ) : (
            cases.map((c) => (
              <button
                key={c.id}
                onClick={() => setSelectedCaseId(c.id)}
                className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm transition ${
                  selectedCaseId === c.id
                    ? 'bg-accent/10 text-accent ring-1 ring-accent/30'
                    : 'text-fg-muted ring-1 ring-border hover:bg-surface-3/40'
                }`}
              >
                <span className="min-w-0 flex-1 truncate">{c.name}</span>
                <span className="text-xs uppercase text-fg-subtle">
                  {t('cases.item_caps', { count: c.capture_ids.length })}
                </span>
                {c.status === 'closed' && (
                  <span className="rounded bg-surface-3 px-1.5 py-0.5 text-xs uppercase text-fg-subtle">
                    {t('cases.item_closed')}
                  </span>
                )}
              </button>
            ))
          )}
        </div>
      </div>

      {/* Case detail */}
      {!active ? (
        <EmptyState>{t('cases.empty.select')}</EmptyState>
      ) : (
        <div className="space-y-6">
          {/* Header */}
          <div className="rounded-xl border border-border bg-surface-2/50">
            <div className="flex flex-wrap items-center gap-3 border-b border-border px-5 py-4">
              <div className="flex-1">
                <div className="font-medium text-fg">{active.name}</div>
                {active.description && (
                  <div className="mt-0.5 text-xs text-fg-subtle">{active.description}</div>
                )}
              </div>
              {active.status === 'open' ? (
                <button
                  disabled={closeCase.isPending}
                  onClick={() => closeCase.mutate()}
                  className="rounded-lg px-3 py-1.5 text-xs text-fg-muted ring-1 ring-border-strong hover:text-fg"
                >
                  {t('cases.close')}
                </button>
              ) : (
                <span className="rounded-lg bg-surface-3 px-3 py-1 text-xs text-fg-muted">{t('cases.closed')}</span>
              )}
            </div>

            {detail && (
              <div className="grid grid-cols-6 gap-3 px-5 py-4 text-sm">
                <CaseStat label={t('cases.stat.captures')} value={detail.stats.capture_count} />
                <CaseStat label={t('cases.stat.packets')} value={detail.stats.total_packets.toLocaleString()} />
                <CaseStat label={t('cases.stat.alerts')} value={detail.stats.total_alerts} />
                <CaseStat
                  label={t('cases.stat.incidents')}
                  value={detail.stats.incidents.length}
                  tone={detail.stats.incidents.length > 0 ? 'red' : undefined}
                />
                <CaseStat
                  label={t('cases.stat.critical_high')}
                  value={
                    (detail.stats.alerts_by_severity.critical ?? 0) +
                    (detail.stats.alerts_by_severity.high ?? 0)
                  }
                  tone={
                    (detail.stats.alerts_by_severity.critical ?? 0) +
                      (detail.stats.alerts_by_severity.high ?? 0) >
                    0
                      ? 'amber'
                      : undefined
                  }
                />
                <CaseStat label={t('cases.stat.status')} value={active.status} />
              </div>
            )}

            {/* Captures in case */}
            <div className="divide-y divide-border/60 border-t border-border">
              {detail?.captures.map((c) => (
                <div key={c.id} className="flex items-center gap-3 px-5 py-2.5 text-sm">
                  <span className="min-w-0 flex-1 truncate text-fg-muted">{c.filename}</span>
                  <StatusPill status={c.status} />
                  <span className="text-xs text-fg-subtle">
                    {t('cases.item_packets', { packets: c.packet_count.toLocaleString(), bytes: formatBytes(c.size_bytes) })}
                  </span>
                  <a
                    href={api.captureReportUrl(c.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="rounded px-2 py-1 text-xs text-info ring-1 ring-info/30 hover:bg-info/10"
                  >
                    {t('cases.report')}
                  </a>
                  {active.status === 'open' && (
                    <button
                      disabled={removeCapture.isPending}
                      onClick={() => removeCapture.mutate(c.id)}
                      className="rounded px-2 py-1 text-xs text-fg-subtle ring-1 ring-border-strong hover:text-danger"
                    >
                      {t('cases.remove')}
                    </button>
                  )}
                </div>
              ))}
              {!detail?.captures.length && (
                <div className="px-5 py-3 text-xs text-fg-subtle">
                  {t('cases.empty.no_captures')}
                </div>
              )}
            </div>

            {/* Add capture */}
            {active.status === 'open' && (
              <div className="flex items-center gap-3 border-t border-border px-5 py-3">
                <select
                  aria-label={t('cases.add_capture')}
                  value=""
                  disabled={!available.length || addCapture.isPending}
                  onChange={(e) => e.target.value && addCapture.mutate(e.target.value)}
                  className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-sm text-fg disabled:opacity-50"
                >
                  <option value="">
                    {available.length ? t('cases.add_placeholder') : t('cases.no_available')}
                  </option>
                  {available.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.filename}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Incidents */}
          {detail && detail.stats.incidents.length > 0 && (
            <div>
              <div className="mb-2 text-xs font-medium uppercase tracking-wider text-fg-subtle">
                {t('cases.incidents')}
              </div>
              <div className="space-y-2">
                {detail.stats.incidents.map((inc) => (
                  <div
                    key={`${inc.source_ip}-${inc.title}`}
                    className="rounded-xl border border-danger/25 bg-danger/5 px-4 py-3"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-sm font-medium text-fg">{inc.title}</span>
                      <span className="ml-auto font-mono text-xs text-fg-subtle">
                        {t('cases.incidents.count', { count: inc.alert_count, max: inc.max_score })}
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-fg-muted">{inc.story}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Merged timeline */}
          {active.capture_ids.length > 0 && (
            <CaseTimeline caseId={active.id} />
          )}
        </div>
      )}
    </div>
  )
}

const CASE_TONE_TEXT: Record<string, string> = {
  red: 'text-danger',
  amber: 'text-warning',
  default: 'text-fg',
}

function CaseStat({ label, value, tone }: { label: string; value: string | number; tone?: 'red' | 'amber' }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-fg-subtle">{label}</div>
      <div className={`mt-0.5 font-semibold ${CASE_TONE_TEXT[tone ?? 'default']}`}>
        {value}
      </div>
    </div>
  )
}

function CaseTimeline({ caseId }: { caseId: string }) {
  const t = useT()
  const [eventType, setEventType] = useState('')
  const { data: events, isLoading, isError, refetch } = useQuery({
    queryKey: ['caseTimeline', caseId, eventType],
    queryFn: () => api.caseTimeline(caseId, { eventType: eventType || undefined, limit: 500 }),
  })

  return (
    <div>
      <div className="mb-2 flex items-center gap-3">
        <div className="text-xs font-medium uppercase tracking-wider text-fg-subtle">
          {t('cases.timeline.title', { count: events?.length ?? 0 })}
        </div>
        <select
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          aria-label={t('cases.timeline.filter')}
          className="rounded-lg border border-border-strong bg-surface-2/50 px-2 py-1 text-xs text-fg-muted"
        >
          <option value="">{t('cases.timeline.all_types')}</option>
          <option value="alert">{t('cases.timeline.alerts')}</option>
          <option value="tcp_connect">{t('cases.timeline.connections')}</option>
          <option value="dns_query">{t('cases.timeline.dns_queries')}</option>
          <option value="tcp_reset">{t('cases.timeline.resets')}</option>
          <option value="flow_failed">{t('cases.timeline.failures')}</option>
        </select>
      </div>
      {isLoading ? (
        <SkeletonStatus label={t('cases.timeline.skeleton')}>
          <div className="max-h-[55vh] space-y-0 overflow-hidden rounded-xl border border-border bg-surface-2/50" aria-hidden>
            {Array.from({ length: 10 }, (_, i) => (
              <div
                key={i}
                className="flex items-center gap-3 border-t border-border/60 px-4 py-1.5 first:border-t-0"
              >
                <SkeletonRow className="w-20" />
                <SkeletonRow className={`${i % 2 ? 'w-2/3' : 'w-5/6'}`} />
                <SkeletonRow className="ml-auto w-14" />
              </div>
            ))}
          </div>
        </SkeletonStatus>
      ) : isError ? (
        <ErrorState message={t('cases.timeline.error')} onRetry={() => refetch()} />
      ) : !events?.length ? (
        <EmptyState>{t('cases.timeline.empty')}</EmptyState>
      ) : (
        <div className="max-h-[55vh] overflow-y-auto rounded-xl border border-border bg-surface-2/50">
          {events.map((e: TimelineEvent) => (
            <div
              key={e.id}
              className="flex items-center gap-3 border-t border-border/60 px-4 py-1.5 text-sm first:border-t-0"
            >
              <span className="w-20 shrink-0 font-mono text-xs text-fg-subtle">
                {new Date(e.timestamp * 1000).toLocaleTimeString()}
              </span>
              <span className="min-w-0 flex-1 truncate text-xs text-fg-muted">{e.label}</span>
              <span className="shrink-0 font-mono text-xs text-fg-subtle">
                {e.capture_id.slice(0, 8)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
