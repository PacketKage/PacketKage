import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { EmptyState, ErrorState } from '../components/states'
import { mutateError, mutateSuccess } from '../components/toasts'
import { SkeletonRow, SkeletonStatus, StatusPill, formatBytes } from '../components/ui'
import { useCaptures } from '../hooks/captures'
import type { Case, TimelineEvent } from '../types/api'

export function CasesPage() {
  const queryClient = useQueryClient()
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
      mutateSuccess(`Case created — ${c.name}`, 'case-create')
    },
    onError: (err) => {
      setCreateError(err.message)
      mutateError('Case creation', err, 'case-create')
    },
  })

  const addCapture = useMutation({
    mutationFn: (captureId: string) => api.addCaptureToCase(selectedCaseId!, captureId),
    onSuccess: (_detail, captureId) => {
      invalidate()
      mutateSuccess('Capture added to case', `case-add-${captureId}`)
    },
    onError: (err, captureId) =>
      mutateError('Adding capture', err, `case-add-${captureId}`),
  })

  const removeCapture = useMutation({
    mutationFn: (captureId: string) => api.removeCaptureFromCase(selectedCaseId!, captureId),
    onSuccess: (_detail, captureId) => {
      invalidate()
      mutateSuccess('Capture removed from case', `case-remove-${captureId}`)
    },
    onError: (err, captureId) =>
      mutateError('Removing capture', err, `case-remove-${captureId}`),
  })

  const closeCase = useMutation({
    mutationFn: () => api.closeCase(selectedCaseId!),
    onSuccess: () => {
      invalidate()
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      mutateSuccess('Case closed', 'case-close')
    },
    onError: (err) => mutateError('Closing case', err, 'case-close'),
  })

  const active: Case | null =
    detail ?? cases?.find((c) => c.id === selectedCaseId) ?? null
  const inCase = new Set(active?.capture_ids ?? [])
  const available = (captures ?? []).filter((c) => c.status === 'completed' && !inCase.has(c.id))

  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold text-fg">Cases</h1>
      <p className="mt-1 mb-6 text-sm text-fg-subtle">
        Group related captures into one investigation — merged timeline, combined alerts,
        one story.
      </p>

      {/* Create + case list */}
      <div className="mb-6 flex flex-wrap items-start gap-4">
        <div className="flex flex-1 flex-col gap-2">
          <div className="flex gap-2">
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Case name — e.g. Incident-2026-09-11"
              aria-label="Case name"
              className="flex-1 rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-sm text-fg placeholder-fg-subtle focus:border-accent/50 focus:outline-none"
            />
            <button
              disabled={!newName.trim() || createCase.isPending}
              onClick={() => createCase.mutate()}
              className="rounded-lg bg-accent/10 px-4 py-1.5 text-sm font-medium text-accent ring-1 ring-accent/30 hover:bg-accent/20 disabled:opacity-50"
            >
              {createCase.isPending ? 'Creating…' : '+ New case'}
            </button>
          </div>
          <input
            value={newDescription}
            onChange={(e) => setNewDescription(e.target.value)}
            placeholder="Description (optional)"
            aria-label="Case description"
            className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-sm text-fg placeholder-fg-subtle focus:border-accent/50 focus:outline-none"
          />
          {createError && <p className="text-xs text-danger">{createError}</p>}
        </div>

        <div className="w-72 space-y-1">
          {isLoading ? (
            <SkeletonStatus label="Loading cases…">
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
              No cases yet — create one and add analyzed captures.
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
                  {c.capture_ids.length} cap
                </span>
                {c.status === 'closed' && (
                  <span className="rounded bg-surface-3 px-1.5 py-0.5 text-xs uppercase text-fg-subtle">
                    closed
                  </span>
                )}
              </button>
            ))
          )}
        </div>
      </div>

      {/* Case detail */}
      {!active ? (
        <EmptyState>Select or create a case to see its investigation.</EmptyState>
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
                  Close case
                </button>
              ) : (
                <span className="rounded-lg bg-surface-3 px-3 py-1 text-xs text-fg-muted">Closed</span>
              )}
            </div>

            {detail && (
              <div className="grid grid-cols-6 gap-3 px-5 py-4 text-sm">
                <CaseStat label="Captures" value={detail.stats.capture_count} />
                <CaseStat label="Packets" value={detail.stats.total_packets.toLocaleString()} />
                <CaseStat label="Alerts" value={detail.stats.total_alerts} />
                <CaseStat
                  label="Incidents"
                  value={detail.stats.incidents.length}
                  tone={detail.stats.incidents.length > 0 ? 'red' : undefined}
                />
                <CaseStat
                  label="Critical/High"
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
                <CaseStat label="Status" value={active.status} />
              </div>
            )}

            {/* Captures in case */}
            <div className="divide-y divide-border/60 border-t border-border">
              {detail?.captures.map((c) => (
                <div key={c.id} className="flex items-center gap-3 px-5 py-2.5 text-sm">
                  <span className="min-w-0 flex-1 truncate text-fg-muted">{c.filename}</span>
                  <StatusPill status={c.status} />
                  <span className="text-xs text-fg-subtle">
                    {c.packet_count.toLocaleString()} pkt · {formatBytes(c.size_bytes)}
                  </span>
                  <a
                    href={api.captureReportUrl(c.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="rounded px-2 py-1 text-xs text-info ring-1 ring-info/30 hover:bg-info/10"
                  >
                    report ↗
                  </a>
                  {active.status === 'open' && (
                    <button
                      disabled={removeCapture.isPending}
                      onClick={() => removeCapture.mutate(c.id)}
                      className="rounded px-2 py-1 text-xs text-fg-subtle ring-1 ring-border-strong hover:text-danger"
                    >
                      remove
                    </button>
                  )}
                </div>
              ))}
              {!detail?.captures.length && (
                <div className="px-5 py-3 text-xs text-fg-subtle">
                  No captures in this case yet — add one below.
                </div>
              )}
            </div>

            {/* Add capture */}
            {active.status === 'open' && (
              <div className="flex items-center gap-3 border-t border-border px-5 py-3">
                <select
                  aria-label="Add capture to case"
                  value=""
                  disabled={!available.length || addCapture.isPending}
                  onChange={(e) => e.target.value && addCapture.mutate(e.target.value)}
                  className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-sm text-fg disabled:opacity-50"
                >
                  <option value="">
                    {available.length ? '+ add a capture…' : 'no analyzed captures available'}
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
                Correlated incidents
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
                        {inc.alert_count} alerts · max {inc.max_score}
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

function CaseStat({ label, value, tone }: { label: string; value: string | number; tone?: 'red' | 'amber' }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wider text-fg-subtle">{label}</div>
      <div
        className={`mt-0.5 font-semibold ${
          tone === 'red' ? 'text-danger' : tone === 'amber' ? 'text-warning' : 'text-fg'
        }`}
      >
        {value}
      </div>
    </div>
  )
}

function CaseTimeline({ caseId }: { caseId: string }) {
  const [eventType, setEventType] = useState('')
  const { data: events, isLoading, isError, refetch } = useQuery({
    queryKey: ['caseTimeline', caseId, eventType],
    queryFn: () => api.caseTimeline(caseId, { eventType: eventType || undefined, limit: 500 }),
  })

  return (
    <div>
      <div className="mb-2 flex items-center gap-3">
        <div className="text-xs font-medium uppercase tracking-wider text-fg-subtle">
          Merged timeline ({events?.length ?? 0} events)
        </div>
        <select
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          aria-label="Filter case timeline"
          className="rounded-lg border border-border-strong bg-surface-2/50 px-2 py-1 text-xs text-fg-muted"
        >
          <option value="">all types</option>
          <option value="alert">alerts</option>
          <option value="tcp_connect">connections</option>
          <option value="dns_query">DNS queries</option>
          <option value="tcp_reset">resets</option>
          <option value="flow_failed">failures</option>
        </select>
      </div>
      {isLoading ? (
        <SkeletonStatus label="Merging timelines…">
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
        <ErrorState message="Failed to load case timeline." onRetry={() => refetch()} />
      ) : !events?.length ? (
        <EmptyState>No events in this case yet.</EmptyState>
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
