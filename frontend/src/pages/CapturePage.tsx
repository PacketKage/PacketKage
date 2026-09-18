import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Trash2 } from 'lucide-react'
import { api } from '../api/client'
import { Modal } from '../components/Modal'
import { StatusPill, formatBytes } from '../components/ui'
import { mutateError, mutateSuccess, watchJobForToast } from '../components/toasts'
import { useCaptures } from '../hooks/captures'
import { useAuth } from '../auth/AuthContext'
import { useT } from '../i18n/LocaleContext'
import type { Capture, Job } from '../types/api'

export function CapturePage() {
  const t = useT()
  const [selectedCapture, setSelectedCapture] = useState<Capture | null>(null)
  const [parser, setParser] = useState('')
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [liveJob, setLiveJob] = useState<Job | null>(null)
  const [pendingDelete, setPendingDelete] = useState<Capture | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const queryClient = useQueryClient()
  const { isAdmin } = useAuth()

  const { data: parsers } = useQuery({ queryKey: ['parsers'], queryFn: api.parsers })
  const { data: captures } = useCaptures()

  const upload = useMutation({
    mutationFn: api.uploadCapture,
    onSuccess: async (capture) => {
      setUploadError(null)
      setSelectedCapture(capture)
      mutateSuccess(t('capture.uploaded', { filename: capture.filename }))
      await queryClient.invalidateQueries({ queryKey: ['captures'] })
    },
    onError: (err) => {
      setUploadError(err.message)
      mutateError(t('capture.upload.action'), err, 'capture-upload')
    },
  })

  const analyze = useMutation({
    mutationFn: (captureId: string) => api.analyzeCapture(captureId, parser || undefined),
    onSuccess: (job) => {
      setLiveJob(job)
      queryClient.invalidateQueries({ queryKey: ['captures'] })
      mutateSuccess(t('capture.analysis_started'))
      watchJobForToast(job.id)
    },
    onError: (err) => mutateError(t('capture.analyze.action'), err),
  })

  // Delete needs to refresh everything that embeds capture data — the
  // shared captures list plus case details whose stats include it.
  const deleteCapture = useMutation({
    mutationFn: (captureId: string) => api.deleteCapture(captureId),
    onSuccess: async (_result, captureId) => {
      setPendingDelete(null)
      if (selectedCapture?.id === captureId) setSelectedCapture(null)
      mutateSuccess(t('capture.deleted'))
      await queryClient.invalidateQueries({ queryKey: ['captures'] })
      await queryClient.invalidateQueries({ queryKey: ['cases'] })
    },
    onError: (err) => {
      mutateError(t('capture.delete.action'), err, `capture-delete-${pendingDelete?.id ?? ''}`)
    },
  })

  // SSE live progress for the running job (falls back to captures polling).
  // Subscribe ONCE per job id — liveJob changes on every snapshot; depending
  // on it would tear down and reopen the EventSource for each progress tick.
  const liveJobId = liveJob?.id ?? null
  const liveJobActive =
    !!liveJob && liveJob.status !== 'completed' && liveJob.status !== 'failed'
  useEffect(() => {
    if (!liveJobId || !liveJobActive) return
    const unsubscribe = api.streamJob(
      liveJobId,
      (job) => setLiveJob(job),
      () => queryClient.invalidateQueries({ queryKey: ['captures'] }),
    )
    return unsubscribe
  }, [liveJobId, liveJobActive, queryClient])

  // Selected capture status from the shared captures list (post-refresh source of truth)
  const captureRow = captures?.find((c) => c.id === selectedCapture?.id) ?? null
  // The live job snapshot drives the in-progress display, but the polled DB
  // row wins once it reaches a terminal state — if an SSE message is ever
  // lost or malformed, the card self-heals on the next captures poll
  // instead of staying pinned at "analyzing" forever.
  const captureRowTerminal =
    captureRow?.status === 'completed' || captureRow?.status === 'failed'
  const current =
    liveJob && (liveJob.status === 'running' || liveJob.status === 'queued') && !captureRowTerminal
      ? {
          ...(captureRow ?? selectedCapture ?? undefined),
          status: 'analyzing' as const,
          analysis_progress:
            liveJob.status === 'running' ? Math.max(1, Math.round(liveJob.progress)) : 1,
        }
      : (captureRow ?? selectedCapture)
  const busy = upload.isPending || analyze.isPending

  const protocolRows = useMemo(() => {
    const summary = current?.summary?.protocol_counts
    if (!summary) return []
    const max = Math.max(...Object.values(summary))
    return Object.entries(summary)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([name, count]) => ({ name, count, pct: (count / max) * 100 }))
  }, [current])

  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold text-fg">{t('capture.title')}</h1>
      <p className="mt-1 mb-6 text-sm text-fg-subtle">{t('capture.subtitle')}</p>

      {/* Upload zone */}
      <div className="rounded-xl border border-dashed border-border-strong bg-surface-2/50 p-8">
        <div className="flex flex-col items-center gap-3">
          <div className="text-3xl font-light text-fg-subtle">{t('capture.pcap_label')}</div>
          <p className="text-sm text-fg-muted">
            {t('capture.drop_zone', {
              ext: '.pcap',
            })}{' '}
            <span className="text-fg-muted">.pcapng</span>
          </p>
          <input
            ref={fileRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) upload.mutate(f)
              e.target.value = ''
            }}
          />
          <button
            disabled={busy}
            onClick={() => fileRef.current?.click()}
            className="rounded-lg bg-accent/10 px-5 py-2 text-sm font-medium text-accent ring-1 ring-accent/30 transition hover:bg-accent/20 disabled:opacity-50"
          >
            {upload.isPending ? t('capture.uploading') : t('capture.select_file')}
          </button>
          {uploadError && <p className="text-sm text-danger">{uploadError}</p>}
        </div>
      </div>

      {/* Parser selection */}
      <div className="mt-6 flex items-center gap-3 text-sm">
        <span className="text-fg-subtle">{t('capture.parser')}</span>
        {['', 'scapy', 'tshark']
          .filter((p) => p !== 'tshark' || parsers?.tshark)
          .map((p) => (
            <button
              key={p}
              onClick={() => setParser(p)}
              className={`rounded-lg px-3 py-1.5 ring-1 transition ${
                parser === p
                  ? 'bg-accent/10 text-accent ring-accent/30'
                  : 'text-fg-muted ring-border-strong hover:text-fg'
              }`}
              title={p === '' ? t('capture.parser.title') : t('capture.parser.title_named', { name: p })}
            >
              {p === '' ? t('capture.parser.auto') : p}
            </button>
          ))}
        {parsers && (
          <span className="ml-2 text-xs text-fg-subtle">
            {t('capture.parser.available', {
              list: Object.entries(parsers)
                .filter(([, v]) => v)
                .map(([k]) => k)
                .join(', '),
            })}
          </span>
        )}
      </div>

      <LiveCapturePanel />

      {/* Selected capture detail */}
      {current && (
        <div className="mt-6 rounded-xl border border-border bg-surface-2/50">
          <div className="flex flex-wrap items-center gap-4 border-b border-border px-5 py-4">
            <div className="flex-1">
              <div className="font-medium text-fg">{current.filename}</div>
              <div className="mt-0.5 text-xs text-fg-subtle">
                {formatBytes(current.size_bytes ?? 0)} ·{' '}
                {t('capture.detail.packets', { count: current.packet_count ?? 0 })}
                {current.parser_used && t('capture.detail.parsed_by', { parser: current.parser_used })}
              </div>
            </div>
            <StatusPill status={current.status} />
            {isAdmin && (
              <button
                // `current` may be the synthesized analyzing object; the button
                // is disabled exactly then, so the modal only ever gets a full row
                onClick={() => setPendingDelete(current as Capture)}
                aria-label={t('capture.detail.delete_aria', { name: current.filename })}
                title={t('capture.detail.delete_title')}
                disabled={current.status === 'queued' || current.status === 'analyzing'}
                className="rounded-lg p-1.5 text-fg-subtle transition hover:bg-danger/10 hover:text-danger disabled:opacity-40"
              >
                <Trash2 size={15} aria-hidden />
              </button>
            )}
            {current.status === 'created' && (
              <button
                disabled={analyze.isPending}
                onClick={() => analyze.mutate(current.id)}
                className="rounded-lg bg-accent/10 px-4 py-1.5 text-sm font-medium text-accent ring-1 ring-accent/30 hover:bg-accent/20 disabled:opacity-50"
              >
                {analyze.isPending ? t('capture.detail.starting') : t('capture.detail.analyze')}
              </button>
            )}
            {(current.status === 'analyzing' || current.status === 'queued') && (
              <span className="text-sm text-warning">{t('capture.detail.analysis_running')}</span>
            )}
          </div>

          {/* Progress */}
          {(current.status === 'analyzing' || current.status === 'queued') && (
            <div className="px-5 py-3">
              <div className="mb-1.5 flex justify-between text-xs text-fg-subtle">
                <span>
                  {liveJob?.status === 'running' && liveJob.stage
                    ? liveJob.stage
                    : current.status === 'queued'
                      ? t('capture.detail.queued')
                      : t('capture.detail.working')}
                </span>
                <span>{current.analysis_progress}%</span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-surface-3">
                <div
                  className="h-full rounded-full bg-warning transition-all"
                  style={{ width: `${current.analysis_progress}%` }}
                />
              </div>
            </div>
          )}

          {current.status === 'failed' && current.error && (
            <div className="px-5 py-3 text-sm text-danger">{current.error}</div>
          )}

          {/* Summary results */}
          {current.status === 'completed' && (
            <div className="space-y-4 px-5 py-4">
              <div className="grid grid-cols-4 gap-4 text-sm">
                <SummaryStat label={t('capture.summary.packets')} value={current.packet_count.toLocaleString()} />
                <SummaryStat
                  label={t('capture.summary.source_ips')}
                  value={current.summary.unique_source_ips ?? 0}
                />
                <SummaryStat
                  label={t('capture.summary.destination_ips')}
                  value={current.summary.unique_destination_ips ?? 0}
                />
                <SummaryStat
                  label={t('capture.summary.protocols')}
                  value={Object.keys(current.summary.protocol_counts ?? {}).length}
                />
              </div>

              {protocolRows.length > 0 && (
                <div>
                  <div className="mb-2 text-xs uppercase tracking-wider text-fg-subtle">
                    {t('capture.summary.protocol_distribution')}
                  </div>
                  <div className="space-y-1.5">
                    {protocolRows.map((p) => (
                      <div key={p.name} className="flex items-center gap-3 text-xs">
                        <span className="w-16 text-right font-mono text-fg-muted">{p.name}</span>
                        <div className="h-2 flex-1 overflow-hidden rounded bg-surface-3">
                          <div
                            className="h-full rounded bg-info/60"
                            style={{ width: `${p.pct}%` }}
                          />
                        </div>
                        <span className="w-12 text-fg-subtle">{p.count.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(current.summary.top_talkers?.length ?? 0) > 0 && (
                <div>
                  <div className="mb-2 text-xs uppercase tracking-wider text-fg-subtle">
                    {t('capture.summary.top_talkers')}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {current.summary.top_talkers!.slice(0, 6).map((t) => (
                      <span
                        key={t.ip}
                        className="rounded-lg bg-surface-3/60 px-3 py-1.5 font-mono text-xs text-fg-muted ring-1 ring-border-strong"
                      >
                        {t.ip}
                        <span className="ml-2 text-fg-subtle">{t.packets} pkt</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Existing captures */}
      {captures && captures.length > 0 && (
        <div className="mt-6 rounded-xl border border-border bg-surface-2/50">
          <div className="border-b border-border px-4 py-3 text-sm font-medium text-fg-muted">
            {t('capture.all_captures')}
          </div>
          <div className="divide-y divide-border/60">
            {captures.map((c) => (
              <div
                key={c.id}
                className={`group flex items-center gap-3 px-4 py-2.5 text-left text-sm transition hover:bg-surface-3/30 ${
                  current?.id === c.id ? 'bg-accent/5' : ''
                }`}
              >
                <button
                  onClick={() => setSelectedCapture(c)}
                  className="flex flex-1 items-center gap-3 text-left"
                >
                  <span className="font-medium text-fg-muted">{c.filename}</span>
                  <StatusPill status={c.status} />
                  <span className="text-xs text-fg-subtle">
                    {c.packet_count.toLocaleString()} pkt · {formatBytes(c.size_bytes)}
                  </span>
                </button>
                {isAdmin && (
                  <button
                    onClick={() => setPendingDelete(c)}
                    aria-label={t('capture.detail.delete_aria', { name: c.filename })}
                    title={t('capture.detail.delete_title')}
                    className="rounded-lg p-1.5 text-fg-subtle opacity-0 transition hover:bg-danger/10 hover:text-danger focus-visible:opacity-100 group-hover:opacity-100"
                  >
                    <Trash2 size={14} aria-hidden />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Deletion confirmation */}
      {pendingDelete && (
        <Modal
          title={t('capture.delete.title')}
          subtitle={pendingDelete.filename}
          onClose={() => {
            if (!deleteCapture.isPending) setPendingDelete(null)
          }}
        >
          <div className="px-5 py-4">
            <p className="text-sm text-fg">
              {t('capture.delete.confirm', {
                name: pendingDelete.filename,
                size: formatBytes(pendingDelete.size_bytes ?? 0),
              })}
            </p>
            <p className="mt-2 text-sm font-medium text-danger">{t('capture.delete.irreversible')}</p>
            <div className="mt-5 flex justify-end gap-2">
              <button
                onClick={() => setPendingDelete(null)}
                disabled={deleteCapture.isPending}
                className="rounded-lg px-4 py-2 text-sm text-fg-muted ring-1 ring-border-strong transition hover:text-fg disabled:opacity-50"
              >
                {t('capture.delete.cancel')}
              </button>
              <button
                onClick={() => deleteCapture.mutate(pendingDelete.id)}
                disabled={deleteCapture.isPending}
                className="rounded-lg bg-danger/10 px-4 py-2 text-sm font-medium text-danger ring-1 ring-danger/30 transition hover:bg-danger/20 disabled:opacity-50"
              >
                {deleteCapture.isPending ? t('capture.delete.deleting') : t('capture.delete.permanently')}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}

function SummaryStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg bg-surface-3/40 px-3 py-2.5 ring-1 ring-border">
      <div className="text-xs uppercase tracking-wider text-fg-subtle">{label}</div>
      <div className="mt-0.5 font-semibold text-fg">{value}</div>
    </div>
  )
}

function LiveCapturePanel() {
  const queryClient = useQueryClient()
  const t = useT()
  const [iface, setIface] = useState('')
  const [bpf, setBpf] = useState('')
  const [duration, setDuration] = useState(60)
  const [liveError, setLiveError] = useState<string | null>(null)

  const { data: interfaces } = useQuery({
    queryKey: ['liveInterfaces'],
    queryFn: api.liveInterfaces,
    staleTime: 60_000,
  })

  // poll live status fast while recording, slow when idle
  const { data: live } = useQuery({
    queryKey: ['liveStatus'],
    queryFn: api.liveStatus,
    refetchInterval: (q) => (q.state.data?.status === 'running' ? 1000 : false),
  })

  const start = useMutation({
    mutationFn: () =>
      api.liveStart({
        // effectiveIface, not raw state — the select defaults to interfaces[0]
        // but iface stays '' until the user manually changes it
        interface: effectiveIface,
        bpf: bpf || undefined,
        max_seconds: duration,
      }),
    onSuccess: (_status) => {
      setLiveError(null)
      queryClient.invalidateQueries({ queryKey: ['liveStatus'] })
      mutateSuccess(t('live.started'))
    },
    onError: (err) => {
      setLiveError(err.message)
      mutateError(t('live.start.action'), err, 'live-start')
    },
  })

  const stop = useMutation({
    mutationFn: api.liveStop,
    onSuccess: ({ capture }) => {
      queryClient.invalidateQueries({ queryKey: ['liveStatus'] })
      queryClient.invalidateQueries({ queryKey: ['captures'] })
      mutateSuccess(t('live.stopped_toast', { filename: capture.filename }))
    },
    onError: (err) => {
      setLiveError(err.message)
      mutateError(t('live.stop.action'), err, 'live-stop')
    },
  })

  const running = live?.status === 'running'
  // default to the first detected interface when the user never touches the select
  const effectiveIface = iface || interfaces?.[0] || ''

  return (
    <div className="mt-6 rounded-xl border border-info/20 bg-info/5 p-5">
      <div className="mb-3 flex items-center gap-3">
        <span className="h-2 w-2 rounded-full bg-info"></span>
        <div className="flex-1">
          <div className="text-sm font-medium text-fg">{t('live.title')}</div>
          <div className="text-xs text-fg-subtle">{t('live.subtitle')}</div>
        </div>
        {running && (
          <span className="flex items-center gap-1.5 rounded-full bg-accent/10 px-3 py-1 text-xs font-medium text-accent ring-1 ring-accent/30">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
            {t('live.recording', {
              packets: live?.packet_count.toLocaleString(),
              seconds: live?.elapsed_seconds.toFixed(0),
            })}
          </span>
        )}
      </div>

      {!running ? (
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <select
            aria-label={t('live.network_interface')}
            value={effectiveIface}
            onChange={(e) => setIface(e.target.value)}
            className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg"
          >
            {(interfaces ?? []).map((i) => (
              <option key={i} value={i}>
                {i}
              </option>
            ))}
          </select>
          <input
            value={bpf}
            onChange={(e) => setBpf(e.target.value)}
            placeholder={t('live.bpf_placeholder')}
            aria-label={t('live.bpf_label')}
            className="w-72 rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg placeholder-fg-subtle focus:border-info/50 focus:outline-none"
          />
          <select
            aria-label={t('live.duration')}
            value={duration}
            onChange={(e) => setDuration(Number(e.target.value))}
            className="rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg"
          >
            {[15, 30, 60, 300, 900].map((d) => (
              <option key={d} value={d}>
                {d < 60 ? `${d}s` : `${d / 60}min`}
              </option>
            ))}
          </select>
          <button
            disabled={!effectiveIface || start.isPending}
            onClick={() => start.mutate()}
            className="rounded-lg bg-info/10 px-4 py-1.5 text-sm font-medium text-info ring-1 ring-info/30 transition hover:bg-info/20 disabled:opacity-50"
          >
            {start.isPending ? t('capture.detail.starting') : t('live.start')}
          </button>
          {live?.status === 'stopped' && (
            <span className="text-xs text-accent">
              {t('live.stopped', { packets: live.packet_count.toLocaleString() })}
            </span>
          )}
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span className="font-mono text-xs text-fg-muted">
            {live?.interface}
            {live?.bpf ? t('live.filter', { filter: live.bpf }) : ''}
            {t('live.auto_stop', { seconds: Math.max(0, (live?.max_seconds ?? 0) - (live?.elapsed_seconds ?? 0)).toFixed(0) })}
          </span>
          <button
            disabled={stop.isPending}
            onClick={() => stop.mutate()}
            className="rounded-lg bg-danger/10 px-4 py-1.5 text-sm font-medium text-danger ring-1 ring-danger/30 transition hover:bg-danger/20 disabled:opacity-50"
          >
            {stop.isPending ? t('live.stopping') : t('live.stop_analyze')}
          </button>
        </div>
      )}

      {liveError && <p className="mt-3 text-sm text-danger">{liveError}</p>}
      {live?.status === 'failed' && live.error && (
        <p className="mt-3 text-sm text-danger">{live.error}</p>
      )}
    </div>
  )
}
