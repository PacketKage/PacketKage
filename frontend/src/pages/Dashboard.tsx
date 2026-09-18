import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import {
  SkeletonStatBox,
  SkeletonTable,
  StatusPill,
  formatBytes,
  formatDuration,
} from '../components/ui'
import { useCaptures } from '../hooks/captures'
import { useT } from '../i18n/LocaleContext'
import type { Capture } from '../types/api'

export function Dashboard() {
  const navigate = useNavigate()
  const { data: captures, isLoading } = useCaptures()
  const t = useT()

  const { data: jobs } = useQuery({
    queryKey: ['jobs'],
    queryFn: api.listJobs,
    refetchInterval: (q) => {
      const active = q.state.data?.some((j) => j.status === 'running' || j.status === 'queued')
      return active ? 1500 : 15000
    },
  })

  const completed = captures?.filter((c) => c.status === 'completed') ?? []
  const totalPackets = completed.reduce((acc, c) => acc + c.packet_count, 0)
  const activeJobs = jobs?.filter((j) => j.status === 'running' || j.status === 'queued') ?? []
  const activeJob = activeJobs[0]
  // captures are listed newest-first — index 0 is the most recent analysis
  const latestSummary = completed[0]?.summary
  const lastFlowSummary = latestSummary?.flow_summary ?? null
  const alertSummary = latestSummary?.alert_summary ?? null

  return (
    <div className="p-8">
      <div className="mb-6 flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-fg">{t('dashboard.title')}</h1>
          <p className="mt-1 text-sm text-fg-subtle">{t('dashboard.subtitle')}</p>
        </div>
        <Link
          to="/capture"
          className="rounded-lg bg-accent/10 px-4 py-2 text-sm font-medium text-accent ring-1 ring-accent/30 transition hover:bg-accent/20"
        >
          {t('dashboard.upload_pcap')}
        </Link>
      </div>

      {/* Top statistics */}
      {isLoading ? (
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4" aria-hidden>
          {Array.from({ length: 4 }, (_, i) => (
            <SkeletonStatBox key={i} />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
          <StatCard label={t('dashboard.stat.captures')} value={captures?.length ?? 0} />
          <StatCard label={t('dashboard.stat.analyzed')} value={completed.length} tone="emerald" />
          <StatCard label={t('dashboard.stat.total_packets')} value={totalPackets.toLocaleString()} />
          <StatCard
            label={t('dashboard.stat.active_jobs')}
            value={activeJobs.length}
            tone={activeJobs.length > 0 ? 'amber' : undefined}
          />
        </div>
      )}

      {/* Active job banner */}
      {activeJob && (
        <div className="mt-6 rounded-xl border border-warning/20 bg-warning/5 p-4">
          <div className="mb-2 flex items-center justify-between text-sm">
            <span className="font-medium text-warning">
              {t('dashboard.analysis_in_progress', { stage: activeJob.stage })}
            </span>
            <span className="text-warning">{activeJob.progress}%</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-surface-3">
            <div
              className="h-full rounded-full bg-warning transition-all"
              style={{
                width: `${activeJob.progress}%`,
                backgroundImage:
                  'repeating-linear-gradient(45deg, transparent, transparent 6px, color-mix(in oklab, var(--bg) 18%, transparent) 6px, color-mix(in oklab, var(--bg) 18%, transparent) 12px)',
              }}
            />
          </div>
        </div>
      )}

      {/* Flow summary (Step 2) */}
      {lastFlowSummary && (
        <div className="mt-4 grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
          <FlowStat label={t('dashboard.flow.flows')} value={lastFlowSummary.flow_count ?? 0} />
          <FlowStat label="TCP" value={lastFlowSummary.tcp_flows ?? 0} />
          <FlowStat label="UDP" value={lastFlowSummary.udp_flows ?? 0} />
          <FlowStat
            label={t('dashboard.flow.failed')}
            value={lastFlowSummary.failed_flows ?? 0}
            tone="red"
          />
          <FlowStat
            label={t('dashboard.flow.resets')}
            value={lastFlowSummary.reset_flows ?? 0}
            tone="red"
          />
          <FlowStat
            label={t('dashboard.flow.retransmitting')}
            value={lastFlowSummary.retransmitting_flows ?? 0}
            tone="amber"
          />
        </div>
      )}

      {/* Alerts strip (Step 4) */}
      {alertSummary && alertSummary.total > 0 && (
        <button
          onClick={() => navigate('/alerts')}
          className="mt-4 flex w-full items-center gap-4 rounded-xl border border-danger/20 bg-danger/5 px-5 py-4 text-left transition hover:bg-danger/10"
        >
          <div className="flex-1">
            <div className="text-sm font-medium text-danger">
              {t('dashboard.alert_summary', { count: alertSummary.total, max: alertSummary.max_score })}
            </div>
            <div className="mt-1 flex gap-2 text-xs">
              {Object.entries(alertSummary.by_severity)
                .filter(([, n]) => n > 0)
                .map(([sev, n]) => (
                  <span key={sev} className="rounded bg-surface-3/60 px-2 py-0.5 text-fg-muted">
                    {sev}: {n}
                  </span>
                ))}
            </div>
          </div>
          <span className="text-xs text-danger">{t('dashboard.view_alerts')}</span>
        </button>
      )}

      {/* Captures table */}
      <div className="mt-6 overflow-hidden rounded-xl border border-border bg-surface-2/50">
        <div className="border-b border-border px-4 py-3 text-sm font-medium text-fg">
          {t('dashboard.recent_captures')}
        </div>
        {isLoading ? (
          <div className="p-4">
            <SkeletonTable
              headers={[
                t('dashboard.table.file'),
                t('dashboard.table.status'),
                t('dashboard.table.packets'),
                t('dashboard.table.size'),
                t('dashboard.table.duration'),
                t('dashboard.table.parser'),
                t('dashboard.table.progress'),
              ]}
              widths={['w-40', 'w-20', 'w-16', 'w-16', 'w-16', 'w-16', 'w-24']}
              rows={5}
              className="border-0"
            />
          </div>
        ) : !captures?.length ? (
          <EmptyState />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-fg-subtle">
                <th className="px-4 py-2.5">{t('dashboard.table.file')}</th>
                <th className="px-4 py-2.5">{t('dashboard.table.status')}</th>
                <th className="px-4 py-2.5">{t('dashboard.table.packets')}</th>
                <th className="px-4 py-2.5">{t('dashboard.table.size')}</th>
                <th className="px-4 py-2.5">{t('dashboard.table.duration')}</th>
                <th className="px-4 py-2.5">{t('dashboard.table.parser')}</th>
                <th className="px-4 py-2.5">{t('dashboard.table.progress')}</th>
              </tr>
            </thead>
            <tbody>
              {captures.map((c) => (
                <CaptureRow key={c.id} capture={c} />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function CaptureRow({ capture }: { capture: Capture }) {
  return (
    <tr className="border-t border-border/60 hover:bg-surface-3/30">
      <td className="px-4 py-2.5 font-medium text-fg">{capture.filename}</td>
      <td className="px-4 py-2.5">
        <StatusPill status={capture.status} />
      </td>
      <td className="px-4 py-2.5 font-mono text-fg-muted tabular-nums">{capture.packet_count.toLocaleString()}</td>
      <td className="px-4 py-2.5 font-mono text-fg-muted tabular-nums">{formatBytes(capture.size_bytes)}</td>
      <td className="px-4 py-2.5 font-mono text-fg-muted tabular-nums">
        {formatDuration(capture.first_packet_ts, capture.last_packet_ts)}
      </td>
      <td className="px-4 py-2.5 text-fg-muted">{capture.parser_used ?? '—'}</td>
      <td className="w-32 px-4 py-2.5">
        <div className="h-1.5 overflow-hidden rounded-full bg-surface-3">
          <div
            className={`h-full rounded-full transition-all ${
              capture.status === 'failed' ? 'bg-danger' : 'bg-success'
            }`}
            style={{ width: `${capture.analysis_progress}%` }}
          />
        </div>
      </td>
    </tr>
  )
}

const TONE_TEXT: Record<string, string> = {
  red: 'text-danger',
  amber: 'text-warning',
  emerald: 'text-fg',
  default: 'text-fg',
}

const TONE_DOT: Record<string, string> = {
  emerald: 'bg-success',
  amber: 'bg-warning',
  default: 'bg-info',
}

function FlowStat({
  label,
  value,
  tone,
}: {
  label: string
  value: number
  tone?: 'red' | 'amber'
}) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/50 p-3">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-fg-subtle">{label}</span>
      </div>
      <div className={`mt-1 text-xl font-semibold tabular-nums ${TONE_TEXT[tone ?? 'default']}`}>
        {value.toLocaleString()}
      </div>
    </div>
  )
}

function StatCard({
  label,
  value,
  tone,
}: {
  label: string
  value: string | number
  tone?: 'emerald' | 'amber'
}) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/50 p-4">
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider text-fg-subtle">{label}</span>
        <span className={`h-1.5 w-1.5 rounded-full ${TONE_DOT[tone ?? 'default']}`} />
      </div>
      <div className="mt-2 text-2xl font-semibold tabular-nums text-fg">{value}</div>
    </div>
  )
}

function EmptyState() {
  const t = useT()
  return (
    <div className="flex flex-col items-center gap-3 p-12">
      <div className="h-10 w-10 rounded-full border-2 border-dashed border-border-strong" />
      <p className="text-sm text-fg-subtle">{t('dashboard.empty.title')}</p>
      <Link
        to="/capture"
        className="rounded-lg bg-accent/10 px-4 py-2 text-sm text-accent ring-1 ring-accent/30 hover:bg-accent/20"
      >
        {t('dashboard.empty.upload')}
      </Link>
    </div>
  )
}
