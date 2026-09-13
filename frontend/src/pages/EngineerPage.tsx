import { useQuery } from '@tanstack/react-query'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api } from '../api/client'
import { CapturePicker } from '../components/CapturePicker'
import { ErrorState } from '../components/states'
import { SkeletonRow, SkeletonStatus, formatBytes } from '../components/ui'
import { useSelectedCapture } from '../hooks/captures'
import type { EngineerIssue } from '../types/api'

const HEALTH_STYLE: Record<string, { label: string; cls: string }> = {
  healthy: { label: 'HEALTHY', cls: 'bg-accent/10 text-accent ring-accent/30' },
  warning: { label: 'WARNING', cls: 'bg-warning/10 text-warning ring-warning/30' },
  degraded: { label: 'DEGRADED', cls: 'bg-danger/10 text-danger ring-danger/30' },
}

const ISSUE_SEV: Record<string, string> = {
  high: 'text-danger',
  medium: 'text-warning',
  low: 'text-info',
  info: 'text-fg-muted',
}

const PROTOCOL_COLORS = [
  '#38bdf8', '#a78bfa', '#34d399', '#fbbf24', '#f87171',
  '#22d3ee', '#c084fc', '#4ade80', '#fb923c', '#94a3b8',
]

export function EngineerPage() {
  const { analyzed, effectiveCaptureId, setCaptureId } = useSelectedCapture()

  const { data: m, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['engineer', effectiveCaptureId],
    queryFn: () => api.getEngineerMetrics(effectiveCaptureId!),
    enabled: !!effectiveCaptureId,
  })

  return (
    <div className="p-8">
      <div className="mb-6 flex flex-wrap items-center gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-fg">Engineer Mode</h1>
          <p className="mt-1 text-sm text-fg-subtle">
            Network health — throughput, reliability, latency. Not security.
          </p>
        </div>
        <div className="ml-auto flex items-center gap-3">
          {m && (
            <span
              className={`rounded-lg px-4 py-1.5 text-sm font-bold ring-1 ${
                (HEALTH_STYLE[m.health] ?? HEALTH_STYLE.healthy).cls
              }`}
            >
              {(HEALTH_STYLE[m.health] ?? HEALTH_STYLE.healthy).label}
            </span>
          )}
          <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={setCaptureId} />
        </div>
      </div>

      {!analyzed.length ? (
        <div className="rounded-xl border border-border bg-surface-2/50 p-12 text-center text-sm text-fg-subtle">
          No analyzed captures yet.
        </div>
      ) : isLoading ? (
        <SkeletonStatus label="Computing network health…">
          <div className="space-y-6" aria-hidden>
            {/* health banner */}
            <SkeletonRow className="w-32 rounded-lg" />
            {/* top stats */}
            <div className="grid grid-cols-6 gap-4">
              {Array.from({ length: 6 }, (_, i) => (
                <div key={i} className="rounded-xl border border-border bg-surface-2/50 p-4">
                  <SkeletonRow className="w-1/2" />
                  <SkeletonRow className="mt-2 h-6 w-1/3" />
                </div>
              ))}
            </div>
            {/* TCP + DNS health + charts */}
            <div className="grid grid-cols-2 gap-4">
              {Array.from({ length: 4 }, (_, i) => (
                <div
                  key={i}
                  className="rounded-xl border border-border bg-surface-2/50 p-4"
                >
                  <SkeletonRow className="mb-4 w-28" />
                  <SkeletonRow className="h-44 w-full rounded-lg" />
                </div>
              ))}
            </div>
          </div>
        </SkeletonStatus>
      ) : isError ? (
        <ErrorState message={String(error)} onRetry={() => void refetch()} />
      ) : !m ? (
        <div className="rounded-xl border border-border bg-surface-2/50 p-12 text-center text-sm text-fg-subtle">
          No metrics available.
        </div>
      ) : (
        <div className="space-y-6">
          {/* Health issues */}
          {m.issues.length > 0 && (
            <div className="rounded-xl border border-border bg-surface-2/50 p-4">
              <div className="mb-2 text-xs font-medium uppercase tracking-wider text-fg-subtle">
                Detected issues
              </div>
              <div className="space-y-1.5">
                {m.issues.map((i: EngineerIssue, idx) => (
                  <div key={idx} className="flex items-start gap-2 text-sm">
                    <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${ISSUE_SEV[i.severity] ?? 'text-fg-muted'}`} aria-hidden>
                      <span className="block h-full w-full rounded-full bg-current" />
                    </span>
                    <span className="text-fg-muted">{i.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Top stats */}
          <div className="grid grid-cols-6 gap-4">
            <Metric label="Duration" value={`${m.capture_duration_s.toFixed(1)}s`} />
            <Metric label="Packets" value={m.total_packets.toLocaleString()} />
            <Metric label="Avg pps" value={m.avg_pps.toFixed(1)} />
            <Metric label="Peak pps" value={m.peak_pps.toFixed(0)} />
            <Metric label="Avg bandwidth" value={formatBps(m.avg_bandwidth_bps)} />
            <Metric label="Peak bandwidth" value={formatBps(m.peak_bandwidth_bps)} />
          </div>

          {/* TCP + DNS health */}
          <div className="grid grid-cols-2 gap-4">
            <div className="rounded-xl border border-border bg-surface-2/50 p-4">
              <div className="mb-3 text-xs font-medium uppercase tracking-wider text-fg-subtle">
                TCP reliability
              </div>
              <div className="space-y-2 text-sm">
                <HealthRow
                  label="Flows"
                  value={m.tcp.flows.toLocaleString()}
                  bad={false}
                />
                <HealthRow
                  label="Retransmissions"
                  value={`${m.tcp.retransmissions} (${(m.tcp.retransmission_ratio * 100).toFixed(1)}%)`}
                  bad={m.tcp.retransmission_ratio > 0.05}
                />
                <HealthRow
                  label="SYN retransmissions"
                  value={String(m.tcp.syn_retransmissions)}
                  bad={m.tcp.syn_retransmissions > 0}
                />
                <HealthRow
                  label="Resets"
                  value={`${m.tcp.resets} (${(m.tcp.reset_ratio * 100).toFixed(0)}%)`}
                  bad={m.tcp.reset_ratio > 0.1}
                />
                <HealthRow
                  label="Failed connections"
                  value={`${m.tcp.failed_flows} (${(m.tcp.failure_ratio * 100).toFixed(0)}%)`}
                  bad={m.tcp.failure_ratio > 0.5}
                />
                <HealthRow
                  label="One-way flows"
                  value={String(m.tcp.one_way_flows)}
                  bad={m.tcp.one_way_flows > 5}
                />
              </div>
            </div>

            <div className="rounded-xl border border-border bg-surface-2/50 p-4">
              <div className="mb-3 text-xs font-medium uppercase tracking-wider text-fg-subtle">
                DNS health
              </div>
              <div className="space-y-2 text-sm">
                <HealthRow label="Transactions" value={String(m.dns.transactions)} bad={false} />
                <HealthRow
                  label="Avg latency"
                  value={m.dns.avg_latency_ms != null ? `${m.dns.avg_latency_ms} ms` : '—'}
                  bad={(m.dns.avg_latency_ms ?? 0) > 500}
                />
                <HealthRow
                  label="P95 latency"
                  value={m.dns.p95_latency_ms != null ? `${m.dns.p95_latency_ms} ms` : '—'}
                  bad={(m.dns.p95_latency_ms ?? 0) > 1000}
                />
                <HealthRow
                  label="NXDOMAIN rate"
                  value={`${(m.dns.nxdomain_rate * 100).toFixed(0)}%`}
                  bad={m.dns.nxdomain_rate > 0.3}
                />
                <div className="mt-4 border-t border-border pt-3 text-xs font-medium uppercase tracking-wider text-fg-subtle">
                  MTU
                </div>
                <HealthRow
                  label="Max packet size"
                  value={`${m.max_packet_size} B`}
                  bad={m.mtu_boundary_packets > 0}
                />
                <HealthRow
                  label="Boundary packets"
                  value={String(m.mtu_boundary_packets)}
                  bad={m.mtu_boundary_packets > 0}
                />
              </div>
            </div>
          </div>

          {/* Throughput charts */}
          <div className="grid grid-cols-2 gap-4">
            <ChartCard title="Packets / sec">
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={m.timeseries.pps}>
                  <defs>
                    <linearGradient id="ppsGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                  <XAxis dataKey="t" stroke="#475569" fontSize={10} unit="s" />
                  <YAxis stroke="#475569" fontSize={10} />
                  <Tooltip
                    contentStyle={{
                      background: 'var(--surface)',
                      border: '1px solid #334155',
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="pps"
                    stroke="#38bdf8"
                    fill="url(#ppsGrad)"
                    strokeWidth={1.5}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </ChartCard>

            <ChartCard title="Bandwidth (bps)">
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={m.timeseries.bandwidth}>
                  <defs>
                    <linearGradient id="bwGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#34d399" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#34d399" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
                  <XAxis dataKey="t" stroke="#475569" fontSize={10} unit="s" />
                  <YAxis stroke="#475569" fontSize={10} />
                  <Tooltip
                    contentStyle={{
                      background: 'var(--surface)',
                      border: '1px solid #334155',
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="bps"
                    stroke="#34d399"
                    fill="url(#bwGrad)"
                    strokeWidth={1.5}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </ChartCard>
          </div>

          {/* Protocol distribution + top talkers */}
          <div className="grid grid-cols-2 gap-4">
            <ChartCard title="Protocol distribution">
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={Object.entries(m.protocol_distribution).map(([name, count]) => ({ name, count }))}>
                  <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="name" stroke="#475569" fontSize={10} />
                  <YAxis stroke="#475569" fontSize={10} />
                  <Tooltip
                    contentStyle={{
                      background: 'var(--surface)',
                      border: '1px solid #334155',
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {Object.entries(m.protocol_distribution).map((_, i) => (
                      <Cell key={i} fill={PROTOCOL_COLORS[i % PROTOCOL_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>

            <div className="rounded-xl border border-border bg-surface-2/50 p-4">
              <div className="mb-3 text-xs font-medium uppercase tracking-wider text-fg-subtle">
                Top talkers
              </div>
              <div className="space-y-1.5">
                {m.top_talkers.slice(0, 8).map((t) => {
                  const max = m.top_talkers[0]?.sent_bytes || 1
                  return (
                    <div key={t.ip} className="flex items-center gap-3 text-xs">
                      <span className="w-28 truncate font-mono text-fg-muted">{t.ip}</span>
                      <div className="h-2 flex-1 overflow-hidden rounded bg-surface-3">
                        <div
                          className="h-full rounded bg-info/60"
                          style={{ width: `${(t.sent_bytes / max) * 100}%` }}
                        />
                      </div>
                      <span className="w-16 text-right text-fg-subtle">
                        {formatBytes(t.sent_bytes)}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/50 p-4">
      <div className="text-xs uppercase tracking-wider text-fg-subtle">{label}</div>
      <div className="mt-1 text-xl font-semibold text-fg">{value}</div>
    </div>
  )
}

function HealthRow({ label, value, bad }: { label: string; value: string; bad: boolean }) {
  return (
    <div className="flex justify-between">
      <span className="text-fg-muted">{label}</span>
      <span className={`font-mono ${bad ? 'text-danger' : 'text-fg'}`}>{value}</span>
    </div>
  )
}

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/50 p-4">
      <div className="mb-3 text-xs font-medium uppercase tracking-wider text-fg-subtle">
        {title}
      </div>
      {children}
    </div>
  )
}

function formatBps(bps: number): string {
  if (bps > 1e9) return `${(bps / 1e9).toFixed(1)} Gbps`
  if (bps > 1e6) return `${(bps / 1e6).toFixed(1)} Mbps`
  if (bps > 1e3) return `${(bps / 1e3).toFixed(1)} Kbps`
  return `${bps.toFixed(0)} bps`
}
