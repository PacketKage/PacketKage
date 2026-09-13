import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { api } from '../api/client'
import { CapturePicker } from '../components/CapturePicker'
import {
  EmptyState,
  Pagination,
} from '../components/states'
import { SkeletonRow, SkeletonStatBox, formatBytes, formatTime } from '../components/ui'
import { useDebouncedValue, useSelectedCapture } from '../hooks/captures'
import { fetchAllPages, useCsvExport } from '../hooks/useCsvExport'
import { csvTime } from '../utils/csv'
import type { DNSTransaction, HTTPTransaction, ProtocolStats, TLSSession } from '../types/api'

type Tab = 'dns' | 'http' | 'tls'

const PAGE_SIZE = 50

export function ProtocolPage() {
  const { analyzed, effectiveCaptureId, setCaptureId } = useSelectedCapture()
  const [tab, setTab] = useState<Tab>('dns')

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['protocolStats', effectiveCaptureId],
    queryFn: () => api.protocolStats(effectiveCaptureId!),
    enabled: !!effectiveCaptureId,
  })

  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold text-fg">Protocol Explorer</h1>
      <p className="mt-1 mb-6 text-sm text-fg-subtle">
        What is each protocol doing — not which fields live in a packet.
      </p>

      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={setCaptureId} />
        {(['dns', 'http', 'tls'] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-lg px-4 py-1.5 font-medium uppercase tracking-wide ring-1 transition ${
              tab === t
                ? 'bg-info/10 text-info ring-info/30'
                : 'text-fg-muted ring-border-strong hover:text-fg'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {!analyzed.length ? (
        <EmptyState>No analyzed captures yet.</EmptyState>
      ) : (
        <>
          {/* Protocol overview stats */}
          {statsLoading && (tab === 'dns' || tab === 'http') && (
            <div className="mb-4 grid grid-cols-5 gap-4" aria-hidden>
              {Array.from({ length: 5 }, (_, i) => (
                <SkeletonStatBox key={i} />
              ))}
            </div>
          )}
          {stats && tab === 'dns' && <DnsStats stats={stats.dns} />}
          {stats && tab === 'http' && <HttpStats stats={stats.http} />}
          {tab === 'dns' && effectiveCaptureId && <DnsTable captureId={effectiveCaptureId} />}
          {tab === 'http' && effectiveCaptureId && <HttpTable captureId={effectiveCaptureId} />}
          {tab === 'tls' && effectiveCaptureId && <TlsTable captureId={effectiveCaptureId} />}
        </>
      )}
    </div>
  )
}

// ---------------- DNS ----------------

function DnsStats({ stats }: { stats: ProtocolStats['dns'] }) {
  return (
    <div className="mb-4 grid grid-cols-5 gap-4">
      <StatBox label="Transactions" value={stats.transactions} />
      <StatBox label="Unique Domains" value={stats.unique_domains} />
      <StatBox
        label="NXDOMAIN"
        value={stats.nxdomain_count}
        tone={stats.nxdomain_count > 0 ? 'red' : undefined}
      />
      <StatBox
        label="NXDOMAIN Rate"
        value={stats.nxdomain_rate ? `${(stats.nxdomain_rate * 100).toFixed(0)}%` : '0%'}
        tone={stats.nxdomain_rate > 0.2 ? 'red' : undefined}
      />
      <StatBox
        label="Avg Latency"
        value={stats.avg_latency != null ? `${(stats.avg_latency * 1000).toFixed(1)} ms` : '—'}
      />
    </div>
  )
}

function DnsTable({ captureId }: { captureId: string }) {
  const [domain, setDomain] = useState('')
  const [nxdomainOnly, setNxdomainOnly] = useState(false)
  const [offset, setOffset] = useState(0)
  const debouncedDomain = useDebouncedValue(domain)

  const { data: page, isLoading, isError, refetch } = useQuery({
    queryKey: ['dns', captureId, debouncedDomain, nxdomainOnly, offset],
    queryFn: () =>
      api.listDns(
        captureId,
        {
          domain: debouncedDomain || undefined,
          rcode: nxdomainOnly ? 3 : undefined,
        },
        { limit: PAGE_SIZE, offset },
      ),
  })

  const txns = page?.items ?? []

  const dnsExport = useCsvExport<DNSTransaction>({
    label: 'dns',
    headers: ['Time', 'Client', 'Query', 'Type', 'Answers', 'RCode', 'Latency (s)'],
    toRow: (t) => [
      csvTime(t.timestamp), t.client_ip, t.query_name, t.query_type,
      t.response_ips, t.rcode, t.latency,
    ],
    fetchAll: () =>
      fetchAllPages((p) =>
        api.listDns(
          captureId,
          { domain: debouncedDomain || undefined, rcode: nxdomainOnly ? 3 : undefined },
          p,
        ),
      ),
  })

  return (
    <div>
      <div className="mb-3 flex items-center gap-3 text-sm">
        <input
          value={domain}
          onChange={(e) => { setDomain(e.target.value); setOffset(0) }}
          placeholder="filter by domain…"
          aria-label="Filter by domain"
          className="w-64 rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg placeholder-fg-subtle focus:border-info/50 focus:outline-none"
        />
        <button
          onClick={() => { setNxdomainOnly(!nxdomainOnly); setOffset(0) }}
          className={`rounded-lg px-3 py-1.5 ring-1 transition ${
            nxdomainOnly
              ? 'bg-danger/10 text-danger ring-danger/30'
              : 'text-fg-muted ring-border-strong hover:text-fg'
          }`}
        >
          NXDOMAIN only
        </button>
        <ExportButton onClick={dnsExport.export} pending={dnsExport.isExporting} disabled={isLoading} label="dns" />
      </div>
      <TableShell
        count={page?.total ?? 0}
        headers={['Time', 'Client', 'Query', 'Type', 'Answers', 'RCode', 'Latency']}
        loading={isLoading}
        error={isError}
        onRetry={refetch}
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
      >
        {txns.map((t) => (
          <tr key={t.id} className="border-t border-border/60 hover:bg-surface-3/30">
            <Td className="font-mono text-xs text-fg-subtle">{formatTime(t.timestamp)}</Td>
            <Td className="font-mono text-xs">{t.client_ip}</Td>
            <Td className="max-w-[280px] truncate font-mono text-xs text-fg">
              {t.query_name}
            </Td>
            <Td className="text-xs text-fg-muted">{t.query_type === '1' ? 'A' : t.query_type}</Td>
            <Td className="font-mono text-xs text-accent/80">
              {t.response_ips.length ? t.response_ips.join(', ') : '—'}
            </Td>
            <Td>
              <span
                className={`rounded px-1.5 py-0.5 text-xs font-bold ${
                  t.rcode === 0
                    ? 'bg-accent/10 text-accent'
                    : t.rcode === 3
                      ? 'bg-danger/10 text-danger'
                      : 'bg-warning/10 text-warning'
                }`}
              >
                {t.rcode === 0 ? 'NOERROR' : t.rcode === 3 ? 'NXDOMAIN' : `RC${t.rcode}`}
              </span>
            </Td>
            <Td className="text-xs text-fg-muted">
              {t.latency != null ? `${(t.latency * 1000).toFixed(1)} ms` : '—'}
            </Td>
          </tr>
        ))}
      </TableShell>
    </div>
  )
}

// ---------------- HTTP ----------------

function HttpStats({ stats }: { stats: ProtocolStats['http'] }) {
  return (
    <div className="mb-4 grid grid-cols-5 gap-4">
      <StatBox label="Transactions" value={stats.transactions} />
      <StatBox label="Methods" value={Object.keys(stats.methods).join(', ') || '—'} />
      <StatBox
        label="Errors (4xx/5xx)"
        value={
          Object.entries(stats.status_codes)
            .filter(([s]) => Number(s) >= 400)
            .reduce((a, [, c]) => a + c, 0)
        }
        tone="amber"
      />
      <StatBox label="Request Bytes" value={formatBytes(stats.total_request_bytes)} />
      <StatBox label="Response Bytes" value={formatBytes(stats.total_response_bytes)} />
    </div>
  )
}

function HttpTable({ captureId }: { captureId: string }) {
  const [hostFilter, setHostFilter] = useState('')
  const [offset, setOffset] = useState(0)
  const debouncedHost = useDebouncedValue(hostFilter)

  const { data: page, isLoading, isError, refetch } = useQuery({
    queryKey: ['http', captureId, debouncedHost, offset],
    queryFn: () =>
      api.listHttp(captureId, { host: debouncedHost || undefined }, { limit: PAGE_SIZE, offset }),
  })

  const txns = page?.items ?? []

  const httpExport = useCsvExport<HTTPTransaction>({
    label: 'http',
    headers: [
      'Time', 'Method', 'Host', 'Path', 'Status', 'User Agent',
      'Request Bytes', 'Response Bytes', 'Client IP', 'Server IP', 'Server Port',
    ],
    toRow: (t) => [
      csvTime(t.timestamp), t.method, t.host, t.path, t.status_code, t.user_agent,
      t.request_len, t.response_len, t.client_ip, t.server_ip, t.server_port,
    ],
    fetchAll: () =>
      fetchAllPages((p) => api.listHttp(captureId, { host: debouncedHost || undefined }, p)),
  })

  return (
    <div>
      <div className="mb-3 flex items-center gap-3 text-sm">
        <input
          value={hostFilter}
          onChange={(e) => { setHostFilter(e.target.value); setOffset(0) }}
          placeholder="filter by host header…"
          aria-label="Filter by host"
          className="w-64 rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg placeholder-fg-subtle focus:border-info/50 focus:outline-none"
        />
        <ExportButton onClick={httpExport.export} pending={httpExport.isExporting} disabled={isLoading} label="http" />
      </div>
      <TableShell
        count={page?.total ?? 0}
        headers={['Time', 'Method', 'Host', 'Path', 'Status', 'UA', 'Size']}
        loading={isLoading}
        error={isError}
        onRetry={refetch}
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
      >
        {txns.map((t) => (
          <tr key={t.id} className="border-t border-border/60 hover:bg-surface-3/30">
            <Td className="font-mono text-xs text-fg-subtle">{formatTime(t.timestamp)}</Td>
            <Td className="text-xs font-bold text-info">{t.method ?? '—'}</Td>
            <Td className="font-mono text-xs text-fg">{t.host ?? '—'}</Td>
            <Td className="max-w-[160px] truncate font-mono text-xs text-fg-muted">
              {t.path ?? '—'}
            </Td>
            <Td>
              <span
                className={`rounded px-1.5 py-0.5 text-xs font-bold ${
                  t.status_code != null && t.status_code < 400
                    ? 'bg-accent/10 text-accent'
                    : 'bg-danger/10 text-danger'
                }`}
              >
                {t.status_code ?? '?'}
              </span>
            </Td>
            <Td className="max-w-[180px] truncate text-xs text-fg-subtle">
              {t.user_agent ?? '—'}
            </Td>
            <Td className="text-xs text-fg-muted">
              {formatBytes(t.request_len)} / {formatBytes(t.response_len)}
            </Td>
          </tr>
        ))}
      </TableShell>
    </div>
  )
}

// ---------------- TLS ----------------

function TlsTable({ captureId }: { captureId: string }) {
  const [sniFilter, setSniFilter] = useState('')
  const [offset, setOffset] = useState(0)
  const debouncedSni = useDebouncedValue(sniFilter)

  const { data: page, isLoading, isError, refetch } = useQuery({
    queryKey: ['tls', captureId, debouncedSni, offset],
    queryFn: () =>
      api.listTls(captureId, { sni: debouncedSni || undefined }, { limit: PAGE_SIZE, offset }),
  })

  const sessions = page?.items ?? []

  const tlsExport = useCsvExport<TLSSession>({
    label: 'tls',
    headers: ['First Seen', 'Client', 'Server', 'Server Port', 'SNI', 'Version', 'Bytes', 'Packets'],
    toRow: (s) => [
      csvTime(s.first_seen), s.client_ip, s.server_ip, s.server_port, s.sni, s.version,
      s.bytes, s.packets,
    ],
    fetchAll: () => fetchAllPages((p) => api.listTls(captureId, { sni: debouncedSni || undefined }, p)),
  })

  return (
    <div>
      <div className="mb-3 flex items-center gap-3 text-sm">
        <input
          value={sniFilter}
          onChange={(e) => { setSniFilter(e.target.value); setOffset(0) }}
          placeholder="filter by SNI…"
          aria-label="Filter by SNI"
          className="w-64 rounded-lg border border-border-strong bg-surface-2/50 px-3 py-1.5 text-fg placeholder-fg-subtle focus:border-info/50 focus:outline-none"
        />
        <ExportButton onClick={tlsExport.export} pending={tlsExport.isExporting} disabled={isLoading} label="tls" />
      </div>
      <TableShell
        count={page?.total ?? 0}
        headers={['First Seen', 'Client', 'Server', 'SNI', 'Bytes', 'Packets']}
        loading={isLoading}
        error={isError}
        onRetry={refetch}
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
      >
        {sessions.map((s) => (
          <tr key={s.id} className="border-t border-border/60 hover:bg-surface-3/30">
            <Td className="font-mono text-xs text-fg-subtle">{formatTime(s.first_seen)}</Td>
            <Td className="font-mono text-xs">{s.client_ip}</Td>
            <Td className="font-mono text-xs">
              {s.server_ip}
              <span className="text-fg-subtle">:{s.server_port}</span>
            </Td>
            <Td className="font-mono text-xs text-info">{s.sni ?? '— (encrypted/no SNI)'}</Td>
            <Td className="text-xs text-fg-muted">{formatBytes(s.bytes)}</Td>
            <Td className="text-xs text-fg-muted">{s.packets}</Td>
          </tr>
        ))}
      </TableShell>
    </div>
  )
}

// ---------------- shared bits ----------------

function StatBox({
  label,
  value,
  tone,
}: {
  label: string
  value: string | number
  tone?: 'red' | 'amber'
}) {
  return (
    <div className="rounded-xl border border-border bg-surface-2/50 p-4">
      <div className="text-xs uppercase tracking-wider text-fg-subtle">{label}</div>
      <div
        className={`mt-1 text-xl font-semibold ${
          tone === 'red' ? 'text-danger' : tone === 'amber' ? 'text-warning' : 'text-fg'
        }`}
      >
        {value}
      </div>
    </div>
  )
}

function TableShell({
  headers,
  count,
  loading,
  error,
  onRetry,
  footer,
  children,
}: {
  headers: string[]
  count: number
  loading?: boolean
  error?: boolean
  onRetry: () => void
  footer?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div
      className="overflow-hidden rounded-xl border border-border bg-surface-2/50"
      role={loading ? 'status' : undefined}
    >
      <div className="border-b border-border px-4 py-3 text-sm text-fg-muted">
        {error ? (
          <span className="flex items-center gap-3 text-danger">
            Failed to load records.
            <button
              onClick={onRetry}
              className="rounded-lg bg-surface-3 px-3 py-1 text-xs text-fg-muted ring-1 ring-border-strong hover:text-fg"
            >
              Retry
            </button>
          </span>
        ) : loading ? (
          <>
            <span className="sr-only">Loading records…</span>
            <span aria-hidden>
              <SkeletonRow className="w-24" />
            </span>
          </>
        ) : (
          `${count.toLocaleString()} records`
        )}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs uppercase tracking-wider text-fg-subtle">
              {headers.map((h) => (
                <th key={h} className="px-4 py-2.5">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <SkeletonTds headers={headers} rows={8} />
            ) : (
              children
            )}
          </tbody>
        </table>
      </div>
      {footer}
    </div>
  )
}

/** Skeleton body rows for TableShell — one td per column, varied widths. */
function SkeletonTds({ headers, rows }: { headers: string[]; rows: number }) {
  const widths = ['w-24', 'w-20', 'w-40', 'w-14', 'w-24', 'w-20', 'w-28']
  return (
    <>
      {Array.from({ length: rows }, (_, r) => (
        <tr key={r} className="border-t border-border/60" aria-hidden>
          {headers.map((h, c) => (
            <td key={h} className="px-4 py-2">
              <SkeletonRow className={widths[c % widths.length]} />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}

function Td({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <td className={`px-4 py-2 text-fg-muted ${className}`}>{children}</td>
}

/** Small accessible CSV export button (shared by DNS/HTTP/TLS tables). */
function ExportButton({
  onClick,
  pending,
  disabled,
  label,
}: {
  onClick: () => void
  pending: boolean
  disabled?: boolean
  label: string
}) {
  return (
    <button
      onClick={onClick}
      disabled={pending || disabled}
      aria-label={`Export ${label} to CSV`}
      title={`Export filtered ${label} to CSV`}
      className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs text-fg-muted ring-1 ring-border-strong transition hover:text-fg disabled:pointer-events-none disabled:opacity-50"
    >
      <Download size={12} aria-hidden />
      {pending ? 'Exporting…' : 'CSV'}
    </button>
  )
}
