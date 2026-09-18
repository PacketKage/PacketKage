import { useState } from 'react'
import { Download } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { CapturePicker } from '../components/CapturePicker'
import { Modal } from '../components/Modal'
import { EmptyState, ErrorState } from '../components/states'
import { SkeletonRow, SkeletonStatus, formatBytes, formatTime } from '../components/ui'
import { useSelectedCapture } from '../hooks/captures'
import { useCsvExport } from '../hooks/useCsvExport'
import { translate } from '../i18n/locale'
import { useT } from '../i18n/LocaleContext'
import { csvTime } from '../utils/csv'
import type { Host } from '../types/api'

export function HostsPage() {
  const { analyzed, effectiveCaptureId, setCaptureId } = useSelectedCapture()
  const t = useT()
  const [internalFilter, setInternalFilter] = useState<'' | 'true' | 'false'>('')
  const [selectedHost, setSelectedHost] = useState<Host | null>(null)

  // explicit 1000 (the endpoint max) — matches the CSV export so the table
  // never silently shows fewer hosts than the export contains
  const { data: hosts, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['hosts', effectiveCaptureId, internalFilter],
    queryFn: () =>
      api.listHosts(effectiveCaptureId!, internalFilter ? internalFilter === 'true' : undefined, 1000),
    enabled: !!effectiveCaptureId,
  })

  // CSV export of every host matching the current internal/external filter.
  // The hosts endpoint is un-paginated (single request, cap 1000).
  const hostExport = useCsvExport<Host>({
    label: translate('hosts.csv.label'),
    headers: [
      translate('hosts.csv.ip'), translate('hosts.csv.hostname'), translate('hosts.csv.internal'),
      translate('hosts.csv.role'), translate('hosts.csv.mac'), translate('hosts.csv.bytes_sent'),
      translate('hosts.csv.bytes_received'), translate('hosts.csv.packets_sent'),
      translate('hosts.csv.packets_received'), translate('hosts.csv.services'),
      translate('hosts.csv.first_seen'), translate('hosts.csv.last_seen'),
    ],
    toRow: (h) => [
      h.ip, h.hostname, h.is_internal, h.role, h.mac, h.bytes_sent, h.bytes_received,
      h.packets_sent, h.packets_received, h.services, csvTime(h.first_seen), csvTime(h.last_seen),
    ],
    fetchAll: () =>
      api.listHosts(effectiveCaptureId!, internalFilter ? internalFilter === 'true' : undefined, 1000),
  })

  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold text-fg">{t('hosts.title')}</h1>
      <p className="mt-1 mb-6 text-sm text-fg-subtle">{t('hosts.subtitle')}</p>

      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={setCaptureId} />
        {[
          { v: '', l: t('hosts.filter.all') },
          { v: 'true', l: t('hosts.filter.internal') },
          { v: 'false', l: t('hosts.filter.external') },
        ].map(({ v, l }) => (
          <button
            key={v}
            onClick={() => setInternalFilter(v as '' | 'true' | 'false')}
            className={`rounded-lg px-3 py-1.5 ring-1 transition ${
              internalFilter === v
                ? 'bg-info/10 text-info ring-info/30'
                : 'text-fg-muted ring-border-strong hover:text-fg'
            }`}
          >
            {l}
          </button>
        ))}
        <button
          onClick={hostExport.export}
          disabled={hostExport.isExporting || !effectiveCaptureId || isLoading}
          aria-label={t('hosts.export_aria')}
          title={t('hosts.export_title')}
          className="ml-auto inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs text-fg-muted ring-1 ring-border-strong transition hover:text-fg disabled:pointer-events-none disabled:opacity-50"
        >
          <Download size={12} aria-hidden />
          {hostExport.isExporting ? t('common.exporting') : t('common.csv')}
        </button>
      </div>

      {!analyzed.length ? (
        <EmptyState>{t('hosts.empty.no_analyzed')}</EmptyState>
      ) : isLoading ? (
        <SkeletonStatus label={t('hosts.skeleton')}>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3" aria-hidden>
            {Array.from({ length: 6 }, (_, i) => (
              <div
                key={i}
                className="rounded-xl border border-border bg-surface-2/50 p-4"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <SkeletonRow className="w-28" />
                      <SkeletonRow className="w-16 rounded" />
                    </div>
                    <SkeletonRow className="mt-2 w-24" />
                  </div>
                  <SkeletonRow className="w-20 rounded-lg" />
                </div>
                <div className="mt-3 flex gap-4">
                  <SkeletonRow className="w-28" />
                  <SkeletonRow className="w-28" />
                </div>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  <SkeletonRow className="w-14 rounded" />
                  <SkeletonRow className="w-14 rounded" />
                  <SkeletonRow className="w-14 rounded" />
                </div>
                <div className="mt-3">
                  <SkeletonRow className="w-40" />
                </div>
              </div>
            ))}
          </div>
        </SkeletonStatus>
      ) : isError ? (
        <ErrorState message={String(error)} onRetry={() => void refetch()} />
      ) : !hosts?.length ? (
        <EmptyState>{t('hosts.empty.no_filtered')}</EmptyState>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
          {hosts.map((h) => (
            <HostCard key={h.id} host={h} onClick={() => setSelectedHost(h)} />
          ))}
        </div>
      )}

      {selectedHost && <HostDetailModal host={selectedHost} onClose={() => setSelectedHost(null)} />}
    </div>
  )
}

function HostCard({ host, onClick }: { host: Host; onClick: () => void }) {
  const t = useT()
  const totalBytes = host.bytes_sent + host.bytes_received
  return (
    <button
      onClick={onClick}
      className="rounded-xl border border-border bg-surface-2/50 p-4 text-left transition hover:border-border-strong hover:bg-surface-3/70"
    >
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-semibold text-fg">{host.ip}</span>
            <span
              className={`rounded px-1.5 py-0.5 text-xs font-medium ring-1 ${
                host.is_internal
                  ? 'bg-accent/10 text-accent ring-accent/30'
                  : 'bg-info/10 text-info ring-info/30'
              }`}
            >
              {host.is_internal ? t('hosts.card.internal') : t('hosts.card.external')}
            </span>
          </div>
          {host.hostname && (
            <div className="mt-0.5 text-xs text-fg-subtle">{host.hostname}</div>
          )}
        </div>
        {host.role && (
          <span className="rounded-lg bg-info/10 px-2 py-1 text-xs font-medium text-info ring-1 ring-info/30">
            {host.role}
          </span>
        )}
      </div>

      <div className="mt-3 flex gap-4 text-xs text-fg-muted">
        <span>
          {t('hosts.card.sent', { bytes: formatBytes(host.bytes_sent), packets: host.packets_sent })}
        </span>
        <span>
          {t('hosts.card.received', { bytes: formatBytes(host.bytes_received), packets: host.packets_received })}
        </span>
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {host.services.slice(0, 4).map((s) => (
          <span
            key={`${s.port}-${s.transport}`}
            className="rounded bg-surface-3/60 px-1.5 py-0.5 font-mono text-xs text-fg-muted ring-1 ring-border-strong"
          >
            {s.port}/{s.service}
          </span>
        ))}
        {host.services.length > 4 && (
          <span className="text-xs text-fg-subtle">{t('common.more', { count: host.services.length - 4 })}</span>
        )}
      </div>

      <div className="mt-3 flex items-center justify-between text-xs text-fg-subtle">
        <span>{formatTime(host.first_seen)} → {formatTime(host.last_seen)}</span>
        <span>{totalBytes > 0 ? formatBytes(totalBytes) : '—'}</span>
      </div>
    </button>
  )
}

function HostDetailModal({ host, onClose }: { host: Host; onClose: () => void }) {
  const t = useT()
  return (
    <Modal
      wide
      title={host.ip}
      subtitle={`${host.hostname ? `${host.hostname} · ` : ''}${host.role ?? translate('hosts.card.no_role')} · ${host.mac ?? translate('hosts.card.no_mac')}`}
      onClose={onClose}
    >
      <div className="space-y-6 p-5">
        {/* Stats */}
        <div className="grid grid-cols-4 gap-3 text-sm">
          <MiniStat label={t('hosts.detail.sent')} value={formatBytes(host.bytes_sent)} />
          <MiniStat label={t('hosts.detail.received')} value={formatBytes(host.bytes_received)} />
          <MiniStat label={t('hosts.detail.peers')} value={host.behavior_summary.unique_peers ?? 0} />
          <MiniStat
            label={t('hosts.detail.connections')}
            value={host.behavior_summary.connections_initiated ?? 0}
          />
        </div>

        {/* Relationship tree (Module A) */}
        {(host.contacted.length > 0 || host.services.length > 0) && (
          <div>
            <SectionTitle>{t('hosts.detail.relationships')}</SectionTitle>
            <div className="rounded-lg bg-bg/60 p-4 font-mono text-xs ring-1 ring-border">
              <div className="text-fg">{host.ip}</div>
              {host.services.slice(0, 8).map((s) => (
                <div key={`${s.port}-${s.transport}`} className="ml-2 text-fg-muted">
                  ├──{' '}
                  <span className="text-accent">LISTENS</span> :{s.port}{' '}
                  <span className="text-fg-subtle">({s.service})</span>
                </div>
              ))}
              {host.contacted.slice(0, 10).map((c, i) => (
                <div key={`${c.ip}-${c.port}-${c.app_protocol}`} className="ml-2 text-fg-muted">
                  {i === Math.min(host.contacted.length, 10) - 1 ? '└──' : '├──'}{' '}
                  <span className="text-info">{c.app_protocol}</span> → {c.ip}
                  <span className="text-fg-subtle">:{c.port}</span>{' '}
                  <span className="text-fg-subtle">
                    {c.packets} pkt · {formatBytes(c.bytes)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Protocol distribution */}
        <div>
          <SectionTitle>{t('hosts.detail.protocol_activity')}</SectionTitle>
          <div className="space-y-1.5">
            {Object.entries(host.protocols)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 8)
              .map(([proto, count]) => {
                const max = Math.max(...Object.values(host.protocols))
                return (
                  <div key={proto} className="flex items-center gap-3 text-xs">
                    <span className="w-20 text-right font-mono text-fg-muted">{proto}</span>
                    <div className="h-2 flex-1 overflow-hidden rounded bg-surface-3">
                      <div
                        className="h-full rounded bg-info/60"
                        style={{ width: `${(count / max) * 100}%` }}
                      />
                    </div>
                    <span className="w-10 text-fg-subtle">{count}</span>
                  </div>
                )
              })}
          </div>
        </div>
      </div>
    </Modal>
  )
}

function MiniStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg bg-surface-3/40 px-3 py-2 ring-1 ring-border">
      <div className="text-xs uppercase tracking-wider text-fg-subtle">{label}</div>
      <div className="mt-0.5 text-sm font-semibold text-fg">{value}</div>
    </div>
  )
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-2 text-xs font-medium uppercase tracking-wider text-fg-subtle">
      {children}
    </div>
  )
}
