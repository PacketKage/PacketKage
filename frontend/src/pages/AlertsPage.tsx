import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, ChevronDown, ChevronUp, Download } from 'lucide-react'
import { EvidenceTable } from '../components/EvidenceTable'
import { api } from '../api/client'
import { CapturePicker } from '../components/CapturePicker'
import { EmptyState, ErrorState } from '../components/states'
import { mutateError, mutateSuccess } from '../components/toasts'
import { SkeletonRow, SkeletonStatus, formatTime } from '../components/ui'
import { useSelectedCapture } from '../hooks/captures'
import { fetchAllPages, useCsvExport } from '../hooks/useCsvExport'
import { translate } from '../i18n/locale'
import { useT } from '../i18n/LocaleContext'
import { csvTime } from '../utils/csv'
import type { Alert } from '../types/api'

const SEVERITY_STYLE: Record<string, { badge: string; bar: string; labelKey: string }> = {
  critical: { badge: 'bg-danger/10 text-danger ring-danger/30', bar: 'bg-danger', labelKey: 'alerts.severity.critical' },
  high: { badge: 'bg-warning/10 text-warning ring-warning/30', bar: 'bg-warning', labelKey: 'alerts.severity.high' },
  medium: { badge: 'bg-warning/10 text-warning ring-warning/30', bar: 'bg-warning', labelKey: 'alerts.severity.medium' },
  low: { badge: 'bg-info/10 text-info ring-info/30', bar: 'bg-info', labelKey: 'alerts.severity.low' },
  info: { badge: 'bg-fg/10 text-fg-muted ring-fg/20', bar: 'bg-fg-muted', labelKey: 'alerts.severity.info' },
}

const RULE_KEYS: Record<string, string> = {
  port_scan: 'alerts.rule.port_scan',
  beaconing: 'alerts.rule.beaconing',
  dns_tunneling: 'alerts.rule.dns_tunneling',
  nxdomain_burst: 'alerts.rule.nxdomain_burst',
  suspicious_port: 'alerts.rule.suspicious_port',
  excessive_connection_failures: 'alerts.rule.excessive_connection_failures',
  connection_without_dns: 'alerts.rule.connection_without_dns',
  high_outbound_volume: 'alerts.rule.high_outbound_volume',
  arp_spoofing: 'alerts.rule.arp_spoofing',
  lateral_movement: 'alerts.rule.lateral_movement',
  dga_domain: 'alerts.rule.dga_domain',
  data_exfiltration: 'alerts.rule.data_exfiltration',
  low_slow_beaconing: 'alerts.rule.low_slow_beaconing',
  suspicious_user_agent: 'alerts.rule.suspicious_user_agent',
}

const isUntriaged = (a: Alert) =>
  !a.tags.includes('confirmed') && !a.tags.includes('false-positive')

const ruleLabel = (ruleName: string) => {
  const key = RULE_KEYS[ruleName]
  if (!key) return ruleName
  return translate(key)
}

export function AlertsPage() {
  const { analyzed, effectiveCaptureId, setCaptureId } = useSelectedCapture()
  const t = useT()
  const [severity, setSeverity] = useState('')
  const [unconfirmedOnly, setUnconfirmedOnly] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)
  const queryClient = useQueryClient()

  const { data: page, isLoading, isError, refetch } = useQuery({
    queryKey: ['alerts', effectiveCaptureId, severity],
    queryFn: () =>
      api.listAlerts(effectiveCaptureId!, { severity: severity || undefined }, { limit: 100 }),
    enabled: !!effectiveCaptureId,
  })

  const allAlerts = page?.items ?? []
  const alerts = unconfirmedOnly ? allAlerts.filter(isUntriaged) : allAlerts

  // CSV export of every alert matching the current filters. The server-side
  // severity filter rides the query; the client-side "hide confirmed &
  // false-positives" filter is applied post-fetch so the file matches the screen.
  const alertExport = useCsvExport<Alert>({
    label: translate('alerts.csv.label'),
    headers: [
      translate('alerts.csv.timestamp'), translate('alerts.csv.severity'), translate('alerts.csv.score'),
      translate('alerts.csv.rule'), translate('alerts.csv.title'), translate('alerts.csv.source_ip'),
      translate('alerts.csv.destination_ip'), translate('alerts.csv.destination_port'),
      translate('alerts.csv.acknowledged'), translate('alerts.csv.tags'), translate('alerts.csv.note'),
    ],
    toRow: (a) => [
      csvTime(a.timestamp), a.severity, a.score, ruleLabel(a.rule_name),
      a.title, a.source_ip, a.destination_ip, a.destination_port, a.acknowledged, a.tags, a.note,
    ],
    fetchAll: async () => {
      const rows = await fetchAllPages((p) =>
        api.listAlerts(effectiveCaptureId!, { severity: severity || undefined }, p),
      )
      return unconfirmedOnly ? rows.filter(isUntriaged) : rows
    },
  })

  const ack = useMutation({
    mutationFn: ({ id, acknowledged }: { id: string; acknowledged: boolean }) =>
      api.ackAlert(id, acknowledged),
    onSuccess: (_alert, vars) => {
      mutateSuccess(vars.acknowledged ? t('alerts.ack.success') : t('alerts.ack.removed'), `ack-${vars.id}`)
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
    onError: (err, vars) => mutateError(t('alerts.ack.action'), err, `ack-${vars.id}`),
  })

  const triage = useMutation({
    mutationFn: ({
      id,
      ...body
    }: {
      id: string
      acknowledged?: boolean
      tags?: string[]
      note?: string
    }) => api.triageAlert(id, body),
    onSuccess: (_alert, vars) => {
      mutateSuccess(vars.note !== undefined ? t('alerts.triage.note_saved') : t('alerts.triage.updated'), `triage-${vars.id}`)
      queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
    onError: (err, vars) => mutateError(t('alerts.triage.action'), err, `triage-${vars.id}`),
  })

  // capture summary for correlated incidents
  const { data: captureDetail } = useQuery({
    queryKey: ['captureDetail', effectiveCaptureId],
    queryFn: () => api.getCapture(effectiveCaptureId!),
    enabled: !!effectiveCaptureId,
  })
  const incidents = captureDetail?.summary?.incidents ?? []

  const counts = allAlerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="p-8">
      <h1 className="text-2xl font-semibold text-fg">{t('alerts.title')}</h1>
      <p className="mt-1 mb-6 text-sm text-fg-subtle">{t('alerts.subtitle')}</p>

      <div className="mb-4 flex flex-wrap items-center gap-3 text-sm">
        <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={setCaptureId} />
        {['', 'critical', 'high', 'medium', 'low'].map((s) => (
          <button
            key={s}
            onClick={() => setSeverity(s)}
            className={`rounded-lg px-3 py-1.5 ring-1 transition ${
              severity === s
                ? 'bg-danger/10 text-danger ring-danger/30'
                : 'text-fg-muted ring-border hover:text-fg'
            }`}
          >
            {s || t('common.all')}
            {s && counts[s] ? ` (${counts[s]})` : ''}
          </button>
        ))}
        <label className="ml-2 flex cursor-pointer items-center gap-1.5 text-xs text-fg-subtle">
          <input
            type="checkbox"
            checked={unconfirmedOnly}
            onChange={(e) => setUnconfirmedOnly(e.target.checked)}
            className="accent-accent"
          />
          {t('alerts.hide_acknowledged')}
        </label>
        {effectiveCaptureId && (
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={alertExport.export}
              disabled={alertExport.isExporting || isLoading}
              aria-label={t('alerts.export_aria')}
              title={t('alerts.export_title')}
              className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs text-fg-muted ring-1 ring-border-strong transition hover:text-fg disabled:pointer-events-none disabled:opacity-50"
            >
              <Download size={12} aria-hidden />
              {alertExport.isExporting ? t('common.exporting') : t('common.csv')}
            </button>
            <a
              href={api.captureReportUrl(effectiveCaptureId)}
              target="_blank"
              rel="noreferrer"
              aria-disabled={captureDetail?.status !== 'completed'}
              title={
                captureDetail?.status === 'completed'
                  ? t('alerts.report.open')
                  : t('alerts.report.not_ready')
              }
              onClick={(e) => {
                if (captureDetail?.status !== 'completed') e.preventDefault()
              }}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium ring-1 ring-info/30 transition ${
                captureDetail?.status === 'completed'
                  ? 'text-info hover:bg-info/10'
                  : 'cursor-not-allowed text-fg-subtle opacity-50'
              }`}
            >
              {t('alerts.report.download')}
            </a>
          </div>
        )}
      </div>

      {/* Correlated incidents */}
      {incidents.length > 0 && (
        <div className="mb-6 space-y-2">
          <div className="text-xs font-medium uppercase tracking-wider text-fg-subtle">
            {t('alerts.incidents.title', { count: incidents.length })}
          </div>
          {incidents.map((inc) => (
            <div
              key={`${inc.source_ip}-${inc.first_seen}`}
              className="rounded-xl border border-danger/25 bg-danger/5 px-4 py-3"
            >
              <div className="flex flex-wrap items-center gap-3">
                <span
                  className={`rounded px-2 py-0.5 text-xs font-bold ring-1 ${
                    (SEVERITY_STYLE[inc.severity] ?? SEVERITY_STYLE.info).badge
                  }`}
                >
                  {(SEVERITY_STYLE[inc.severity] ?? SEVERITY_STYLE.info).labelKey &&
                    translate((SEVERITY_STYLE[inc.severity] ?? SEVERITY_STYLE.info).labelKey)}
                </span>
                <span className="text-sm font-medium text-fg">{inc.title}</span>
                <span className="ml-auto font-mono text-xs text-fg-subtle">
                  {t('alerts.incidents.alert_count', { count: inc.alert_count, max: inc.max_score })}
                </span>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-fg-muted">{inc.story}</p>
            </div>
          ))}
        </div>
      )}

      {!analyzed.length ? (
        <EmptyState>{t('alerts.empty.no_analyzed')}</EmptyState>
      ) : isLoading ? (
        <SkeletonStatus label={t('alerts.skeleton')}>
          <div className="space-y-3" aria-hidden>
            {Array.from({ length: 6 }, (_, i) => (
              <div
                key={i}
                className="flex items-center gap-4 overflow-hidden rounded-xl border border-border bg-surface-2/50 px-5 py-4"
              >
                {/* score gauge */}
                <SkeletonRow className="h-12 w-12 shrink-0 rounded-full" />
                <div className="min-w-0 flex-1 space-y-2">
                  <div className="flex items-center gap-2">
                    <SkeletonRow className="w-20 rounded" />
                    <SkeletonRow className="w-28 rounded" />
                  </div>
                  <SkeletonRow className={`${i % 2 ? 'w-2/3' : 'w-5/6'}`} />
                  <SkeletonRow className="w-1/4" />
                </div>
              </div>
            ))}
          </div>
        </SkeletonStatus>
      ) : isError ? (
        <ErrorState message={t('alerts.load_error')} onRetry={() => refetch()} />
      ) : !alerts.length ? (
        <div className="rounded-xl border border-accent/20 bg-accent/5 p-12 text-center">
          <Check size={36} className="mx-auto text-accent" aria-hidden />
          <p className="mt-2 text-sm text-accent">{t('alerts.empty.no_alerts')}</p>
        </div>
      ) : (
        <div className="space-y-3">
          {page && page.total > allAlerts.length && (
            <div className="text-xs text-fg-subtle">
              {t('alerts.showing_first', {
                shown: allAlerts.length.toLocaleString(),
                total: page.total.toLocaleString(),
              })}
            </div>
          )}
          {alerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              expanded={expanded === alert.id}
              onToggle={() => setExpanded(expanded === alert.id ? null : alert.id)}
               onAck={(v) => ack.mutate({ id: alert.id, acknowledged: v })}
               ackPending={ack.isPending && ack.variables?.id === alert.id}
               onToggleTag={(tag, active) => {
                 const next = active
                   ? alert.tags.filter((t) => t !== tag)
                   : [...alert.tags, tag]
                 triage.mutate({ id: alert.id, tags: next })
               }}
               onSaveNote={(note) => triage.mutate({ id: alert.id, note })}
              triagePending={triage.isPending && triage.variables?.id === alert.id}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function AlertCard({
  alert,
  expanded,
  onToggle,
  onAck,
  ackPending,
  onToggleTag,
  onSaveNote,
  triagePending,
}: {
  alert: Alert
  expanded: boolean
  onToggle: () => void
  onAck: (v: boolean) => void
  ackPending?: boolean
  onToggleTag: (tag: string, active: boolean) => void
  onSaveNote: (note: string) => void
  triagePending?: boolean
}) {
  const style = SEVERITY_STYLE[alert.severity] ?? SEVERITY_STYLE.info
  const t = useT()
  const [showNote, setShowNote] = useState(false)
  const [noteDraft, setNoteDraft] = useState(alert.note ?? '')

  return (
    <div
      className={`overflow-hidden rounded-xl border bg-surface-2/50 transition ${
        alert.acknowledged ? 'border-border opacity-60' : 'border-border-strong'
      }`}
    >
      {/* Header — always visible */}
      <button
        onClick={onToggle}
        aria-expanded={expanded}
        className="flex w-full items-center gap-4 px-5 py-4 text-left"
      >
        {/* Score gauge */}
        <div className="relative flex h-12 w-12 shrink-0 items-center justify-center">
          <svg viewBox="0 0 36 36" className="h-12 w-12 -rotate-90">
            <circle cx="18" cy="18" r="15" fill="none" stroke="currentColor" strokeWidth="3" className="text-surface-3" />
            <circle
              cx="18"
              cy="18"
              r="15"
              fill="none"
              stroke="currentColor"
              className={
                alert.severity === 'critical'
                  ? 'text-danger'
                  : alert.severity === 'high'
                    ? 'text-warning'
                    : alert.severity === 'medium'
                      ? 'text-warning'
                      : 'text-info'
              }
              strokeWidth="3"
              strokeDasharray={`${(alert.score / 100) * 94.2} 94.2`}
              strokeLinecap="round"
            />
          </svg>
          <span className="absolute text-xs font-bold text-fg">{alert.score}</span>
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`rounded px-2 py-0.5 text-xs font-bold ring-1 ${style.badge}`}>
              {translate(style.labelKey)}
            </span>
            <span className="rounded bg-surface-3 px-2 py-0.5 text-xs font-medium text-fg-muted ring-1 ring-border">
              {RULE_KEYS[alert.rule_name] ? translate(RULE_KEYS[alert.rule_name]) : alert.rule_name}
            </span>
            {alert.acknowledged && (
              <span className="text-xs text-fg-subtle">{t('alerts.card.acknowledged')}</span>
            )}
          </div>
          <div className="mt-1 truncate text-sm font-medium text-fg">{alert.title}</div>
          <div className="mt-0.5 text-xs text-fg-subtle">
            {alert.timestamp != null && formatTime(alert.timestamp)}
            {alert.source_ip && t('alerts.card.source', { ip: alert.source_ip })}
          </div>
        </div>

        <span className="shrink-0 text-fg-subtle" aria-hidden>
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </span>
      </button>

      {/* Expanded evidence */}
      {expanded && (
        <div className="border-t border-border bg-bg/40 px-5 py-4">
          {/* Host / destination */}
          <div className="mb-4 grid grid-cols-3 gap-4 text-sm">
            <div>
              <div className="text-xs uppercase tracking-wider text-fg-subtle">{t('alerts.card.host')}</div>
              <div className="mt-0.5 font-mono text-fg">{alert.source_ip ?? '—'}</div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wider text-fg-subtle">
                {t('alerts.card.destination')}
              </div>
              <div className="mt-0.5 font-mono text-fg">
                {alert.destination_ip ?? '—'}
                {alert.destination_port ? `:${alert.destination_port}` : ''}
              </div>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wider text-fg-subtle">{t('alerts.card.risk')}</div>
              <div className="mt-0.5 font-semibold text-fg">{alert.score}/100</div>
            </div>
          </div>

          {/* Reasons */}
          <div className="mb-4">
            <div className="mb-1.5 text-xs font-medium uppercase tracking-wider text-fg-subtle">
              {t('alerts.card.reasons')}
            </div>
            <div className="space-y-1">
              {alert.reasons.map((r, i) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <Check size={14} className="mt-0.5 shrink-0 text-accent" aria-hidden />
                  <span className="text-fg">
                    {r.reason}
                    <span className="ml-2 text-xs text-fg-subtle">{r.detail}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Evidence JSON */}
          <div className="mb-4">
            <div className="mb-1.5 text-xs font-medium uppercase tracking-wider text-fg-subtle">
              {t('alerts.card.evidence')}
            </div>
            <div className="max-h-40 overflow-auto rounded-lg bg-surface/80 p-3 ring-1 ring-border">
              <EvidenceTable data={alert.evidence} />
            </div>
          </div>

          {/* Explanation */}
          {alert.explanation && (
            <div className="mb-4 rounded-lg border-l-2 border-border-strong bg-surface/60 p-3 text-sm leading-relaxed text-fg">
              {alert.explanation}
            </div>
          )}

          {/* Actions */}
          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={(e) => {
                e.stopPropagation()
                onAck(!alert.acknowledged)
              }}
              disabled={ackPending}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium ring-1 transition ${
                ackPending
                  ? 'cursor-wait bg-surface-3/50 text-fg-subtle ring-border'
                  : alert.acknowledged
                    ? 'bg-surface-3 text-fg-muted ring-border hover:text-fg'
                    : 'bg-accent/10 text-accent ring-accent/30 hover:bg-accent/20'
              }`}
            >
              {ackPending
                ? t('alerts.card.saving')
                : alert.acknowledged
                  ? t('alerts.card.unacknowledge')
                  : t('alerts.card.acknowledge')}
            </button>

            {/* Triage tags */}
            {(['confirmed', 'false-positive', 'escalated'] as const).map((tag) => {
              const active = alert.tags.includes(tag)
              return (
                <button
                  key={tag}
                  onClick={(e) => {
                    e.stopPropagation()
                    onToggleTag(tag, active)
                  }}
                  className={`rounded-lg px-2.5 py-1.5 text-xs ring-1 transition ${
                    active
                      ? tag === 'confirmed'
                        ? 'bg-accent/10 text-accent ring-accent/30'
                        : tag === 'false-positive'
                          ? 'bg-fg/10 text-fg-muted ring-fg/20'
                          : 'bg-danger/10 text-danger ring-danger/30'
                      : 'text-fg-subtle ring-border hover:text-fg-muted'
                  }`}
                >
                  {tag}
                </button>
              )
            })}

            {/* Deep link: jump to first related flow's evidence */}
            {alert.related_flow_ids.length > 0 && (
              <a
                href={`/flows?capture_id=${alert.capture_id}&flow=${alert.related_flow_ids[0]}`}
                onClick={(e) => e.stopPropagation()}
                className="rounded-lg px-3 py-1.5 text-xs text-info ring-1 ring-info/30 transition hover:bg-info/10"
              >
                {t('alerts.card.related_flows', { count: alert.related_flow_ids.length })}
                {t('alerts.card.view_evidence')}
              </a>
            )}

            {/* Analyst note */}
            <button
              onClick={(e) => {
                e.stopPropagation()
                // resync the draft each time the editor opens so a canceled
                // edit never resurfaces as the textarea's initial content
                setNoteDraft(alert.note ?? '')
                setShowNote(!showNote)
              }}
              className="rounded-lg px-2.5 py-1.5 text-xs text-fg-subtle ring-1 ring-border transition hover:text-fg-muted"
            >
              {alert.note ? t('alerts.card.edit_note') : t('alerts.card.add_note')}
            </button>
          </div>

          {/* Note editor */}
          {showNote && (
            <div className="mt-3">
              <textarea
                value={noteDraft}
                onChange={(e) => setNoteDraft(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                placeholder={t('alerts.card.note_placeholder')}
                aria-label={t('alerts.card.note_label')}
                rows={2}
                className="w-full rounded-lg border border-border bg-bg p-2.5 text-sm text-fg placeholder-fg-subtle focus:border-accent/50 focus:outline-none"
              />
              <div className="mt-1.5 flex gap-2">
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    onSaveNote(noteDraft)
                    setShowNote(false)
                  }}
                  disabled={triagePending}
                  className="rounded-lg bg-accent/10 px-3 py-1 text-xs text-accent ring-1 ring-accent/30 hover:bg-accent/20 disabled:opacity-50"
                >
                  {triagePending ? t('alerts.card.saving') : t('alerts.card.save_note')}
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    setShowNote(false)
                  }}
                  className="rounded-lg px-3 py-1 text-xs text-fg-muted ring-1 ring-border hover:text-fg"
                >
                  {t('alerts.card.cancel')}
                </button>
              </div>
            </div>
          )}

          {/* Saved note display */}
          {alert.note && !showNote && (
            <div className="mt-3 rounded-lg border-l-2 border-accent/50 bg-surface/60 p-2.5 text-sm text-fg">
              <span className="text-xs uppercase tracking-wider text-fg-subtle">{t('alerts.card.note')}</span>{' '}
              {alert.note}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
