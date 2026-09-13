import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { CapturePicker } from '../components/CapturePicker'
import { EvidenceTable } from '../components/EvidenceTable'
import { Modal } from '../components/Modal'
import { SkeletonRow, SkeletonStatus, formatTime } from '../components/ui'
import { useSelectedCapture } from '../hooks/captures'
import type { TimelineEvent } from '../types/api'

const SPEEDS = [0.5, 1, 4, 16, 64]

export function ReplayPage() {
  const { analyzed, effectiveCaptureId, setCaptureId } = useSelectedCapture()
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(4)
  const [position, setPosition] = useState(0) // event index
  const [selected, setSelected] = useState<TimelineEvent | null>(null)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const { data: events, isError } = useQuery({
    queryKey: ['replay', effectiveCaptureId],
    queryFn: () => api.getReplay(effectiveCaptureId!),
    enabled: !!effectiveCaptureId,
  })

  // playback: advance position at `speed` events/sec
  useEffect(() => {
    if (!playing || !events) return
    timerRef.current = setInterval(() => {
      setPosition((p) => Math.min(p + 1, events.length - 1))
    }, 1000 / speed)
    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [playing, speed, events])

  // stop when playback reaches the end of the tape
  useEffect(() => {
    if (playing && events && position >= events.length - 1) setPlaying(false)
  }, [playing, events, position])

  const current = events?.[position] ?? null
  const past = useMemo(() => events?.slice(Math.max(0, position - 14), position + 1) ?? [], [events, position])

  return (
    <div className="flex h-full flex-col p-8">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold text-fg">Incident Replay</h1>
        <span className="text-xs text-fg-subtle">
          watch what happened, in order — click any event for evidence
        </span>
        <div className="ml-auto">
          <CapturePicker captures={analyzed} value={effectiveCaptureId} onChange={(id) => { setCaptureId(id); setPosition(0); setPlaying(false) }} />
        </div>
      </div>

      {!events ? (
        analyzed.length ? (
          <SkeletonStatus label="Loading events…">
            <div className="flex flex-1 flex-col gap-4" aria-hidden>
              {/* transport controls */}
              <div className="flex items-center gap-4 rounded-xl border border-border bg-surface-2/50 px-5 py-4">
                <SkeletonRow className="w-20 rounded-full" />
                <SkeletonRow className="flex-1" />
                <SkeletonRow className="w-24" />
                <SkeletonRow className="w-12" />
              </div>
              {/* current-event spotlight */}
              <div className="flex items-center gap-4 rounded-xl border border-border bg-surface-2/50 px-5 py-4">
                <SkeletonRow className="w-16" />
                <SkeletonRow className="w-1/2" />
              </div>
              {/* event tape */}
              <div className="flex-1 space-y-1 rounded-xl border border-border bg-surface-2/50 p-3">
                {Array.from({ length: 8 }, (_, i) => (
                  <div key={i} className="flex items-center gap-3 rounded-lg px-3 py-1.5">
                    <SkeletonRow className="w-16" />
                    <SkeletonRow className={`${i % 2 ? 'w-2/3' : 'w-4/5'}`} />
                  </div>
                ))}
              </div>
            </div>
          </SkeletonStatus>
        ) : (
          <div className="rounded-xl border border-border bg-surface-2/50 p-12 text-center text-sm text-fg-subtle">
            No analyzed captures yet.
          </div>
        )
      ) : isError ? (
        <div className="rounded-xl border border-border bg-surface-2/50 p-12 text-center text-sm text-danger">
          Failed to load replay events. Please try again.
        </div>
      ) : (
        <div className="flex flex-1 flex-col gap-4">
          {/* Transport controls */}
          <div className="flex items-center gap-4 rounded-xl border border-border bg-surface-2/50 px-5 py-4">
            <button
              onClick={() => {
                if (position >= events.length - 1) setPosition(0)
                setPlaying(!playing)
              }}
              className="flex h-10 items-center justify-center rounded-full bg-accent/10 px-4 text-sm font-medium text-accent ring-1 ring-accent/30 hover:bg-accent/20"
            >
              {playing ? 'Pause' : 'Play'}
            </button>
            <button
              onClick={() => setPosition((p) => Math.max(0, p - 1))}
              className="rounded-lg px-2 py-1 text-xs text-fg-muted ring-1 ring-border-strong hover:text-fg"
              title="previous event"
            >
              Prev
            </button>
            <button
              onClick={() => setPosition((p) => Math.min(events.length - 1, p + 1))}
              className="rounded-lg px-2 py-1 text-xs text-fg-muted ring-1 ring-border-strong hover:text-fg"
              title="next event"
            >
              Next
            </button>

            {/* scrubber */}
            <input
              type="range"
              min={0}
              max={events.length - 1}
              value={position}
              onChange={(e) => {
                setPlaying(false)
                setPosition(Number(e.target.value))
              }}
              className="h-1.5 flex-1 cursor-pointer appearance-none rounded-full bg-surface-3 accent-accent"
            />

            {/* speed */}
            <div className="flex items-center gap-1.5">
              {SPEEDS.map((s) => (
                <button
                  key={s}
                  onClick={() => setSpeed(s)}
                  className={`rounded px-2 py-1 text-xs ring-1 transition ${
                    speed === s
                      ? 'bg-info/10 text-info ring-info/30'
                      : 'text-fg-muted ring-border-strong hover:text-fg'
                  }`}
                >
                  {s}×
                </button>
              ))}
            </div>

            <div className="w-14 text-right font-mono text-xs text-fg-subtle">
              {position + 1}/{events.length}
            </div>
          </div>

          {/* Current event spotlight */}
          <div className="rounded-xl border border-border bg-surface-2/50 px-5 py-4">
            {current ? (
              <button
                onClick={() => setSelected(current)}
                className="flex w-full items-center gap-4 text-left"
              >
                <span className="font-mono text-lg text-fg-subtle">
                  {formatTime(current.timestamp)}
                </span>
                <span
                  className={`text-base ${
                    current.severity === 'critical'
                      ? 'text-danger'
                      : current.severity === 'high'
                        ? 'text-warning'
                        : 'text-fg'
                  }`}
                >
                  {current.label}
                </span>
                <span className="ml-auto text-xs text-fg-subtle">details →</span>
              </button>
            ) : (
              <span className="text-sm text-fg-subtle">No events</span>
            )}
          </div>

          {/* Event tape (recent history, newest at bottom) */}
          <div className="flex-1 overflow-y-auto rounded-xl border border-border bg-surface-2/50 p-3">
            <div className="space-y-1">
              {past.map((e, i) => {
                const isCurrent = i === past.length - 1
                return (
                  <button
                    key={e.id}
                    onClick={() => setSelected(e)}
                    className={`flex w-full items-center gap-3 rounded-lg px-3 py-1.5 text-left text-sm transition ${
                      isCurrent
                        ? 'bg-accent/10 ring-1 ring-accent/30'
                        : 'opacity-70 hover:opacity-100'
                    }`}
                  >
                    <span className="w-16 shrink-0 font-mono text-xs text-fg-subtle">
                      {formatTime(e.timestamp)}
                    </span>
                    <span className="min-w-0 flex-1 truncate text-fg-muted">{e.label}</span>
                    {isCurrent && (
                      <span className="shrink-0 text-xs uppercase tracking-wider text-accent">
                        now
                      </span>
                    )}
                  </button>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {selected && <ReplayEventModal event={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

function ReplayEventModal({ event, onClose }: { event: TimelineEvent; onClose: () => void }) {
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
          <div>
            <div className="text-xs uppercase tracking-wider text-fg-subtle">Source</div>
            <div className="mt-0.5 font-mono text-fg-muted">{event.source_ip ?? '—'}</div>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-fg-subtle">
              Destination
            </div>
            <div className="mt-0.5 font-mono text-fg-muted">
              {event.destination_ip ?? '—'}
              {event.destination_port ? `:${event.destination_port}` : ''}
            </div>
          </div>
        </div>
        <div className="overflow-auto rounded-lg bg-bg/60 p-3 ring-1 ring-border">
          <EvidenceTable data={event.detail} />
        </div>
        {flow && (
          <div className="rounded-lg bg-bg/60 p-3 font-mono text-xs text-fg-muted ring-1 ring-border">
            flow: {flow.source_ip}:{flow.source_port} → {flow.destination_ip}:
            {flow.destination_port} · {flow.packets} pkt · {flow.bytes} B ·{' '}
            {flow.tcp_state ?? 'n/a'}
          </div>
        )}
      </div>
    </Modal>
  )
}
