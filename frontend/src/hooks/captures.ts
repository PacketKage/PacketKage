import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import type { Capture } from '../types/api'

/**
 * Single shared captures query.
 * Polls fast while any capture is analyzing/queued, slow otherwise.
 */
export function useCaptures() {
  return useQuery({
    queryKey: ['captures'],
    queryFn: api.listCaptures,
    refetchInterval: (query) => {
      const captures = query.state.data
      const active = captures?.some(
        (c) => c.status === 'analyzing' || c.status === 'queued',
      )
      return active ? 1500 : 15000
    },
  })
}

/**
 * Per-page capture selection with the analyzed-captures list derived once.
 * Returns the effective capture id (selection or newest analyzed capture).
 */
export function useSelectedCapture() {
  const [captureId, setCaptureId] = useState<string | null>(null)
  const { data: captures, isLoading } = useCaptures()
  const analyzed = (captures ?? []).filter((c: Capture) => c.status === 'completed')
  const effectiveCaptureId = captureId ?? analyzed[0]?.id ?? null
  return { analyzed, effectiveCaptureId, setCaptureId, isLoading }
}

/** Debounce any fast-changing value (filter inputs). */
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs)
    return () => clearTimeout(t)
  }, [value, delayMs])
  return debounced
}

