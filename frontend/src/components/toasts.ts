import { toast } from 'sonner'
import { api, apiErrorMessage } from '../api/client'
import { translate } from '../i18n/locale'

/**
 * Shared toast feedback for user-triggered API mutations.
 *
 * - `mutateSuccess`: called from a mutation's onSuccess (backend confirmed).
 * - `mutateError(action, err)`: called from a mutation's onError; `action` is
 *   a noun phrase ("Upload", "Acknowledge") — renders the backend's
 *   actionable detail, never stack traces or internals.
 * - Stable `id` per action target: rapid repeats of the same action replace
 *   the existing toast instead of stacking duplicates.
 *
 * Deliberately NOT used for queries/polling — passive data fetching stays silent.
 */
export function mutateSuccess(message: string, id?: string) {
  toast.success(message, id ? { id } : undefined)
}

export function mutateError(action: string, err: unknown, id?: string) {
  const detail = apiErrorMessage(err)
  const failed = translate('toast.failed_suffix', { action })
  const message =
    detail === translate('error.request_failed')
      ? failed
      : translate('toast.failed_with_detail', { action, detail })
  toast.error(message, id ? { id } : undefined)
}

/**
 * Analysis jobs are async: the mutation only queues the job, terminal state
 * arrives later over SSE. This module-level watcher lets the completion /
 * failure toast fire wherever the analyst has navigated to.
 *
 * One EventSource at a time; switching jobs closes the previous stream. Each
 * job id toasts at most once (guard set), and ids are stable so repeated
 * notifications replace instead of stacking.
 */
const toastedJobs = new Set<string>()
let watchedJobId: string | null = null
let unsubscribeWatch: (() => void) | null = null

export function watchJobForToast(jobId: string) {
  if (watchedJobId === jobId) return
  unsubscribeWatch?.()
  unsubscribeWatch = null
  watchedJobId = jobId

  unsubscribeWatch = api.streamJob(
    jobId,
    (job) => {
      if (job.status !== 'completed' && job.status !== 'failed') return
      if (toastedJobs.has(job.id)) return
      toastedJobs.add(job.id)
      if (job.status === 'completed') {
        const packets = job.result?.packets
        mutateSuccess(
          packets != null
            ? translate('toast.analysis_completed', { packets: packets.toLocaleString() })
            : translate('toast.analysis_completed_short'),
          `job-${job.id}`,
        )
      } else {
        const detail = job.message || job.stage
        toast.error(
          detail
            ? translate('toast.analysis_failed', { detail })
            : translate('toast.analysis_failed_short'),
          { id: `job-${job.id}` },
        )
      }
    },
    () => {
      // stream ended (terminal or error) — nothing to do; the snapshot
      // callback above already toasted terminal states
    },
  )
}

