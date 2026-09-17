import type {
  Alert,
  AuthStatus,
  AuthUser,
  Capture,
  Case,
  CaseDetail,
  DNSTransaction,
  EngineerMetrics,
  Flow,
  FlowDetail,
  Graph,
  GraphProvenance,
  GraphV2,
  GraphV2Blast,
  GraphV2Edge,
  GraphV2NodeDetail,
  GraphV2Paths,
  HTTPTransaction,
  Host,
  Job,
  LiveCapture,
  LiveStatus,
  Page,
  ProtocolStats,
  SetupConfig,
  SetupSaveResult,
  SetupStatus,
  SetupTestResult,
  SetupValues,
  TimelineEvent,
  TLSSession,
} from '../types/api'

const BASE = '/api'

/** First-run setup endpoints accept a one-time token from remote callers. */
function setupHeaders(token?: string): Record<string, string> {
  return token ? { 'X-Setup-Token': token } : {}
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, init)
  if (!resp.ok) {
    let detail = resp.statusText
    try {
      detail = (await resp.json()).detail ?? detail
    } catch {
      /* no body */
    }
    throw new Error(detail)
  }
  return resp.json()
}

/**
 * Safe, user-displayable message from an API error. `request()` throws
 * `Error(detail)` with the backend's client-actionable detail; anything else
 * (network failure, unexpected shape) falls back to a generic message so
 * toasts never leak internals or stack traces.
 */
export function apiErrorMessage(err: unknown): string {
  if (err instanceof Error && err.message) return err.message
  return 'Request failed'
}

export interface Pagination {
  limit?: number
  offset?: number
}

function paged(params: URLSearchParams, page?: Pagination) {
  if (page?.limit !== undefined) params.set('limit', String(page.limit))
  if (page?.offset !== undefined) params.set('offset', String(page.offset))
  return params
}

export const api = {
  parsers: () => request<Record<string, boolean>>('/captures/meta/parsers'),

  listCaptures: () => request<Capture[]>('/captures'),

  getCapture: (id: string) => request<Capture>(`/captures/${id}`),

  deleteCapture: (id: string) =>
    request<{ detail: string; id: string; file_removed: boolean }>(`/captures/${id}`, {
      method: 'DELETE',
    }),

  uploadCapture: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return request<Capture>('/captures', { method: 'POST', body: form })
  },

  analyzeCapture: (id: string, parser?: string) =>
    request<Job>(`/captures/${id}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(parser ? { parser } : {}),
    }),

  listJobs: () => request<Job[]>('/jobs'),

  /** Subscribe to job progress over SSE; resolves snapshot updates + terminal state. */
  streamJob: (id: string, onUpdate: (job: Job) => void, onDone: () => void) => {
    const es = new EventSource(`${BASE}/jobs/${id}/events`)
    es.onmessage = (ev) => {
      // a malformed frame must not kill the handler — skip it and keep
      // streaming; the polled captures list self-heals missed snapshots
      let job: Job
      try {
        job = JSON.parse(ev.data) as Job
      } catch {
        return
      }
      onUpdate(job)
      if (job.status === 'completed' || job.status === 'failed') {
        es.close()
        onDone()
      }
    }
    es.onerror = () => {
      // stream ended unexpectedly; fall back — caller can poll
      es.close()
      onDone()
    }
    return () => es.close()
  },

  listFlows: (
    captureId: string,
    filters?: { transport?: string; direction?: string; sort?: string; order?: string },
    page?: Pagination,
  ) => {
    const params = new URLSearchParams({ capture_id: captureId })
    if (filters?.transport) params.set('transport', filters.transport)
    if (filters?.direction) params.set('direction', filters.direction)
    if (filters?.sort) params.set('sort', filters.sort)
    if (filters?.order) params.set('order', filters.order)
    return request<Page<Flow>>(`/flows?${paged(params, page)}`)
  },

  getFlow: (id: string) => request<FlowDetail>(`/flows/${id}`),

  // Hosts (Step 3)
  listHosts: (captureId: string, internal?: boolean, limit?: number) => {
    const params = new URLSearchParams({ capture_id: captureId })
    if (internal !== undefined) params.set('internal', String(internal))
    if (limit !== undefined) params.set('limit', String(limit))
    return request<Host[]>(`/hosts?${params}`)
  },

  // Protocols (Step 3)
  listDns: (
    captureId: string,
    filters?: { domain?: string; rcode?: number },
    page?: Pagination,
  ) => {
    const params = new URLSearchParams({ capture_id: captureId })
    if (filters?.domain) params.set('domain', filters.domain)
    if (filters?.rcode !== undefined) params.set('rcode', String(filters.rcode))
    return request<Page<DNSTransaction>>(`/protocols/dns?${paged(params, page)}`)
  },

  listHttp: (
    captureId: string,
    filters?: { host?: string; status?: number },
    page?: Pagination,
  ) => {
    const params = new URLSearchParams({ capture_id: captureId })
    if (filters?.host) params.set('host', filters.host)
    if (filters?.status !== undefined) params.set('status', String(filters.status))
    return request<Page<HTTPTransaction>>(`/protocols/http?${paged(params, page)}`)
  },

  listTls: (captureId: string, filters?: { sni?: string }, page?: Pagination) => {
    const params = new URLSearchParams({ capture_id: captureId })
    if (filters?.sni) params.set('sni', filters.sni)
    return request<Page<TLSSession>>(`/protocols/tls?${paged(params, page)}`)
  },

  protocolStats: (captureId: string) =>
    request<ProtocolStats>(`/protocols/stats?capture_id=${captureId}`),

  // Alerts (Step 4)
  listAlerts: (
    captureId: string,
    filters?: { severity?: string; minScore?: number; rule?: string },
    page?: Pagination,
  ) => {
    const params = new URLSearchParams({ capture_id: captureId })
    if (filters?.severity) params.set('severity', filters.severity)
    if (filters?.minScore !== undefined) params.set('min_score', String(filters.minScore))
    if (filters?.rule) params.set('rule', filters.rule)
    return request<Page<Alert>>(`/alerts?${paged(params, page)}`)
  },

  ackAlert: (id: string, acknowledged: boolean) =>
    request<Alert>(`/alerts/${id}/ack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ acknowledged }),
    }),

  // Triage (Phase 5): partial update — tags/note/acknowledged
  triageAlert: (
    id: string,
    body: { acknowledged?: boolean; tags?: string[]; note?: string },
  ) =>
    request<Alert>(`/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),

  // Cases (Phase 5)
  listCases: () => request<Case[]>('/cases'),

  getCase: (id: string) => request<CaseDetail>(`/cases/${id}`),

  createCase: (name: string, description?: string) =>
    request<CaseDetail>('/cases', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description }),
    }),

  addCaptureToCase: (caseId: string, captureId: string) =>
    request<CaseDetail>(`/cases/${caseId}/captures`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ capture_id: captureId }),
    }),

  removeCaptureFromCase: (caseId: string, captureId: string) =>
    request<CaseDetail>(`/cases/${caseId}/captures/${captureId}`, { method: 'DELETE' }),

  closeCase: (caseId: string) =>
    request<Case>(`/cases/${caseId}/close`, { method: 'POST' }),

  caseTimeline: (
    caseId: string,
    filters?: { eventType?: string; severity?: string; after?: number; before?: number; limit?: number },
  ) => {
    const params = new URLSearchParams()
    if (filters?.eventType) params.set('event_type', filters.eventType)
    if (filters?.severity) params.set('severity', filters.severity)
    if (filters?.after !== undefined) params.set('after', String(filters.after))
    if (filters?.before !== undefined) params.set('before', String(filters.before))
    if (filters?.limit !== undefined) params.set('limit', String(filters.limit))
    return request<TimelineEvent[]>(`/cases/${caseId}/timeline?${params}`)
  },

  // Report download URL (opens in a new tab; printable to PDF)
  captureReportUrl: (captureId: string) => `${BASE}/captures/${captureId}/report`,

  // Timeline + Graph + Replay (Step 5)
  getTimeline: (
    captureId: string,
    filters?: {
      host?: string
      protocol?: string
      eventType?: string
      severity?: string
      after?: number
      before?: number
      limit?: number
      offset?: number
    },
  ) => {
    const params = new URLSearchParams({ capture_id: captureId })
    if (filters?.host) params.set('host', filters.host)
    if (filters?.protocol) params.set('protocol', filters.protocol)
    if (filters?.eventType) params.set('event_type', filters.eventType)
    if (filters?.severity) params.set('severity', filters.severity)
    if (filters?.after !== undefined) params.set('after', String(filters.after))
    if (filters?.before !== undefined) params.set('before', String(filters.before))
    if (filters?.limit !== undefined) params.set('limit', String(filters.limit))
    if (filters?.offset !== undefined) params.set('offset', String(filters.offset))
    return request<Page<TimelineEvent>>(`/timeline?${params}`)
  },

  getGraph: (captureId: string) => request<Graph>(`/graph?capture_id=${captureId}`),

  // Evidence Graph 2.0 (v2) — provenance-carrying investigation graph
  getEvidenceGraph: (
    captureId: string,
    filters?: {
      relationships?: string[]
      provenance?: GraphProvenance[]
      after?: number
      before?: number
      minAlerts?: number
      nodeId?: string
      limit?: number
      offset?: number
    },
  ) => {
    const params = new URLSearchParams({ capture_id: captureId })
    if (filters?.relationships?.length)
      params.set('relationships', filters.relationships.join(','))
    if (filters?.provenance?.length) params.set('provenance', filters.provenance.join(','))
    if (filters?.after !== undefined) params.set('after', String(filters.after))
    if (filters?.before !== undefined) params.set('before', String(filters.before))
    if (filters?.minAlerts) params.set('min_alerts', String(filters.minAlerts))
    if (filters?.nodeId) params.set('node_id', filters.nodeId)
    if (filters?.limit) params.set('limit', String(filters.limit))
    if (filters?.offset) params.set('offset', String(filters.offset))
    return request<GraphV2>(`/graph/v2?${params}`)
  },

  getGraphNode: (captureId: string, nodeId: string) => {
    const params = new URLSearchParams({ capture_id: captureId, node_id: nodeId })
    return request<GraphV2NodeDetail>(`/graph/v2/node?${params}`)
  },

  getGraphEdge: (captureId: string, edgeId: string) =>
    request<GraphV2Edge>(`/graph/v2/edge/${edgeId}?capture_id=${captureId}`),

  getGraphPaths: (captureId: string, source: string, target: string) => {
    const params = new URLSearchParams({ capture_id: captureId, source, target })
    return request<GraphV2Paths>(`/graph/v2/paths?${params}`)
  },

  getGraphBlast: (captureId: string, host: string, depth = 2) => {
    const params = new URLSearchParams({
      capture_id: captureId,
      host,
      depth: String(depth),
    })
    return request<GraphV2Blast>(`/graph/v2/blast?${params}`)
  },

  getReplay: (captureId: string, after?: number) => {
    const params = new URLSearchParams({ capture_id: captureId })
    if (after !== undefined) params.set('after', String(after))
    return request<TimelineEvent[]>(`/replay?${params}`)
  },

  // Live capture (Phase 4)
  liveInterfaces: () => request<string[]>('/live/interfaces'),

  liveStart: (body: {
    interface: string
    bpf?: string
    max_packets?: number
    max_seconds?: number
  }) =>
    request<LiveStatus>('/live/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),

  liveStatus: () => request<LiveStatus | null>('/live/status'),

  liveStop: () =>
    request<{ state: LiveStatus; capture: LiveCapture }>('/live/stop', {
      method: 'POST',
    }),

  // Engineer Mode (Step 6)
  getEngineerMetrics: (captureId: string) =>
    request<EngineerMetrics>(`/engineer/metrics?capture_id=${captureId}`),

  // ---- Authentication (OIDC / Authentik) ----

  /** Public: whether OIDC is configured and which groups map to which role. */
  authStatus: () => request<AuthStatus>('/auth/status'),

  logout: () => request<{ ok: boolean }>('/auth/logout', { method: 'POST' }),

  /**
   * Non-throwing identity probe — the single source of "who am I".
   * Returns the session user, or null when there is no usable session
   * (401 missing/invalid cookie, 403 wrong role, 503 unconfigured).
   * Never throws, so top-of-tree callers can treat it as "anonymous".
   */
  async fetchAuthMe(): Promise<AuthUser | null> {
    try {
      return await request<AuthUser>('/auth/me')
    } catch {
      return null
    }
  },

  // ---- First-run setup wizard ----

  /** Public: whether OIDC is configured and if this caller needs a setup token. */
  setupStatus: () => request<SetupStatus>('/setup/status'),

  /** Current settings + env-locked fields (requires setup token or admin). */
  setupConfig: (token?: string) =>
    request<SetupConfig>('/setup/config', { headers: setupHeaders(token) }),

  /** OIDC discovery + JWKS pre-flight — validates without saving. */
  testSetup: (values: Partial<SetupValues>, token?: string) =>
    request<SetupTestResult>('/setup/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...setupHeaders(token) },
      body: JSON.stringify(values),
    }),

  /** Persist and activate the OIDC settings (no restart required). */
  saveSetup: (values: Partial<SetupValues>, token?: string) =>
    request<SetupSaveResult>('/setup/oidc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...setupHeaders(token) },
      body: JSON.stringify(values),
    }),
}
