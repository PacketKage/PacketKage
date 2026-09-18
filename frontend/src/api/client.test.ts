import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from './client'
import type { Job } from '../types/api'

/**
 * streamJob contract: one EventSource per call, JSON snapshots forwarded to
 * onUpdate, stream closed + onDone on terminal status, closed + onDone on
 * connection error, and the unsubscribe fn closes the stream.
 *
 * The backend regression this guards: SSE events were once emitted as Python
 * dict repr (single quotes) — invalid JSON — so every onmessage threw and
 * job progress never reached the UI.
 */

class MockEventSource {
  static instances: MockEventSource[] = []
  static lastInstance: MockEventSource | null = null

  url: string
  onmessage: ((ev: { data: string }) => void) | null = null
  onerror: ((ev: unknown) => void) | null = null
  readyState = 0
  closed = false

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
    MockEventSource.lastInstance = this
  }

  close() {
    this.closed = true
  }

  /** Test helper: deliver a payload as the browser would. */
  emit(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) })
  }

  fail() {
    this.onerror?.(new Error('connection lost'))
  }
}

function installEventSource() {
  MockEventSource.instances = []
  MockEventSource.lastInstance = null
  vi.stubGlobal(
    'EventSource',
    MockEventSource as unknown as new (url: string) => EventSource,
  )
  return () => {
    vi.unstubAllGlobals()
    MockEventSource.instances = []
    MockEventSource.lastInstance = null
  }
}

const job = (over: Partial<Job> = {}): Job => ({
  id: 'job1',
  capture_id: 'cap1',
  type: 'full_analysis',
  status: 'queued',
  progress: 0,
  stage: 'queued',
  message: null,
  created_at: '2026-09-13T10:00:00Z',
  started_at: null,
  finished_at: null,
  result: {},
  ...over,
})

afterEach(() => {
  vi.unstubAllGlobals()
})

/** Convert the init Headers (if any) into a plain record for assertions. */
function headersOf(init?: RequestInit): Record<string, string> {
  const out: Record<string, string> = {}
  if (!init?.headers) return out
  new Headers(init.headers).forEach((v, k) => {
    out[k] = v
  })
  return out
}

describe('api.streamJob', () => {
  it('subscribes to /api/jobs/{id}/events and forwards JSON snapshots', () => {
    const restore = installEventSource()
    const received: Job[] = []
    api.streamJob(
      'job1',
      (j) => received.push(j),
      () => {},
    )
    const es = MockEventSource.lastInstance!
    expect(es).toBeDefined()
    expect(es.url).toBe('/api/jobs/job1/events')

    es.emit(job({ status: 'running', progress: 45, stage: 'flows' }))
    es.emit(job({ status: 'running', progress: 90, stage: 'hosts' }))
    expect(received.map((j) => j.progress)).toEqual([45, 90])
    restore()
  })

  it('closes the stream and calls onDone on terminal status', () => {
    const restore = installEventSource()
    const done = vi.fn()
    api.streamJob('job1', () => {}, done)
    const es = MockEventSource.lastInstance!

    es.emit(job({ status: 'running', progress: 50 }))
    expect(es.closed).toBe(false)
    expect(done).not.toHaveBeenCalled()

    es.emit(job({ status: 'completed', progress: 100, stage: 'completed' }))
    expect(es.closed).toBe(true)
    expect(done).toHaveBeenCalledTimes(1)
    restore()
  })

  it('closes the stream and calls onDone on connection error (fallback signal)', () => {
    const restore = installEventSource()
    const done = vi.fn()
    api.streamJob('job1', () => {}, done)
    const es = MockEventSource.lastInstance!

    es.fail()
    expect(es.closed).toBe(true)
    expect(done).toHaveBeenCalledTimes(1)
    restore()
  })

  it('unsubscribe closes the EventSource', () => {
    const restore = installEventSource()
    const unsubscribe = api.streamJob('job1', () => {}, () => {})
    const es = MockEventSource.lastInstance!
    expect(es.closed).toBe(false)
    unsubscribe()
    expect(es.closed).toBe(true)
    restore()
  })
})

describe('api auth endpoints', () => {
  it('authStatus hits the public /api/auth/status endpoint', async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ configured: true, admin_group: 'a', analyst_group: 'b' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const status = await api.authStatus()
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/status', expect.any(Object))
    expect(headersOf(fetchMock.mock.calls.at(-1)?.[1])['accept-language']).toBe('en')
    expect(status.configured).toBe(true)
    vi.unstubAllGlobals()
  })

  it('logout POSTs /api/auth/logout', async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await api.logout()
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/auth/logout',
      expect.objectContaining({ method: 'POST' }),
    )
    vi.unstubAllGlobals()
  })

  it('fetchAuthMe returns the user on 200', async () => {
    const user = {
      authenticated: true,
      sub: 's1',
      username: 'analyst@packetkage.test',
      email: null,
      roles: ['analyst'],
      groups: ['packetkage-analyst'],
      is_admin: false,
    }
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify(user), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    )
    await expect(api.fetchAuthMe()).resolves.toMatchObject({ username: 'analyst@packetkage.test' })
    vi.unstubAllGlobals()
  })

  it('fetchAuthMe returns null (never throws) when unauthenticated', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify({ detail: 'Not authenticated' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    )
    await expect(api.fetchAuthMe()).resolves.toBeNull()
    vi.unstubAllGlobals()
  })

  it('fetchAuthMe returns null when the backend is unreachable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      }),
    )
    await expect(api.fetchAuthMe()).resolves.toBeNull()
    vi.unstubAllGlobals()
  })
})

describe('api setup endpoints', () => {
  const jsonResponse = (body: unknown) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })

  it('setupStatus hits the public /api/setup/status endpoint', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse({ configured: false, requires_token: true }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const status = await api.setupStatus()
    expect(fetchMock).toHaveBeenCalledWith('/api/setup/status', expect.any(Object))
    expect(headersOf(fetchMock.mock.calls.at(-1)?.[1])['accept-language']).toBe('en')
    expect(status.requires_token).toBe(true)
    vi.unstubAllGlobals()
  })

  it('setupConfig sends the bootstrap token as X-Setup-Token when provided', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse({ configured: false, values: {}, locked: [], client_secret_set: false, persisted: false }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await api.setupConfig('tok-123')
    const init = fetchMock.mock.calls.at(-1)?.[1]
    expect(fetchMock).toHaveBeenCalledWith('/api/setup/config', expect.any(Object))
    expect(headersOf(init)?.['x-setup-token']).toBe('tok-123')
    expect(headersOf(init)?.['accept-language']).toBe('en')
    vi.unstubAllGlobals()
  })

  it('testSetup POSTs JSON and omits the token header when absent', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse({ ok: true }),
    )
    vi.stubGlobal('fetch', fetchMock)

    await api.testSetup({ oidc_issuer: 'https://idp.example' })
    const init = fetchMock.mock.calls.at(-1)?.[1]
    expect(fetchMock).toHaveBeenCalledWith('/api/setup/test', expect.any(Object))
    expect(init?.method).toBe('POST')
    expect(init?.body).toBe(JSON.stringify({ oidc_issuer: 'https://idp.example' }))
    const headers = headersOf(init)
    expect(headers['content-type']).toBe('application/json')
    expect(headers['accept-language']).toBe('en')
    expect(headers['x-setup-token']).toBeUndefined()
    vi.unstubAllGlobals()
  })

  it('saveSetup POSTs to /api/setup/oidc with the token header', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse({ configured: true, applied: ['oidc_issuer'], redirect_uri: 'https://x/api/auth/callback' }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const result = await api.saveSetup({ oidc_issuer: 'https://idp.example' }, 'tok-9')
    expect(result.configured).toBe(true)
    const init = fetchMock.mock.calls.at(-1)?.[1]
    expect(fetchMock).toHaveBeenCalledWith('/api/setup/oidc', expect.any(Object))
    expect(init?.method).toBe('POST')
    expect(init?.body).toBe(JSON.stringify({ oidc_issuer: 'https://idp.example' }))
    const headers = headersOf(init)
    expect(headers['content-type']).toBe('application/json')
    expect(headers['x-setup-token']).toBe('tok-9')
    expect(headers['accept-language']).toBe('en')
    vi.unstubAllGlobals()
  })
})
