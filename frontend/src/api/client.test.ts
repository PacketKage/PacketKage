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
