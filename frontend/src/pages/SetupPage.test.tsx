import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react'
import { api } from '../api/client'
import { authValue, renderPage } from '../test/harness'
import { SetupPage } from './SetupPage'

/**
 * First-run wizard contract:
 *   - remote callers must present the one-time bootstrap token before the
 *     settings form is shown
 *   - env-managed fields arrive locked (read-only) and are never submitted
 *   - the discovery pre-flight surfaces success/failure inline
 *   - saving persists via the API and re-probes the auth state (no restart)
 */

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    api: {
      ...actual.api,
      setupStatus: vi.fn(),
      setupConfig: vi.fn(),
      testSetup: vi.fn(),
      saveSetup: vi.fn(),
    },
  }
})

const STATUS = vi.mocked(api.setupStatus)
const CONFIG = vi.mocked(api.setupConfig)
const TEST = vi.mocked(api.testSetup)
const SAVE = vi.mocked(api.saveSetup)

function configBody(overrides: Partial<Awaited<ReturnType<typeof api.setupConfig>>> = {}) {
  return {
    configured: false,
    values: {
      oidc_issuer: '',
      oidc_client_id: '',
      oidc_client_secret: '',
      oidc_redirect_uri: '',
      public_url: '',
      oidc_scope: '',
      oidc_groups_claim: '',
      admin_group: '',
      analyst_group: '',
    },
    locked: [],
    client_secret_set: false,
    persisted: false,
    ...overrides,
  }
}

beforeEach(() => {
  STATUS.mockResolvedValue({ configured: false, requires_token: false })
  CONFIG.mockResolvedValue(configBody())
  TEST.mockResolvedValue({ ok: true, issuer: 'https://idp.example' })
  SAVE.mockResolvedValue({ configured: true, applied: [], redirect_uri: '' })
})

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

describe('SetupPage', () => {
  it('requires the bootstrap token from a remote caller', async () => {
    STATUS.mockResolvedValue({ configured: false, requires_token: true })
    renderPage(<SetupPage />, { auth: authValue(null) })

    const input = await screen.findByPlaceholderText(/Paste the token/i)
    fireEvent.change(input, { target: { value: 'tok-abc' } })
    fireEvent.click(screen.getByRole('button', { name: /Continue/i }))

    await waitFor(() => expect(CONFIG).toHaveBeenCalledWith('tok-abc'))
    expect(await screen.findByText(/Connect an identity provider/i)).toBeDefined()
  })

  it('prefills saved values and locks env-managed fields', async () => {
    CONFIG.mockResolvedValue(
      configBody({
        values: {
          ...configBody().values,
          oidc_issuer: 'https://idp.example/application/o/packetkage/',
          oidc_client_id: 'packetkage',
        },
        locked: ['oidc_issuer'],
        client_secret_set: true,
      }),
    )
    renderPage(<SetupPage />, { auth: authValue(null) })

    const issuer = await screen.findByDisplayValue('https://idp.example/application/o/packetkage/')
    expect((issuer as HTMLInputElement).disabled).toBe(true)
    expect(screen.getByDisplayValue('packetkage')).toBeDefined()
    expect(screen.getByPlaceholderText(/keep the saved secret/i)).toBeDefined()
  })

  it('reports a successful discovery pre-flight', async () => {
    renderPage(<SetupPage />, { auth: authValue(null) })
    await screen.findByText(/Connect an identity provider/i)

    fireEvent.click(screen.getByRole('button', { name: /Test connection/i }))
    expect(await screen.findByText(/Connected to/i)).toBeDefined()
    expect(TEST).toHaveBeenCalled()
  })

  it('reports a failed discovery pre-flight without throwing', async () => {
    TEST.mockResolvedValue({ ok: false, stage: 'discovery', detail: 'connection refused' })
    renderPage(<SetupPage />, { auth: authValue(null) })
    await screen.findByText(/Connect an identity provider/i)

    fireEvent.click(screen.getByRole('button', { name: /Test connection/i }))
    expect(await screen.findByText(/Discovery failed/i)).toBeDefined()
  })

  it('submits the non-locked fields, saves, then refreshes the auth state', async () => {
    CONFIG.mockResolvedValue(
      configBody({ values: { ...configBody().values, oidc_issuer: 'https://idp.example' }, locked: ['oidc_issuer'] }),
    )
    const refresh = vi.fn().mockResolvedValue(undefined)
    renderPage(<SetupPage />, { auth: authValue(null, { refresh }) })
    await screen.findByText(/Connect an identity provider/i)

    fireEvent.click(screen.getByRole('button', { name: /Save & enable/i }))

    await waitFor(() => expect(SAVE).toHaveBeenCalled())
    // the env-locked issuer is not sent back
    expect(SAVE.mock.calls[0][0]).not.toHaveProperty('oidc_issuer')
    await waitFor(() => expect(refresh).toHaveBeenCalled())
  })
})
