import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { AuthProvider, useAuth } from './AuthContext'

/**
 * AuthContext contract:
 *   - probes /api/auth/status + /api/auth/me once on mount
 *   - anonymous is a first-class state (missing session is NOT an error)
 *   - backend-unreachable degrades to configured:false (fail closed)
 *   - useAuth() outside the provider is safe (never throws)
 */

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

function Consumer() {
  const { loading, user, configured, isAdmin } = useAuth()
  return (
    <div>
      <span data-testid="loading">{String(loading)}</span>
      <span data-testid="username">{user?.username ?? 'anonymous'}</span>
      <span data-testid="configured">{String(configured)}</span>
      <span data-testid="admin">{String(isAdmin)}</span>
    </div>
  )
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('AuthProvider', () => {
  it('resolves the session user and admin role', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url === '/api/auth/status') {
          return json({ configured: true, admin_group: 'a', analyst_group: 'b' })
        }
        return json({
          authenticated: true,
          sub: 's1',
          username: 'admin@packetkage.test',
          email: 'admin@packetkage.test',
          roles: ['admin'],
          groups: ['packetkage-admin'],
          is_admin: true,
        })
      }),
    )

    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    )

    expect(screen.getByTestId('loading').textContent).toBe('true')
    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('false'))
    expect(screen.getByTestId('username').textContent).toBe('admin@packetkage.test')
    expect(screen.getByTestId('admin').textContent).toBe('true')
    expect(screen.getByTestId('configured').textContent).toBe('true')
  })

  it('treats a 401 from /me as anonymous, not an error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url === '/api/auth/status') return json({ configured: true, admin_group: 'a', analyst_group: 'b' })
        return json({ detail: 'Not authenticated' }, 401)
      }),
    )

    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    )
    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('false'))
    expect(screen.getByTestId('username').textContent).toBe('anonymous')
    expect(screen.getByTestId('admin').textContent).toBe('false')
    expect(screen.getByTestId('configured').textContent).toBe('true')
  })

  it('degrades to configured:false when the backend is unreachable', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      }),
    )

    render(
      <AuthProvider>
        <Consumer />
      </AuthProvider>,
    )
    await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('false'))
    expect(screen.getByTestId('username').textContent).toBe('anonymous')
    expect(screen.getByTestId('configured').textContent).toBe('false')
  })
})

describe('refresh', () => {
  it('re-probes the backend and adopts a newly-configured state', async () => {
    let configured = false
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        if (url === '/api/auth/status') {
          return json({ configured, admin_group: 'a', analyst_group: 'b' })
        }
        return json({ detail: 'Not authenticated' }, 401)
      }),
    )

    function Refresher() {
      const { configured: isConfigured, refresh } = useAuth()
      return (
        <div>
          <span data-testid="configured">{String(isConfigured)}</span>
          <button onClick={() => void refresh()}>refresh</button>
        </div>
      )
    }

    render(
      <AuthProvider>
        <Refresher />
      </AuthProvider>,
    )
    await waitFor(() => expect(screen.getByTestId('configured').textContent).toBe('false'))

    configured = true
    await act(async () => {
      screen.getByRole('button', { name: 'refresh' }).click()
    })
    await waitFor(() => expect(screen.getByTestId('configured').textContent).toBe('true'))
  })
})

describe('useAuth outside a provider', () => {
  it('returns the safe anonymous default instead of throwing', () => {
    render(<Consumer />)
    expect(screen.getByTestId('username').textContent).toBe('anonymous')
    expect(screen.getByTestId('admin').textContent).toBe('false')
    expect(screen.getByTestId('loading').textContent).toBe('false')
  })
})

describe('signIn / signOut', () => {
  function installLocation() {
    const assign = vi.fn()
    const reload = vi.fn()
    const original = window.location
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { ...original, assign, reload, pathname: '/capture', search: '?status=completed' },
    })
    return { assign, reload, restore: () => Object.defineProperty(window, 'location', { configurable: true, writable: true, value: original }) }
  }

  it('signIn redirects to /api/auth/login with an encoded next', async () => {
    const loc = installLocation()
    const fetchMock = vi.fn(async () =>
      json({ configured: true, admin_group: 'a', analyst_group: 'b' }),
    )
    vi.stubGlobal('fetch', fetchMock)

    function Signer() {
      const { signIn } = useAuth()
      return <button onClick={() => signIn('/capture?status=completed')}>go</button>
    }
    render(
      <AuthProvider>
        <Signer />
      </AuthProvider>,
    )
    act(() => screen.getByRole('button', { name: 'go' }).click())
    expect(loc.assign).toHaveBeenCalledWith(
      '/api/auth/login?next=%2Fcapture%3Fstatus%3Dcompleted',
    )
    loc.restore()
  })

  it('signIn ignores non-relative next values (no open redirect)', () => {
    const loc = installLocation()
    vi.stubGlobal('fetch', vi.fn(async () => json({ configured: true })))

    function Signer() {
      const { signIn } = useAuth()
      return <button onClick={() => signIn('https://evil.example/steal')}>go</button>
    }
    render(
      <AuthProvider>
        <Signer />
      </AuthProvider>,
    )
    act(() => screen.getByRole('button', { name: 'go' }).click())
    expect(loc.assign).toHaveBeenCalledWith('/api/auth/login')
    loc.restore()
  })

  it('signOut POSTs /api/auth/logout then reloads', async () => {
    const loc = installLocation()
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.method === 'POST') return json({ ok: true })
      return json({ configured: true, admin_group: 'a', analyst_group: 'b' })
    })
    vi.stubGlobal('fetch', fetchMock)

    function Signer() {
      const { signOut } = useAuth()
      return <button onClick={() => void signOut()}>out</button>
    }
    render(
      <AuthProvider>
        <Signer />
      </AuthProvider>,
    )
    await act(async () => {
      screen.getByRole('button', { name: 'out' }).click()
    })
    await waitFor(() =>
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/auth/logout',
        expect.objectContaining({ method: 'POST' }),
      ),
    )
    await waitFor(() => expect(loc.reload).toHaveBeenCalled())
    loc.restore()
  })
})