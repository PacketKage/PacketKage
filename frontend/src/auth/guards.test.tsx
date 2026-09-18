import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { RequireAdmin, RequireAuth } from './guards'
import { adminUser, analystUser, authValue, TestAuthProvider } from '../test/harness'

afterEach(cleanup)

function renderGuard(ui: React.ReactElement, opts: { at?: string } = {}) {
  return render(<MemoryRouter initialEntries={[opts.at ?? '/']}>{ui}</MemoryRouter>)
}

describe('RequireAuth', () => {
  it('renders a spinner (not the sign-in screen) while the session is loading', () => {
    renderGuard(
      <TestAuthProvider value={authValue(null, { loading: true })}>
        <RequireAuth>
          <div>secret</div>
        </RequireAuth>
      </TestAuthProvider>,
    )
    expect(screen.queryByText('secret')).toBeNull()
    expect(screen.queryByRole('button', { name: /sign in/i })).toBeNull()
  })

  it('renders children for an authenticated session', () => {
    renderGuard(
      <TestAuthProvider value={authValue(adminUser())}>
        <RequireAuth>
          <div>secret</div>
        </RequireAuth>
      </TestAuthProvider>,
    )
    expect(screen.getByText('secret')).toBeDefined()
  })

  it('shows the sign-in screen for anonymous users', () => {
    renderGuard(
      <TestAuthProvider value={authValue(null)}>
        <RequireAuth>
          <div>secret</div>
        </RequireAuth>
      </TestAuthProvider>,
    )
    expect(screen.queryByText('secret')).toBeNull()
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeDefined()
    expect(screen.getByText(/identity provider/i)).toBeDefined()
  })

  it('renders the first-run setup wizard when OIDC is unconfigured', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input)
        const body = url.endsWith('/api/setup/status')
          ? { configured: false, requires_token: false }
          : {
              configured: false,
              values: {},
              locked: [],
              client_secret_set: false,
              persisted: false,
            }
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      }),
    )
    renderGuard(
      <TestAuthProvider value={authValue(null, { configured: false })}>
        <RequireAuth>
          <div>secret</div>
        </RequireAuth>
      </TestAuthProvider>,
    )
    expect(await screen.findByText('Connect an identity provider')).toBeDefined()
    expect(screen.queryByText('secret')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Sign in' })).toBeNull()
    vi.unstubAllGlobals()
  })

  it('passes the current location as next when signing in', () => {
    const signIn = vi.fn()
    renderGuard(
      <TestAuthProvider value={authValue(null, { signIn })}>
        <RequireAuth>
          <div>secret</div>
        </RequireAuth>
      </TestAuthProvider>,
      { at: '/capture?status=completed' },
    )
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(signIn).toHaveBeenCalledWith('/capture?status=completed')
  })
})

describe('RequireAdmin', () => {
  it('renders children for an admin', () => {
    renderGuard(
      <TestAuthProvider value={authValue(adminUser())}>
        <RequireAdmin>
          <div>admin area</div>
        </RequireAdmin>
      </TestAuthProvider>,
    )
    expect(screen.getByText('admin area')).toBeDefined()
  })

  it('shows the access-denied panel for an authenticated analyst', () => {
    renderGuard(
      <TestAuthProvider value={authValue(analystUser())}>
        <RequireAdmin>
          <div>admin area</div>
        </RequireAdmin>
      </TestAuthProvider>,
    )
    expect(screen.queryByText('admin area')).toBeNull()
    expect(screen.getByText('Access denied')).toBeDefined()
    expect(screen.getByText(/packetkage-admin/)).toBeDefined()
  })

  it('falls back to the sign-in screen for anonymous users', () => {
    renderGuard(
      <TestAuthProvider value={authValue(null)}>
        <RequireAdmin>
          <div>admin area</div>
        </RequireAdmin>
      </TestAuthProvider>,
    )
    expect(screen.queryByText('admin area')).toBeNull()
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeDefined()
  })
})