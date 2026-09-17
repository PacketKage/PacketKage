import type { ReactElement, ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { AuthContext, type AuthContextValue } from '../auth/AuthContext'
import type { AuthUser } from '../types/api'

/* ------------------------------------------------------------------ */
/* Auth fixtures + a provider so page tests can render as a given role */
/* ------------------------------------------------------------------ */

export function adminUser(overrides: Partial<AuthUser> = {}): AuthUser {
  return {
    authenticated: true,
    sub: '00000000-0000-0000-0000-000000000001',
    username: 'admin@packetkage.test',
    email: 'admin@packetkage.test',
    roles: ['admin', 'analyst'],
    groups: ['packetkage-admin', 'packetkage-analyst'],
    is_admin: true,
    ...overrides,
  }
}

export function analystUser(overrides: Partial<AuthUser> = {}): AuthUser {
  return {
    authenticated: true,
    sub: '00000000-0000-0000-0000-000000000002',
    username: 'analyst@packetkage.test',
    email: 'analyst@packetkage.test',
    roles: ['analyst'],
    groups: ['packetkage-analyst'],
    is_admin: false,
    ...overrides,
  }
}

export function authValue(
  user: AuthUser | null,
  overrides: Partial<AuthContextValue> = {},
): AuthContextValue {
  return {
    loading: false,
    user,
    configured: true,
    isAdmin: user?.is_admin ?? false,
    refresh: () => Promise.resolve(),
    signIn: () => {},
    signOut: () => Promise.resolve(),
    ...overrides,
  }
}

export function TestAuthProvider({
  value,
  children,
}: {
  value: AuthContextValue
  children: ReactNode
}) {
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/**
 * Renders a page inside MemoryRouter + a QueryClient whose cache is
 * pre-seeded with the given entries — no network, no loading states.
 *
 * Pass `auth` to render inside a fixed AuthContext (e.g. an admin session);
 * omit it and useAuth() falls back to its safe anonymous default.
 *
 * Usage:
 *   renderPage(<AlertsPage />, {
 *     initialEntries: ['/alerts?capture_id=cap1'],
 *     queries: [{ queryKey: ['captures'], data: [captureFixture()] }],
 *   })
 */
export function renderPage(
  ui: ReactElement,
  opts: {
    initialEntries?: string[]
    path?: string
    queries?: { queryKey: unknown[]; data: unknown }[]
    auth?: AuthContextValue
  } = {},
) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchInterval: false, gcTime: Infinity, staleTime: Infinity },
    },
  })
  for (const { queryKey, data } of opts.queries ?? []) {
    queryClient.setQueryData(queryKey, data)
  }
  const tree = (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={opts.initialEntries ?? ['/']}>
        <Routes>
          <Route path={opts.path ?? '/'} element={ui} />
          <Route path="*" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
  return render(opts.auth ? <TestAuthProvider value={opts.auth}>{tree}</TestAuthProvider> : tree)
}

/** QueryClient with the same seeding, for tests needing the client itself. */
export function seededQueryClient(
  queries: { queryKey: unknown[]; data: unknown }[] = [],
): QueryClient {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, refetchInterval: false, gcTime: Infinity, staleTime: Infinity },
    },
  })
  for (const { queryKey, data } of queries) {
    queryClient.setQueryData(queryKey, data)
  }
  return queryClient
}
