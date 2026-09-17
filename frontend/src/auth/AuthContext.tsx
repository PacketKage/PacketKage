import type { ReactNode } from 'react'
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { api } from '../api/client'
import type { AuthUser } from '../types/api'

/**
 * Application auth state, resolved once at startup from the backend's OIDC
 * session (Authorization-Code + PKCE against Authentik).
 *
 * ``useAuth()`` is SAFE OUTSIDE the provider: components rendered without an
 * <AuthProvider> (isolated page tests, pre-mount) fall back to this stable
 * anonymous value instead of throwing, keeping the tree provider-tolerant.
 */

export interface AuthContextValue {
  /** true while the initial session probe is still in flight */
  loading: boolean
  /** the identity, or null when anonymous */
  user: AuthUser | null
  /** whether the backend has OIDC configured (mirrors /api/auth/status) */
  configured: boolean
  isAdmin: boolean
  /** re-probe /api/auth/status + /api/auth/me (e.g. after first-run setup) */
  refresh: () => Promise<void>
  /** start the OIDC flow, returning to `next` (must start with '/') */
  signIn: (next?: string) => void
  /** destroy the backend session, then reload the page */
  signOut: () => Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)

const ANONYMOUS: AuthContextValue = {
  loading: false,
  user: null,
  configured: true,
  isAdmin: false,
  refresh: () => Promise.resolve(),
  signIn: () => {},
  signOut: () => Promise.resolve(),
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  return ctx ?? ANONYMOUS
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<{ user: AuthUser | null; configured: boolean }>({
    user: null,
    configured: true,
  })
  const [loading, setLoading] = useState(true)
  const [reloadCounter, setReloadCounter] = useState(0)

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        const [status, user] = await Promise.all([api.authStatus(), api.fetchAuthMe()])
        if (cancelled) return
        setSession({ configured: status.configured, user })
      } catch {
        if (!cancelled) setSession((s) => ({ ...s, configured: false }))
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [reloadCounter])

  const refresh = useCallback(async () => {
    setLoading(true)
    setReloadCounter((count) => count + 1)
  }, [])

  const signIn = useCallback((next?: string) => {
    const safeNext = next && next.startsWith('/') ? `?next=${encodeURIComponent(next)}` : ''
    window.location.assign(`/api/auth/login${safeNext}`)
  }, [])

  const signOut = useCallback(async () => {
    try {
      await api.logout()
    } catch {
      /* session already gone or backend down — reload regardless */
    }
    setSession((s) => ({ ...s, user: null }))
    window.location.reload()
  }, [])

  const value = useMemo<AuthContextValue>(
    () => ({
      loading,
      user: session.user,
      configured: session.configured,
      isAdmin: session.user?.is_admin ?? false,
      refresh,
      signIn,
      signOut,
    }),
    [loading, session, refresh, signIn, signOut],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}