import type { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { KeyRound, ShieldAlert } from 'lucide-react'
import { useAuth } from './AuthContext'
import { Logo } from '../components/Logo'
import { Button, Spinner } from '../components/ui'
import { SetupPage } from '../pages/SetupPage'
import { useT } from '../i18n/LocaleContext'

/**
 * Route guards wired in main.tsx.
 *
 * - <RequireAuth> renders its children only for an authenticated session;
 *   anonymous/loading/unconfigured visitors get a brand sign-in screen
 *   (the actual OIDC redirect happens on the sign-in button click).
 * - <RequireAdmin> additionally blocks authenticated non-admins with a
 *   Forbidden panel, mirroring the backend's 403 on admin-only endpoints.
 */

function FullScreenSpinner() {
  return (
    <div className="flex h-full min-h-[60vh] items-center justify-center p-16">
      <Spinner size={28} />
    </div>
  )
}

function SignInScreen({ reason }: { reason: string }) {
  const { configured, signIn } = useAuth()
  const { pathname, search } = useLocation()
  const next = pathname + search
  const t = useT()
  return (
    <div className="flex min-h-[70vh] items-center justify-center p-6">
      <div className="w-full max-w-md rounded-xl border border-border bg-surface-2/50 p-8">
        <div className="flex flex-col items-center text-center">
          <Logo size={40} withWordmark={false} />
          <h1 className="mt-4 text-lg font-semibold text-fg">PacketKage</h1>
          <p className="mt-1 text-sm text-fg-muted">{reason}</p>

          {configured ? (
            <>
              <p className="mt-4 text-sm leading-relaxed text-fg-subtle">
                {t('auth.sign_in.title')}
              </p>
              <Button
                variant="primary"
                size="lg"
                className="mt-6 w-full"
                onClick={() => signIn(next || '/')}
              >
                <KeyRound size={16} aria-hidden />
                {t('auth.sign_in')}
              </Button>
              <p className="mt-4 text-xs text-fg-subtle">{t('auth.sign_in_redirect')}</p>
            </>
          ) : (
            <div className="mt-6 w-full rounded-lg border border-warning/30 bg-warning/5 p-4 text-left">
              <p className="text-sm font-medium text-fg">{t('auth.not_configured')}</p>
              <p className="mt-1 text-xs leading-relaxed text-fg-muted">
                {t('auth.not_configured_detail', {
                  issuer: 'PACKETKAGE_OIDC_ISSUER',
                  client_id: 'PACKETKAGE_OIDC_CLIENT_ID',
                  client_secret: 'PACKETKAGE_OIDC_CLIENT_SECRET',
                })}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { loading, user, configured } = useAuth()
  const t = useT()
  if (loading) return <FullScreenSpinner />
  if (user) return <>{children}</>
  // No OIDC provider yet → run the first-run wizard instead of a dead sign-in.
  if (!configured) return <SetupPage />
  return <SignInScreen reason={t('auth.require_sign_in')} />
}

export function RequireAdmin({ children }: { children: ReactNode }) {
  const { loading, user, isAdmin, configured } = useAuth()
  const t = useT()
  if (loading) return <FullScreenSpinner />
  if (!configured) return <SetupPage />
  if (!user) return <SignInScreen reason={t('auth.require_sign_in')} />
  if (isAdmin) return <>{children}</>
  return (
    <div className="flex min-h-[70vh] items-center justify-center p-6">
      <div className="w-full max-w-md rounded-xl border border-danger/30 bg-danger/5 p-8 text-center">
        <ShieldAlert size={28} className="mx-auto text-danger" aria-hidden />
        <h1 className="mt-3 text-lg font-semibold text-fg">{t('auth.access_denied')}</h1>
        <p className="mt-2 text-sm leading-relaxed text-fg-muted">
          {t('auth.access_denied_detail', { role: 'analyst', group: 'packetkage-admin' })}
        </p>
        <Link
          to="/"
          className="mt-5 inline-flex items-center gap-2 text-sm font-medium text-accent hover:underline"
        >
          {t('auth.return_dashboard')}
        </Link>
      </div>
    </div>
  )
}