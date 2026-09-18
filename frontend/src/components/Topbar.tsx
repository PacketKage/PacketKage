import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { LogOut, Tag } from 'lucide-react'
import { Breadcrumbs } from './Breadcrumbs'
import { ThemeToggle } from './ThemeToggle'
import { LanguageToggle } from './LanguageToggle'
import { Button } from './ui'
import { useAuth } from '../auth/AuthContext'
import { useT } from '../i18n/LocaleContext'
import version from '../../package.json'

/** Route section → i18n key for page titles and breadcrumbs. */
const ROUTE_TITLE_KEYS: Record<string, string> = {
  '': 'topbar.route.dashboard',
  capture: 'topbar.route.capture',
  flows: 'topbar.route.flows',
  hosts: 'topbar.route.hosts',
  protocol: 'topbar.route.protocol',
  timeline: 'topbar.route.timeline',
  graph: 'topbar.route.graph',
  alerts: 'topbar.route.alerts',
  cases: 'topbar.route.cases',
  replay: 'topbar.route.replay',
  engineer: 'topbar.route.engineer',
  admin: 'topbar.route.admin',
}

export const APP_VERSION: string = (version as { version?: string }).version ?? '0.0.0'
/** Derives the page title from the current route, localised. */
export function usePageTitle(): string {
  const { pathname } = useLocation()
  const t = useT()
  const section = pathname.split('/').filter(Boolean)[0] ?? ''
  const key = ROUTE_TITLE_KEYS[section]
  return key ? t(key) : section.charAt(0).toUpperCase() + section.slice(1)
}

/** App-shell topbar: breadcrumb + document.title sync, version, theme + language toggles. */
export function Topbar() {
  const title = usePageTitle()
  const { user, isAdmin, signIn, signOut } = useAuth()
  const { pathname, search } = useLocation()
  const t = useT()

  useEffect(() => {
    document.title = t('topbar.title', { title })
  }, [t, title])

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-border bg-surface/80 px-6 backdrop-blur">
      <Breadcrumbs title={title} />

      <div className="flex items-center gap-1.5">
        <span className="hidden items-center gap-1.5 rounded-full bg-surface-2 px-2.5 py-1 text-xs font-medium text-fg-subtle ring-1 ring-border sm:inline-flex">
          <Tag size={12} aria-hidden />v{APP_VERSION}
        </span>
        {user ? (
          <>
            <span
              className="inline-flex items-center gap-1.5 rounded-full bg-surface-2 px-2.5 py-1 text-xs font-medium text-fg ring-1 ring-border"
              title={user.email ?? user.username}
            >
              {user.username}
              <span
                className={`rounded-full px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1 ${
                  isAdmin
                    ? 'bg-accent/15 text-accent ring-accent/30'
                    : 'bg-surface-3 text-fg-subtle ring-border'
                }`}
              >
                {isAdmin ? t('topbar.role.admin') : t('topbar.role.analyst')}
              </span>
            </span>
            <Button variant="ghost" size="sm" onClick={() => void signOut()}>
              <LogOut size={13} aria-hidden />
              {t('topbar.sign_out')}
            </Button>
          </>
        ) : (
          <Button variant="ghost" size="sm" onClick={() => signIn(pathname + search || '/')}>
            {t('topbar.sign_in')}
          </Button>
        )}
        <LanguageToggle />
        <ThemeToggle />
      </div>
    </header>
  )
}
