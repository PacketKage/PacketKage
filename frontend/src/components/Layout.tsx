import { useEffect, useMemo, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { Toaster } from 'sonner'
import {
  Activity,  Bell,
  ChevronsLeft,
  ChevronsRight,
  FolderOpen,
  Gauge,
  Network,
  PlayCircle,
  Radar,
  ScanSearch,
  Shield,
  Table2,
  Users,
  Waypoints,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Logo } from './Logo'
import { Topbar, APP_VERSION } from './Topbar'
import { useTheme } from '../hooks/theme'
import { useAuth } from '../auth/AuthContext'
import { useT } from '../i18n/LocaleContext'

interface NavItem {
  to: string
  /** i18n key for the label */
  labelKey: string
  icon: LucideIcon
  end?: boolean
}

interface NavGroup {
  /** i18n key for the group label */
  labelKey: string
  items: NavItem[]
}

const NAV_GROUPS: NavGroup[] = [
  {
    labelKey: 'nav.overview',
    items: [{ to: '/', labelKey: 'nav.dashboard', icon: Gauge, end: true }],
  },
  {
    labelKey: 'nav.analyze',
    items: [
      { to: '/capture', labelKey: 'nav.capture', icon: Radar },
      { to: '/flows', labelKey: 'nav.flows', icon: Table2 },
      { to: '/hosts', labelKey: 'nav.hosts', icon: Users },
      { to: '/protocol', labelKey: 'nav.protocol', icon: Activity },
    ],
  },
  {
    labelKey: 'nav.investigate',
    items: [
      { to: '/alerts', labelKey: 'nav.alerts', icon: Bell },
      { to: '/cases', labelKey: 'nav.cases', icon: FolderOpen },
      { to: '/timeline', labelKey: 'nav.timeline', icon: PlayCircle },
      { to: '/graph', labelKey: 'nav.graph', icon: Network },
      { to: '/replay', labelKey: 'nav.replay', icon: Waypoints },
    ],
  },
  {
    labelKey: 'nav.system',
    items: [{ to: '/engineer', labelKey: 'nav.engineer', icon: ScanSearch }],
  },
]

const STORAGE_KEY = 'packetkage-sidebar-collapsed'

function readInitialCollapsed(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === '1'
  } catch {
    return false
  }
}

export function Layout() {
  const [collapsed, setCollapsed] = useState(readInitialCollapsed)
  const { theme } = useTheme()
  const { isAdmin } = useAuth()
  const t = useT()

  // The Admin link is visible only to admins (mirrors the backend's
  // admin-only endpoints; the route itself is wrapped in RequireAdmin).
  const navGroups = useMemo(
    () =>
      isAdmin
        ? NAV_GROUPS.map((g) =>
            g.labelKey === 'nav.system'
              ? { ...g, items: [...g.items, { to: '/admin', labelKey: 'nav.admin', icon: Shield }] }
              : g,
          )
        : NAV_GROUPS,
    [isAdmin],
  )

  // persist + '[' keyboard shortcut
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, collapsed ? '1' : '0')
    } catch {
      /* storage unavailable */
    }
  }, [collapsed])

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === '[' && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement) && !(e.target instanceof HTMLSelectElement)) {
        setCollapsed((c) => !c)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-bg">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[60] focus:rounded-lg focus:bg-accent focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-accent-fg"
      >
        {t('nav.skip_to_content')}
      </a>

      {/* Sidebar */}
      <aside
        className={`flex shrink-0 flex-col border-r border-border bg-surface/60 transition-[width] duration-200 motion-reduce:transition-none ${
          collapsed ? 'w-[68px]' : 'w-56'
        }`}
      >
        <div className="flex h-14 items-center border-b border-border px-4">
          <NavLink to="/" aria-label={t('nav.home')} className="flex items-center overflow-hidden">
            {collapsed ? (
              <Logo size={26} withWordmark={false} />
            ) : (
              <Logo size={26} />
            )}
          </NavLink>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 py-4" aria-label={t('nav.main_navigation')}>
          {navGroups.map((group) => (
            <div key={group.labelKey} className="mb-4 last:mb-0">
              <div
                className={`mb-1.5 px-2.5 text-xs font-semibold uppercase tracking-wider text-fg-subtle ${
                  collapsed ? 'sr-only' : ''
                }`}
              >
                {t(group.labelKey)}
              </div>
              <ul className="space-y-1">
                {group.items.map((item) => (
                  <li key={item.to}>
                    <NavLink
                      to={item.to}
                      end={item.end}
                      title={collapsed ? t(item.labelKey) : undefined}
                      className={({ isActive }) =>
                        `group flex items-center rounded-lg px-2.5 py-2 text-sm transition-colors ${
                          isActive
                            ? 'bg-accent-soft text-accent ring-1 ring-accent-ring'
                            : 'text-fg-muted hover:bg-surface-2/60 hover:text-fg'
                        } ${collapsed ? 'justify-center' : ''}`
                      }
                    >
                      <item.icon size={16} className="shrink-0" aria-hidden />
                      <span className={`ml-2.5 truncate ${collapsed ? 'sr-only' : ''}`}>{t(item.labelKey)}</span>
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>

        <div className="flex items-center justify-between border-t border-border px-3 py-3">
          {collapsed ? (
            <button
              type="button"
              onClick={() => setCollapsed(false)}
              aria-label={t('nav.expand_sidebar')}
              aria-keyshortcuts="["
              className="mx-auto inline-flex h-8 w-8 items-center justify-center rounded-lg text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"
            >
              <ChevronsRight size={16} aria-hidden />
            </button>
          ) : (
            <>
              <span className="text-xs text-fg-subtle">v{APP_VERSION}</span>
              <button
                type="button"
                onClick={() => setCollapsed(true)}
                aria-label={t('nav.collapse_sidebar')}
                aria-keyshortcuts="["
                className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"
              >
                <ChevronsLeft size={16} aria-hidden />
              </button>
            </>
          )}
        </div>
      </aside>

      {/* Main column: topbar + page */}
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main id="main-content" className="flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>

      {/* Toast notifications (used by mutation flows) */}
      {/* theme follows the app toggle, not the OS — mixed dark-OS/light-app
          otherwise renders toasts in the wrong palette */}
      <Toaster theme={theme} position="bottom-right" richColors closeButton />
    </div>
  )
}
