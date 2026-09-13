import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { Tag } from 'lucide-react'
import { Breadcrumbs } from '../components/Breadcrumbs'
import { ThemeToggle } from '../components/ThemeToggle'
import version from '../../package.json'

const ROUTE_TITLES: Record<string, string> = {
  '': 'Dashboard',
  capture: 'Capture',
  flows: 'Flows',
  hosts: 'Hosts',
  protocol: 'Protocol Analysis',
  timeline: 'Timeline',
  graph: 'Graph',
  alerts: 'Alerts',
  cases: 'Cases',
  replay: 'Replay',
  engineer: 'Engineer Mode',
}

export const APP_VERSION: string = (version as { version?: string }).version ?? '0.0.0'
/** Derives the page title from the current route. */
export function usePageTitle(): string {
  const { pathname } = useLocation()
  const section = pathname.split('/').filter(Boolean)[0] ?? ''
  return ROUTE_TITLES[section] ?? section.charAt(0).toUpperCase() + section.slice(1)
}

/** App-shell topbar: breadcrumb + document.title sync, version, theme toggle. */
export function Topbar() {
  const title = usePageTitle()

  useEffect(() => {
    document.title = `PacketKage · ${title}`
  }, [title])

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-border bg-surface/80 px-6 backdrop-blur">
      <Breadcrumbs title={title} />

      <div className="flex items-center gap-1.5">
        <span className="hidden items-center gap-1.5 rounded-full bg-surface-2 px-2.5 py-1 text-xs font-medium text-fg-subtle ring-1 ring-border sm:inline-flex">
          <Tag size={12} aria-hidden />v{APP_VERSION}
        </span>
        <ThemeToggle />
      </div>
    </header>
  )
}
