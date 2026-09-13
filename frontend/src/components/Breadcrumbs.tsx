import { useLocation, useNavigate } from 'react-router-dom'
import { ChevronRight, Home } from 'lucide-react'

/** Home / section breadcrumb shown in the topbar. */
export function Breadcrumbs({ title }: { title: string }) {
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const section = pathname.split('/').filter(Boolean)[0] ?? ''

  return (
    <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
      <button
        type="button"
        onClick={() => navigate('/')}
        className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"
        aria-label="Dashboard"
      >
        <Home size={14} aria-hidden />
      </button>
      {section ? (
        <>
          <ChevronRight size={14} className="shrink-0 text-fg-subtle" aria-hidden />
          <span className="truncate font-medium text-fg" aria-current="page">
            {title}
          </span>
        </>
      ) : (
        <span className="truncate font-medium text-fg" aria-current="page">
          {title}
        </span>
      )}
    </nav>
  )
}
