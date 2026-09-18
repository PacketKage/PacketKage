import { Link } from 'react-router-dom'
import { useT } from '../i18n/LocaleContext'

export function NotFoundPage() {
  const t = useT()
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 p-16 text-center">
      <div className="text-5xl font-bold text-fg-subtle">404</div>
      <p className="text-sm text-fg-muted">{t('notfound.subtitle')}</p>
      <Link
        to="/"
        className="mt-2 rounded-lg bg-accent/10 px-4 py-2 text-sm text-accent ring-1 ring-accent/30 hover:bg-accent/20"
      >
        {t('notfound.return')}
      </Link>
    </div>
  )
}
