import { Component, type ReactNode } from 'react'
import { translate } from '../i18n/locale'

/** Route-level error boundary — keeps one bad page from white-screening the app. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  render() {
    if (this.state.error) {
      const t = (key: string) => translate(key)
      return (
        <div className="flex h-full flex-col items-center justify-center gap-4 p-16 text-center">
          
          <h2 className="text-xl font-semibold text-fg">{t('error.title')}</h2>
          <p className="max-w-md font-mono text-xs text-fg-subtle">{this.state.error.message}</p>
          <button
            onClick={() => this.setState({ error: null })}
            className="rounded-lg bg-surface-3 px-4 py-2 text-sm text-fg-muted ring-1 ring-border-strong hover:bg-border-strong"
          >
            {t('error.retry')}
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
