import { Moon, Sun } from 'lucide-react'
import { useTheme } from '../hooks/theme'
import { useT } from '../i18n/LocaleContext'

/**
 * Visible dark/light theme switch, mounted in the Layout.
 * Uses the single existing theme system (useTheme — localStorage +
 * prefers-color-scheme + pre-paint script); no separate implementation.
 */
export function ThemeToggle() {
  const { theme, toggle } = useTheme()
  const t = useT()
  const isDark = theme === 'dark'
  const label = isDark ? t('theme.light') : t('theme.dark')
  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={label}
      aria-pressed={isDark}
      title={label}
      className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg"
    >
      {isDark ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />}
    </button>
  )
}
