import { useCallback, useEffect, useState } from 'react'

export type Theme = 'dark' | 'light'

const STORAGE_KEY = 'packetkage-theme'

function readInitialTheme(): Theme {
  if (typeof document !== 'undefined' && document.documentElement.classList.contains('light')) {
    return 'light' // index.html pre-paint script already applied it
  }
  return 'dark'
}

/**
 * Theme state synced to <html class="light"> and localStorage.
 * The initial value comes from the pre-paint script in index.html, so the
 * first render always matches what's already on screen.
 */
export function useTheme(): { theme: Theme; toggle: () => void; setTheme: (t: Theme) => void } {
  const [theme, setThemeState] = useState<Theme>(readInitialTheme)

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t)
    document.documentElement.classList.toggle('light', t === 'light')
    try {
      localStorage.setItem(STORAGE_KEY, t)
    } catch {
      /* storage unavailable — session-only theme */
    }
  }, [])

  const toggle = useCallback(() => {
    setTheme(theme === 'dark' ? 'light' : 'dark')
  }, [theme, setTheme])

  // Keep multiple components in sync if storage changes in another tab
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === STORAGE_KEY && (e.newValue === 'dark' || e.newValue === 'light')) {
        setThemeState(e.newValue)
        document.documentElement.classList.toggle('light', e.newValue === 'light')
      }
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  return { theme, toggle, setTheme }
}
