import type { ReactNode } from 'react'
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import {
  currentLocale,
  normalizeLocale,
  setCurrentLocale,
  STORAGE_KEY,
  translateIn,
  type InterpParams,
  type Locale,
} from './locale'

/**
 * Runtime locale state for the React tree.
 *
 * The initial value comes from `readInitialLocale()` (persisted preference,
 * browser languages, or English) — restored on first render, so the screen
 * always matches what the pre-paint script already applied.
 *
 * `useLocale()`/`useT()` are SAFE OUTSIDE the provider: components rendered
 * without a <LocaleProvider> (isolated page tests) fall back to the
 * module-level current locale instead of throwing — the same convention
 * as useAuth().
 */

export interface LocaleContextValue {
  locale: Locale
  /** set the active locale; mirrors to localStorage, <html lang> and cross-tabs */
  setLocale: (locale: Locale) => void
}

/** Exposes `translateIn(locale, …)` for components needing explicit-locale lookups. */
export { translateIn }

export const LocaleContext = createContext<LocaleContextValue | null>(null)

function readInitialLocale(): Locale {
  if (typeof window === 'undefined') return 'en'
  const fromHtml = document.documentElement.getAttribute('lang')
  const normalized = normalizeLocale(fromHtml)
  if (normalized !== 'en') return normalized
  return currentLocale()
}

export function useLocale(): LocaleContextValue {
  return useContext(LocaleContext) ?? FALLBACK
}

/** Locale-aware translator bound to the current tree locale. */
export function useT(): (key: string, params?: InterpParams) => string {
  const { locale } = useLocale()
  return useMemo(() => translateFrom(locale), [locale])
}

/** Curried translator pinned to an explicit locale. */
export function translateFrom(locale: Locale) {
  return (key: string, params?: InterpParams) => translateIn(locale, key, params)
}

const FALLBACK: LocaleContextValue = {
  locale: currentLocale(),
  setLocale: () => {},
}

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(readInitialLocale)

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next)
    setCurrentLocale(next)
    document.documentElement.setAttribute('lang', next)
    try {
      window.localStorage.setItem(STORAGE_KEY, next)
    } catch {
      /* storage unavailable — this tab only */
    }
  }, [])

  // Apply the persisted pre-paint locale on mount (html lang may predate us).
  useEffect(() => {
    document.documentElement.setAttribute('lang', locale)
    setCurrentLocale(locale)
  }, [locale])

  // Keep multiple tabs in sync when the preference changes elsewhere.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key !== STORAGE_KEY) return
      setLocaleState(normalizeLocale(e.newValue))
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const value = useMemo<LocaleContextValue>(() => ({ locale, setLocale }), [locale, setLocale])

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>
}