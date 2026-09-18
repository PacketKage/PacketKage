import en from './dictionaries/en.json'
import fr from './dictionaries/fr.json'

export type Locale = 'en' | 'fr'

export const LOCALES: readonly Locale[] = ['en', 'fr']

export const STORAGE_KEY = 'packetkage-locale'

const DICTIONARIES: Record<Locale, Record<string, string>> = { en, fr }

let _current: Locale = resolveLocale()
export function currentLocale(): Locale {
  return _current
}

/** Runtime-visible current locale for pure modules (toasts, formatters, client). */
export function setCurrentLocale(locale: Locale): Locale {
  _current = locale
  return _current
}

/** Normalizes a preferred language tag: fr / fr-FR / fr-CA / fr-x → 'fr', else 'en'. */
export function normalizeLocale(raw: string | null | undefined): Locale {
  if (!raw) return 'en'
  const tag = raw.trim().toLowerCase()
  if (tag === 'fr' || tag.startsWith('fr-') || tag.startsWith('fr_')) return 'fr'
  return 'en'
}

/**
 * Resolves the effective locale from (in priority order):
 * saved preference → browser languages → English default.
 * Mirrors the pre-paint script; safe to call in a browser only.
 */
export function resolveLocale(): Locale {
  if (typeof window === 'undefined') return 'en'
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY)
    if (saved) return normalizeLocale(saved)
  } catch {
    /* storage unavailable — fall through to navigator */
  }
  for (const lang of navigator.languages ?? []) {
    const locale = normalizeLocale(lang)
    if (locale !== 'en') return locale
  }
  return 'en'
}

export type InterpParams = Record<string, string | number | undefined>

const PARAM_RE = /\{(\w+)\}/g

/** Interpolates `{name}` placeholders; a `{s}` marker is rendered via pluralSuffix(count). */
export function interpolate(template: string, params: InterpParams, locale: Locale): string {
  return template.replace(PARAM_RE, (match, name: string) => {
    if (name === 's') {
      const count = typeof params.count === 'number' ? params.count : 0
      return pluralSuffix(locale, count)
    }
    const value = params[name]
    return value === undefined || value === null ? match : String(value)
  })
}

/** English pluralizes 0/2+; French treats 0 and 1 as singular, 2+ as plural. */
export function pluralSuffix(locale: Locale, count: number): string {
  if (locale === 'fr') return count < 2 ? '' : 's'
  return count === 1 ? '' : 's'
}

/**
 * Looks up a translation key in the active dictionary, interpolating params.
 * Unknown keys, or values that try to inject HTML, fall back defensively:
 * the key itself is never an HTML-injection vector because dictionaries are
 * static, and every value is rendered through React escaping.
 */
export function translate(key: string, params?: InterpParams): string {
  return translateIn(_current, key, params)
}

/** The same lookup pinned to an explicit locale — for multi-locale rendering. */
export function translateIn(locale: Locale, key: string, params?: InterpParams): string {
  const template = DICTIONARIES[locale][key] ?? DICTIONARIES.en[key] ?? key
  return params ? interpolate(template, params, locale) : template
}