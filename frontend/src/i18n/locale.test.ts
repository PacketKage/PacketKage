import { afterEach, describe, expect, it } from 'vitest'
import en from './dictionaries/en.json'
import fr from './dictionaries/fr.json'
import {
  LOCALES,
  normalizeLocale,
  pluralSuffix,
  resolveLocale,
  setCurrentLocale,
  STORAGE_KEY,
  translate,
  translateIn,
} from './locale'

afterEach(() => {
  setCurrentLocale('en')
  window.localStorage.removeItem(STORAGE_KEY)
})

describe('normalizeLocale', () => {
  it('maps fr/fr-FR/fr_CA to fr', () => {
    expect(normalizeLocale('fr')).toBe('fr')
    expect(normalizeLocale('fr-FR')).toBe('fr')
    expect(normalizeLocale('fr_CA')).toBe('fr')
    expect(normalizeLocale('FR')).toBe('fr')
    expect(normalizeLocale(' fr-ca ')).toBe('fr')
  })

  it('defaults everything else to en', () => {
    expect(normalizeLocale('en')).toBe('en')
    expect(normalizeLocale('de-DE')).toBe('en')
    expect(normalizeLocale('')).toBe('en')
    expect(normalizeLocale(null)).toBe('en')
    expect(normalizeLocale(undefined)).toBe('en')
  })
})

describe('pluralSuffix', () => {
  it('English: plural only above 1', () => {
    expect(pluralSuffix('en', 0)).toBe('s')
    expect(pluralSuffix('en', 1)).toBe('')
    expect(pluralSuffix('en', 2)).toBe('s')
  })

  it('French: 0 and 1 are singular, 2+ plural', () => {
    expect(pluralSuffix('fr', 0)).toBe('')
    expect(pluralSuffix('fr', 1)).toBe('')
    expect(pluralSuffix('fr', 2)).toBe('s')
    expect(pluralSuffix('fr', 12)).toBe('s')
  })
})

describe('translateIn', () => {
  it('renders the English dictionary by default', () => {
    expect(translateIn('en', 'nav.alerts')).toBe('Alerts')
  })

  it('renders French when pinned to fr', () => {
    expect(translateIn('fr', 'nav.alerts')).toBe('Alertes')
    expect(translateIn('fr', 'nav.overview')).toBe("Vue d'ensemble")
  })

  it('interpolates named params', () => {
    expect(translateIn('en', 'hosts.card.sent', { packets: 42, bytes: '1.5 KB' })).toBe('↑ 1.5 KB · 42 pkt')
    expect(translateIn('fr', 'hosts.card.sent', { packets: 42, bytes: '1.5 Ko' })).toBe('↑ 1.5 Ko · 42 pkt')
  })

  it('renders the {s} plural marker via pluralSuffix', () => {
    expect(translateIn('en', 'dashboard.alert_summary', { count: 1, max: 80 })).toBe(
      '1 alert — max risk score 80',
    )
    expect(translateIn('en', 'dashboard.alert_summary', { count: 3, max: 80 })).toBe(
      '3 alerts — max risk score 80',
    )
    // French: 0 → singular, 2 → plural
    expect(translateIn('fr', 'dashboard.alert_summary', { count: 0, max: 0 })).toBe(
      '0 alerte — score de risque max 0',
    )
    expect(translateIn('fr', 'dashboard.alert_summary', { count: 2, max: 0 })).toBe(
      '2 alertes — score de risque max 0',
    )
  })

  it('returns the key literal when a key is missing everywhere', () => {
    expect(translateIn('fr', 'totally.missing.key')).toBe('totally.missing.key')
  })
})

describe('translate (module locale)', () => {
  it('follows the current locale set via setCurrentLocale', () => {
    setCurrentLocale('fr')
    expect(translate('nav.alerts')).toBe('Alertes')
    setCurrentLocale('en')
    expect(translate('nav.alerts')).toBe('Alerts')
  })
})

describe('resolveLocale', () => {
  it('saved preference wins over navigator languages', () => {
    window.localStorage.setItem(STORAGE_KEY, 'fr')
    expect(resolveLocale()).toBe('fr')
  })

  it('falls back to navigator.languages then en', () => {
    expect(resolveLocale()).toBe('en')
  })
})

describe('locale registry', () => {
  it('exposes the supported locale list', () => {
    expect([...LOCALES].sort()).toEqual(['en', 'fr'])
  })

  it('keeps en and fr dictionaries in key parity', () => {
    expect(Object.keys(fr).sort()).toEqual(Object.keys(en).sort())
    expect(Object.keys(en).length).toBeGreaterThan(100)
  })
})