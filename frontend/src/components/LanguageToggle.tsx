import { Languages } from 'lucide-react'
import { useLocale, useT } from '../i18n/LocaleContext'
import { LOCALES, type Locale } from '../i18n/locale'

const LABEL: Record<Locale, string> = { en: 'EN', fr: 'FR' }

/**
 * Explicit language switch (EN / FR), mounted in the Layout topbar.
 * Persistent via useLocale → localStorage; mirrors to <html lang> the same
 * way ThemeToggle mirrors to <html class>.
 */
export function LanguageToggle() {
  const { locale, setLocale } = useLocale()
  const t = useT()
  return (
    <div className="inline-flex items-center gap-0.5 rounded-lg p-0.5 ring-1 ring-border" role="group" aria-label={t('lang.title')}>
      {LOCALES.map((option) => {
        const active = option === locale
        return (
          <button
            key={option}
            type="button"
            onClick={() => setLocale(option)}
            aria-pressed={active}
            aria-label={option === 'fr' ? t('lang.switch_to_fr') : t('lang.switch_to_en')}
            className={`inline-flex h-6 items-center justify-center rounded-md px-1.5 text-xs font-semibold transition-colors ${
              active ? 'bg-surface-3 text-fg' : 'text-fg-muted hover:text-fg'
            }`}
          >
            <Languages size={12} className="mr-1" aria-hidden />
            {LABEL[option]}
          </button>
        )
      })}
    </div>
  )
}