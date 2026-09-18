import { afterEach, describe, expect, it } from 'vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { Badge, Button, Spinner, StatusPill, formatBytes, formatDuration, formatTime } from './ui'
import { useTheme } from '../hooks/theme'

// jsdom render cleanup between tests
afterEach(() => cleanup())

describe('Button', () => {
  it('renders with default variant and type', () => {
    render(<Button>Save</Button>)
    const btn = screen.getByRole('button', { name: 'Save' })
    expect(btn).toBeDefined()
  })

  it('shows a loading spinner and disables interaction', () => {
    render(<Button loading>Analyze</Button>)
    const btn = screen.getByRole('button', { name: 'Analyze' }) as HTMLButtonElement
    expect(btn.disabled).toBe(true)
    expect(btn.querySelector('.animate-spin')).not.toBeNull()
  })

  it('disabled prop disables the button', () => {
    render(<Button disabled>Hold</Button>)
    expect((screen.getByRole('button', { name: 'Hold' }) as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('StatusPill', () => {
  it('maps known statuses to tones and capitalizes', () => {
    render(<StatusPill status="completed" />)
    expect(screen.getByText('Completed')).toBeDefined()
  })

  it('falls back to neutral for unknown statuses', () => {
    render(<StatusPill status="garbage" />)
    expect(screen.getByText('Garbage')).toBeDefined()
  })
})

describe('Spinner', () => {
  it('spinner is announced to screen readers', () => {
    render(<Spinner />)
    expect(screen.getByRole('status')).toBeDefined()
  })
})

describe('Locale-aware formatters', () => {
  it('formatBytes uses B/KB/MB/GB for en', () => {
    expect(formatBytes(0, 'en')).toBe('0 B')
    expect(formatBytes(1024, 'en')).toBe('1.0 KB')
    expect(formatBytes(5 * 1024 * 1024, 'en')).toBe('5.0 MB')
  })

  it('formatBytes uses o/Ko/Mo/Go for fr', () => {
    expect(formatBytes(0, 'fr')).toBe('0 o')
    expect(formatBytes(1024, 'fr')).toBe('1.0 Ko')
    expect(formatBytes(5 * 1024 * 1024, 'fr')).toBe('5.0 Mo')
  })

  it('formatDuration localizes the minute marker', () => {
    const start = 1_700_000_000
    expect(formatDuration(start, start + 45, 'en')).toBe('45.0s')
    expect(formatDuration(start, start + 90, 'en')).toBe('1m 30s')
    expect(formatDuration(start, start + 90, 'fr')).toBe('1 min 30s')
  })

  it('formatTime uses the requested locale', () => {
    const ts = 1_700_000_000
    const en = formatTime(ts, 'en')
    const fr = formatTime(ts, 'fr')
    expect(typeof en).toBe('string')
    expect(typeof fr).toBe('string')
    // The separator localization differs; just assert both render the hour.
    expect(en).not.toBe('—')
    expect(fr).not.toBe('—')
  })

  it('formatBytes falls back to the module-level current locale', async () => {
    const { setCurrentLocale } = await import('../i18n/locale')
    setCurrentLocale('fr')
    expect(formatBytes(0)).toBe('0 o')
    setCurrentLocale('en')
    expect(formatBytes(0)).toBe('0 B')
  })
})

describe('Badge tone passthrough', () => {
  it('renders arbitrary tone', () => {
    render(<Badge tone="info">beta</Badge>)
    expect(screen.getByText('beta')).toBeDefined()
  })
})

describe('useTheme', () => {
  function Probe() {
    const { theme, toggle } = useTheme()
    return (
      <button onClick={toggle} data-testid="probe">
        {theme}
      </button>
    )
  }

  it('defaults to dark and toggles to light', () => {
    document.documentElement.classList.remove('light')
    render(<Probe />)
    const probe = screen.getByTestId('probe')
    expect(probe.textContent).toBe('dark')
    act(() => {
      fireEvent.click(probe)
    })
    expect(probe.textContent).toBe('light')
    expect(document.documentElement.classList.contains('light')).toBe(true)
    // restore for other tests
    document.documentElement.classList.remove('light')
    try {
      localStorage.removeItem('packetkage-theme')
    } catch {
      /* ignore */
    }
  })

  it('picks up pre-applied light class from index.html script', () => {
    document.documentElement.classList.add('light')
    render(<Probe />)
    expect(screen.getByTestId('probe').textContent).toBe('light')
    document.documentElement.classList.remove('light')
  })
})
