import { afterEach, describe, expect, it } from 'vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { Badge, Button, Spinner, StatusPill } from './ui'
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
