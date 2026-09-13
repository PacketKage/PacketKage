import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { ThemeToggle } from './ThemeToggle'

beforeEach(() => {
  document.documentElement.classList.remove('light')
  try {
    localStorage.removeItem('packetkage-theme')
  } catch {
    /* storage unavailable */
  }
})

afterEach(() => {
  cleanup()
  document.documentElement.classList.remove('light')
  try {
    localStorage.removeItem('packetkage-theme')
  } catch {
    /* storage unavailable */
  }
})

describe('ThemeToggle', () => {
  it('renders as a labelled, pressed-state button in dark mode', () => {
    render(<ThemeToggle />)
    const btn = screen.getByRole('button', { name: 'Switch to light theme' })
    expect(btn.getAttribute('aria-pressed')).toBe('true')
    expect(btn.getAttribute('title')).toBe('Switch to light theme')
  })

  it('toggles the document class and persists via the existing theme system', () => {
    render(<ThemeToggle />)
    const btn = screen.getByRole('button', { name: 'Switch to light theme' })

    act(() => {
      fireEvent.click(btn)
    })

    // document switched to light + preference persisted
    expect(document.documentElement.classList.contains('light')).toBe(true)
    expect(localStorage.getItem('packetkage-theme')).toBe('light')

    // button re-labels for the reverse action
    const darkBtn = screen.getByRole('button', { name: 'Switch to dark theme' })
    expect(darkBtn.getAttribute('aria-pressed')).toBe('false')

    // and toggles back to dark
    act(() => {
      fireEvent.click(darkBtn)
    })
    expect(document.documentElement.classList.contains('light')).toBe(false)
    expect(localStorage.getItem('packetkage-theme')).toBe('dark')
  })

  it('starts in light mode when the pre-paint script already applied it', () => {
    document.documentElement.classList.add('light')
    render(<ThemeToggle />)
    // light already active → offers switching back to dark
    expect(screen.getByRole('button', { name: 'Switch to dark theme' })).toBeDefined()
  })
})
