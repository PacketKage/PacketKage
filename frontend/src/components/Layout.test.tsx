import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Layout } from './Layout'
import { Breadcrumbs } from './Breadcrumbs'

beforeEach(() => {
  try {
    localStorage.removeItem('packetkage-sidebar-collapsed')
  } catch {
    /* storage unavailable */
  }
})

afterEach(() => {
  cleanup()
  try {
    localStorage.removeItem('packetkage-sidebar-collapsed')
  } catch {
    /* storage unavailable */
  }
})

function renderLayoutAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Layout />
    </MemoryRouter>,
  )
}

describe('Layout shell', () => {
  it('renders grouped navigation with all 11 routes', () => {
    renderLayoutAt('/')
    const nav = screen.getByLabelText('Main navigation')
    const links = nav.querySelectorAll('a')
    expect(links.length).toBe(11)
    for (const label of ['Overview', 'Analyze', 'Investigate', 'System']) {
      expect(screen.getByText(label)).toBeDefined()
    }
  })

  it('shows breadcrumb + section title, and syncs document.title', async () => {
    renderLayoutAt('/alerts')
    const crumb = screen.getByLabelText('Breadcrumb')
    expect(crumb.textContent).toContain('Alerts')
    await waitFor(() => expect(document.title).toBe('PacketKage · Alerts'))
  })

  it('collapses via button, persists, and restores via [ shortcut', async () => {
    renderLayoutAt('/')
    const aside = document.querySelector('aside') as HTMLElement
    expect(aside.className).not.toContain('w-[68px]')

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Collapse sidebar' }))
    })
    expect(aside.className).toContain('w-[68px]')
    expect(localStorage.getItem('packetkage-sidebar-collapsed')).toBe('1')
    // collapsed mode keeps labels screen-reader accessible
    const nav = screen.getByLabelText('Main navigation')
    expect(nav.textContent).toContain('Dashboard')

    await act(async () => {
      fireEvent.keyDown(window, { key: '[' })
    })
    expect(aside.className).not.toContain('w-[68px]')
    expect(localStorage.getItem('packetkage-sidebar-collapsed')).toBe('0')
  })

  it('renders skip-to-content link and main landmark', () => {
    renderLayoutAt('/')
    expect(screen.getByRole('link', { name: 'Skip to content' })).toBeDefined()
    expect(document.getElementById('main-content')).not.toBeNull()
  })

  it('mounts the theme toggle in the topbar', () => {
    renderLayoutAt('/')
    expect(screen.getByRole('button', { name: /theme/ })).toBeDefined()
  })
})

describe('Breadcrumbs', () => {
  it('shows only home on the dashboard root', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <Breadcrumbs title="Dashboard" />
      </MemoryRouter>,
    )
    expect(screen.getByRole('button', { name: 'Dashboard' })).toBeDefined()
    expect(screen.getByText('Dashboard', { selector: 'span[aria-current="page"]' })).toBeDefined()
  })

  it('shows home > section on nested routes', () => {
    render(
      <MemoryRouter initialEntries={['/alerts']}>
        <Breadcrumbs title="Alerts" />
      </MemoryRouter>,
    )
    const crumb = screen.getByLabelText('Breadcrumb')
    expect(crumb.textContent).toContain('Alerts')
  })
})
