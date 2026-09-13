/**
 * Runtime theme audit — verifies every route renders with resolved token
 * colors on BOTH themes (catches typo'd/unresolved Tailwind classes that
 * unit tests cannot see).
 *
 * Usage: node scripts/theme-audit.mjs
 * Boots nothing itself — expects `npx vite` (5173) and the backend (8000)
 * to be reachable. Exits non-zero on failure.
 */
import { chromium } from '@playwright/test'

const BASE = 'http://localhost:5173'
const ROUTES = [
  ['/', 'Dashboard'],
  ['/capture', 'Capture'],
  ['/flows', 'Flows'],
  ['/hosts', 'Hosts'],
  ['/protocol', 'Protocol'],
  ['/alerts', 'Alerts'],
  ['/cases', 'Cases'],
  ['/timeline', 'Timeline'],
  ['/graph', 'Graph'],
  ['/replay', 'Replay'],
  ['/engineer', 'Engineer Mode'],
]

function parseColor(str) {
  // oklch(...) / oklab(...) / rgb(...) → crude but sufficient validity check
  if (!str || str === 'rgba(0, 0, 0, 0)' || str === 'transparent') return null
  return str
}

async function auditRoute(page, path, name) {
  const results = []
  const samples = await page.evaluate(() => {
    const out = []
    const push = (sel, prop, label) => {
      const el = document.querySelector(sel)
      if (el) out.push({ label, sel, value: getComputedStyle(el)[prop] })
    }
    push('body', 'backgroundColor', 'body-bg')
    push('aside', 'backgroundColor', 'sidebar-bg')
    push('header', 'backgroundColor', 'topbar-bg')
    // NOTE: <main> is intentionally transparent (inherits app bg) — not sampled
    push('h1', 'color', 'h1-color')
    return out
  })
  for (const s of samples) {
    const v = parseColor(s.value)
    if (!v) results.push(`FAIL ${name}${path}: ${s.label} (${s.sel}) unresolved: "${s.value}"`)
  }
  if (!samples.length) results.push(`FAIL ${name}${path}: no elements sampled`)
  return results
}

async function main() {
  const browser = await chromium.launch()
  const failures = []

  for (const [theme, media] of [
    ['dark', 'dark'],
    ['light', 'light'],
  ]) {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
    await page.emulateMedia({ colorScheme: media })
    await page.goto(BASE + '/')
    await page.evaluate(() => localStorage.removeItem('packetkage-theme'))
    await page.reload()
    await page.waitForTimeout(500)

    for (const [path, name] of ROUTES) {
      await page.goto(BASE + path)
      await page.waitForTimeout(700) // lazy route chunks + queries settle
      failures.push(...(await auditRoute(page, path, name)))
    }

    // token sanity per theme: body bg must match the theme's --bg
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor)
    const expected = theme === 'dark' ? 'oklch(0.145 0.02 260)' : 'oklch(0.972 0.003 255)'
    if (!bg.startsWith('oklch') || bg !== expected) {
      failures.push(`FAIL ${theme}: body bg "${bg}" != expected "${expected}"`)
    }
    await page.close()
  }

  await browser.close()

  if (failures.length) {
    console.error(`\n${failures.length} FAILURE(S):`)
    for (const f of failures) console.error(' ' + f)
    process.exit(1)
  }
  console.log(`theme-audit: ${ROUTES.length} routes × 2 themes — all token colors resolved ✓`)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
