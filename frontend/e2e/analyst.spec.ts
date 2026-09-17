import { readFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'

/**
 * Analyst (read/analyze, not admin) role end-to-end.
 *
 * Runs inside the `analyst` Playwright project (analyst storage state from
 * setup-analyst). Proves the frontend mirrors the backend's 403 boundary:
 * no Admin nav, no delete affordances, Access denied on /admin.
 */

test.setTimeout(120_000)

const UNIQUE = `analyst-e2e-${Date.now()}`

async function uploadPcap(page: import('@playwright/test').Page, fixture: string, name: string) {
  const chooser = Promise.all([
    page.waitForEvent('filechooser'),
    page.getByRole('button', { name: 'Select PCAP file' }).click(),
  ])
  const [fc] = await chooser
  await fc.setFiles({
    name,
    mimeType: 'application/octet-stream',
    buffer: readFileSync(`../test-data/synthetic/${fixture}`),
  })
}

test('analyst can reach the capture workflow but sees no Admin entry', async ({ page }) => {
  await page.goto('/capture')
  await expect(page.getByRole('heading', { name: 'Capture' })).toBeVisible()
  await expect(page.getByTitle('analyst@packetkage.test')).toBeVisible()
  await expect(page.getByRole('link', { name: 'Admin' })).toHaveCount(0)
})

test('analyst is denied the administration page', async ({ page }) => {
  await page.goto('/admin')
  await expect(page.getByRole('heading', { name: 'Access denied' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Administration' })).toHaveCount(0)
})

test('analyst sees no delete affordance on captures', async ({ page }) => {
  await page.goto('/capture')
  await uploadPcap(page, 'normal_traffic.pcap', `${UNIQUE}.pcap`)
  await expect(page.getByText(`${UNIQUE}.pcap`).first()).toBeVisible({ timeout: 30_000 })

  await expect(page.getByRole('button', { name: `Delete capture ${UNIQUE}.pcap` })).toHaveCount(0)
})
