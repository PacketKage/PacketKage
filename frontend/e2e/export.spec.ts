import { expect, test } from '@playwright/test'

/**
 * E2E for CSV export: real backend + browser download event.
 * Reuses the smoke flow's deterministic c2_beacon.pcap (beaconing alert,
 * a handful of flows), then exports Flows and asserts the downloaded file.
 */
test.setTimeout(120_000)

test('flows export downloads a CSV with expected headers and rows', async ({ page }) => {
  await page.goto('/')

  // Upload + analyze the deterministic capture
  await page.getByRole('link', { name: 'Capture' }).click()
  const chooser = Promise.all([
    page.waitForEvent('filechooser'),
    page.getByRole('button', { name: 'Select PCAP file' }).click(),
  ])
  const [fc] = await chooser
  await fc.setFiles('../test-data/synthetic/c2_beacon.pcap')
  await expect(page.getByRole('button', { name: 'Analyze' })).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: 'Analyze' }).click()
  await expect(
    page.locator('.rounded-full', { hasText: 'completed' }).first(),
  ).toBeVisible({ timeout: 90_000 })

  // Flows → export (wait for table to load so the button is enabled)
  await page.getByRole('link', { name: 'Flows' }).click()
  const exportBtn = page.getByRole('button', { name: 'Export flows to CSV' })
  await expect(exportBtn).toBeEnabled({ timeout: 30_000 })

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    exportBtn.click(),
  ])

  // Filename: flows-YYYY-MM-DD.csv
  expect(download.suggestedFilename()).toMatch(/^flows-\d{4}-\d{2}-\d{2}\.csv$/)

  // Content: header row + at least one data row; RFC 4180 quoting + BOM
  const stream = await download.createReadStream()
  let content = ''
  for await (const chunk of stream) content += chunk.toString('utf-8')
  expect(content.startsWith('﻿First Seen,Source IP,Source Port')).toBe(true)
  expect(content).toContain('192.168.1.42')
  expect(content.split('\r\n').length).toBeGreaterThan(2)

  // Success toast with the row count
  await expect(page.getByText(/Exported \d+ flows/)).toBeVisible({ timeout: 10_000 })
})

test('alerts export with a filter matching nothing shows the empty toast', async ({ page }) => {
  // The flows test (same file, serial worker) analyzed c2_beacon.pcap; wait
  // for the picker to offer it before asserting.
  await page.goto('/alerts')
  const exportBtn = page.getByRole('button', { name: 'Export alerts to CSV' })
  await expect(exportBtn).toBeVisible({ timeout: 30_000 })

  // severity filter 'low' matches nothing in the deterministic beaconing pcap
  // (critical only) → export must show the "nothing to export" toast.
  await page.getByRole('button', { name: /^low/ }).click()

  await expect(exportBtn).toBeEnabled({ timeout: 30_000 })
  await exportBtn.click()
  await expect(
    page.getByText('Nothing to export — no rows match the current filters'),
  ).toBeVisible({ timeout: 10_000 })
})
