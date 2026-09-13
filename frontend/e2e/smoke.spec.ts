import { expect, test } from '@playwright/test'

/**
 * End-to-end smoke: the whole product in one path.
 * upload → analyze → alerts appear. If this passes, everything wired together works.
 */
test.setTimeout(120_000)

test('upload → analyze → alerts appear', async ({ page }) => {
  await page.goto('/')

  // App shell rendered with the new brand
  await expect(page).toHaveTitle('PacketKage · Dashboard')
  await expect(page.getByRole('link', { name: 'PacketKage home' })).toBeVisible()

  // Go to the capture page and upload the c2 beacon pcap (deterministic alert source)
  await page.getByRole('link', { name: 'Capture' }).click()
  const chooser = Promise.all([
    page.waitForEvent('filechooser'),
    page.getByRole('button', { name: 'Select PCAP file' }).click(),
  ])
  const [fc] = await chooser
  await fc.setFiles('../test-data/synthetic/c2_beacon.pcap')

  // Wait for the upload to register, then start analysis
  await expect(page.getByRole('button', { name: 'Analyze' })).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: 'Analyze' }).click()

  // Analysis completes: the selected capture's status pill turns to completed
  await expect(
    page
      .locator('.rounded-full', { hasText: 'completed' })
      .first(),
  ).toBeVisible({ timeout: 90_000 })

  // Alerts page shows the beaconing detection (rule card, not the incident banner)
  await page.getByRole('link', { name: 'Alerts' }).click()
  await expect(
    page.getByText('Beaconing: 192.168.1.42 → 185.234.72.19'),
  ).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('CRITICAL', { exact: true }).first()).toBeVisible()
})
