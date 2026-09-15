import { readFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'

/**
 * Delete-capture E2E — deterministic full-stack flows.
 *
 * Uploads use unique filenames (the dev backend DB persists between runs,
 * so a shared name would collide with rows from earlier specs).
 *
 * The blocked-while-analyzing (409) path is NOT raced here on purpose —
 * small pcaps finish analysis in ~1s and the click would lose the race.
 * It is covered deterministically by:
 *   - backend: tests/test_capture_delete.py::test_delete_blocked_while_analyzing
 *   - frontend unit: CapturePage.test.tsx (409 detail surfaces, modal stays open)
 */
test.setTimeout(120_000)

const UNIQUE = `delete-e2e-${Date.now()}`

/** Upload a synthetic pcap under a unique name (dev DB persists rows). */
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

test('upload → delete via confirmation modal → gone from list', async ({ page }) => {
  await page.goto('/capture')

  await uploadPcap(page, 'normal_traffic.pcap', `${UNIQUE}-1.pcap`)
  await expect(page.getByText(`${UNIQUE}-1.pcap`).first()).toBeVisible({ timeout: 30_000 })

  // Open the delete confirmation from the list row
  await page
    .getByRole('button', { name: `Delete capture ${UNIQUE}-1.pcap` })
    .first()
    .click()

  // Modal shows the permanence warning and the exact filename
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText(/permanently deletes/)).toBeVisible()
  await expect(dialog.getByText(/cannot be undone/i)).toBeVisible()
  await expect(dialog.getByText(`${UNIQUE}-1.pcap`).first()).toBeVisible()

  // Confirm — success toast, row AND detail card disappear
  await dialog.getByRole('button', { name: 'Delete permanently' }).click()
  await expect(page.getByText('Capture deleted')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText(`${UNIQUE}-1.pcap`)).toHaveCount(0, { timeout: 30_000 })
})

test('upload → analyze → delete after completion → gone from list', async ({ page }) => {
  await page.goto('/capture')

  await uploadPcap(page, 'c2_beacon.pcap', `${UNIQUE}-2.pcap`)
  await expect(page.getByRole('button', { name: 'Analyze' })).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: 'Analyze' }).click()

  // Wait for terminal state before deleting (the blocked path is unit-tested)
  await expect(page.getByText(/Analysis completed/i)).toBeVisible({ timeout: 60_000 })
  await expect
    .poll(async () => page.getByText('Analysis running…').count(), { timeout: 30_000 })
    .toBe(0)

  await page
    .getByRole('button', { name: `Delete capture ${UNIQUE}-2.pcap` })
    .first()
    .click()
  await page.getByRole('dialog').getByRole('button', { name: 'Delete permanently' }).click()

  await expect(page.getByText('Capture deleted')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText(`${UNIQUE}-2.pcap`)).toHaveCount(0, { timeout: 30_000 })
})
