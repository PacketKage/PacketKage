import { expect, test } from '@playwright/test'

/**
 * Authentication UX end-to-end against the fake OIDC provider.
 *
 * Runs inside the `auth` Playwright project (admin storage state from
 * setup-admin); the unauthenticated cases opt out with an empty state.
 */

test.describe('unauthenticated', () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test('protected pages render the sign-in screen instead of app data', async ({ page }) => {
    await page.goto('/capture')
    // scope to the page body: the Topbar also renders a "Sign in" when anonymous
    await expect(page.locator('#main-content').getByRole('button', { name: 'Sign in' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Capture' })).toHaveCount(0)
  })

  test('/admin shows the sign-in screen', async ({ page }) => {
    await page.goto('/admin')
    await expect(page.locator('#main-content').getByRole('button', { name: 'Sign in' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Administration' })).toHaveCount(0)
  })
})

test.describe('authenticated as admin', () => {
  test('the session persists across a full page reload', async ({ page }) => {
    await page.goto('/capture')
    await expect(page.getByRole('heading', { name: 'Capture' })).toBeVisible()

    await page.reload()
    await expect(page.getByRole('heading', { name: 'Capture' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible()
  })

  test('the Admin nav entry opens the administration page', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('link', { name: 'Admin' }).click()

    await expect(page).toHaveURL(/\/admin$/)
    await expect(page.getByRole('heading', { name: 'Administration' })).toBeVisible()
    await expect(page.getByText('admin@packetkage.test').first()).toBeVisible()
  })

  test('signing out returns to the sign-in screen', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible()

    await page.getByRole('button', { name: 'Sign out' }).click()

    await expect(page.locator('#main-content').getByRole('button', { name: 'Sign in' })).toBeVisible({
      timeout: 15_000,
    })
    // the protected dashboard is gone for this anonymous session
    await expect(page.getByRole('link', { name: 'Admin' })).toHaveCount(0)
  })
})
