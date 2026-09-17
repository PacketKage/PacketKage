import type { Page } from '@playwright/test'

/**
 * Shared auth helpers for the Playwright suite.
 *
 * All e2e runs use the standalone fake OIDC provider (e2e/fake-idp-server.py)
 * started by playwright.config.ts. Identity is selected by first visiting the
 * provider's /choose endpoint, which sets its `pk_fake_user` cookie; the
 * provider then emits the matching `groups` claim on the ID token.
 */

export const IDP_URL = 'http://127.0.0.1:9090'

export type FakeUser = 'admin' | 'analyst' | 'nobody'

/** Point the fake provider at a user (sets its cookie in this browser context). */
export async function chooseUser(page: Page, user: FakeUser): Promise<void> {
  await page.goto(`${IDP_URL}/choose?user=${user}`)
}

/**
 * Drive the real Authorization-Code + PKCE flow: open the app at `next`
 * (RequireAuth renders the sign-in screen), click through to the provider and
 * back. Resolves once the app is authenticated at `next`.
 */
export async function signIn(page: Page, next = '/'): Promise<void> {
  await page.goto(next)
  // Scope to the page body: when anonymous the Topbar also renders a
  // "Sign in" button, so the bare role locator would be ambiguous.
  await page.locator('#main-content').getByRole('button', { name: 'Sign in' }).click()
  await page.waitForURL(
    (url) => url.host === 'localhost:5173' && !url.pathname.startsWith('/api/auth'),
  )
  await page.getByRole('button', { name: 'Sign out' }).waitFor()
}
