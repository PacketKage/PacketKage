import { defineConfig } from '@playwright/test'

/**
 * E2E config. Boots three servers automatically so `npx playwright test` is
 * self-contained:
 *
 *   - fake OIDC provider (127.0.0.1:9090) — the same provider the pytest suite
 *     uses, wrapped as a standalone server (e2e/fake-idp-server.py)
 *   - backend (port 8000) configured to trust that provider
 *   - Vite dev server (port 5173), which proxies /api to the backend
 *
 * Every browser context is authenticated: setup projects drive the real
 * Authorization-Code + PKCE flow once and persist storageState, which the test
 * projects then load (admin by default, analyst for analyst.spec.ts).
 */

const IDP_PORT = 9090
const IDP_URL = `http://127.0.0.1:${IDP_PORT}`
const APP_URL = 'http://localhost:5173'
const REDIRECT_URI = `${APP_URL}/api/auth/callback`
const CLIENT_ID = 'packetkage-test'
const CLIENT_SECRET = 'test-secret'

export default defineConfig({
  testDir: './e2e',
  timeout: 90_000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: APP_URL,
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'setup-admin', testMatch: /setup\/admin\.setup\.ts/ },
    { name: 'setup-analyst', testMatch: /setup\/analyst\.setup\.ts/ },
    {
      name: 'chromium',
      testIgnore: [/setup\//, /auth\.spec\.ts/, /analyst\.spec\.ts/],
      dependencies: ['setup-admin'],
      use: { storageState: '.auth/admin.json' },
    },
    {
      name: 'auth',
      testMatch: /auth\.spec\.ts/,
      dependencies: ['setup-admin'],
      use: { storageState: '.auth/admin.json' },
    },
    {
      name: 'analyst',
      testMatch: /analyst\.spec\.ts/,
      dependencies: ['setup-analyst'],
      use: { storageState: '.auth/analyst.json' },
    },
  ],
  webServer: [
    {
      // Use the active Python interpreter so this works in both a local venv
      // and a fresh CI runner (which installs dependencies globally for the job).
      command: 'python e2e/fake-idp-server.py',
      url: `${IDP_URL}/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 30_000,
      env: {
        FAKE_OIDC_PORT: String(IDP_PORT),
        FAKE_OIDC_ISSUER: IDP_URL,
        FAKE_OIDC_REDIRECT_URI: REDIRECT_URI,
        FAKE_OIDC_CLIENT_ID: CLIENT_ID,
        FAKE_OIDC_CLIENT_SECRET: CLIENT_SECRET,
      },
    },
    {
      command: 'cd ../backend && python -m uvicorn app.main:app --port 8000',
      port: 8000,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      env: {
        PACKETKAGE_OIDC_ISSUER: IDP_URL,
        PACKETKAGE_OIDC_CLIENT_ID: CLIENT_ID,
        PACKETKAGE_OIDC_CLIENT_SECRET: CLIENT_SECRET,
        PACKETKAGE_OIDC_REDIRECT_URI: REDIRECT_URI,
        PACKETKAGE_PUBLIC_URL: APP_URL,
      },
    },
    {
      command: 'npm run dev',
      port: 5173,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
  ],
})
