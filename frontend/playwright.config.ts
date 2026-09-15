import { defineConfig } from '@playwright/test'

/**
 * E2E smoke test config.
 * Boots the backend (port 8000) and Vite dev server (port 5173) automatically
 * via webServer, so `npx playwright test` is fully self-contained.
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 90_000,
  retries: process.env.CI ? 1 : 0,
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      // Use the active Python interpreter so this works in both a local venv
      // and a fresh CI runner (which installs dependencies globally for the job).
      command: 'cd ../backend && python -m uvicorn app.main:app --port 8000',
      port: 8000,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
    {
      command: 'npm run dev',
      port: 5173,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
    },
  ],
})
