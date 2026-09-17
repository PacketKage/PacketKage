import { expect, test as setup } from '@playwright/test'
import { chooseUser, signIn } from '../auth-helpers'

const ANALYST_STATE = '.auth/analyst.json'

setup('authenticate as analyst', async ({ page }) => {
  await chooseUser(page, 'analyst')
  await signIn(page, '/')

  // Signed in, but without the admin group: no Admin nav entry.
  await expect(page.getByTitle('analyst@packetkage.test')).toBeVisible()
  await expect(page.getByRole('link', { name: 'Admin' })).toHaveCount(0)

  await page.context().storageState({ path: ANALYST_STATE })
})
