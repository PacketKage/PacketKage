import { expect, test as setup } from '@playwright/test'
import { chooseUser, signIn } from '../auth-helpers'

const ADMIN_STATE = '.auth/admin.json'

setup('authenticate as admin', async ({ page }) => {
  await chooseUser(page, 'admin')
  await signIn(page, '/')

  await expect(page.getByTitle('admin@packetkage.test')).toBeVisible()
  await expect(page.getByRole('link', { name: 'Admin' })).toBeVisible()

  await page.context().storageState({ path: ADMIN_STATE })
})
