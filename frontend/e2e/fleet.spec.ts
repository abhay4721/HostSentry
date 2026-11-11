import { expect, test } from '@playwright/test'

const host = {
  id: 'arch-linux',
  hostname: 'arch',
  distribution: 'arch',
  kernel_version: '6.12.1-arch1-1',
  agent_version: 'test',
  policy_version: 0,
  last_seen: '2026-11-10T12:00:00Z',
  online: true,
  cpu_usage_percent: 12.5,
  memory_usage_percent: 42,
  open_incidents: 0,
  health_score: 98,
  report: {
    collected_at: '2026-11-10T12:00:00Z',
    system: { hostname: 'arch', distribution: 'arch', kernel_version: '6.12.1-arch1-1', uptime_seconds: 3600, agent_version: 'test' },
    cpu: { usage_percent: 12.5, core_usage_percent: [10, 15], load_1: 0.3 },
    memory: { used_bytes: 4_200_000_000, total_bytes: 16_000_000_000, usage_percent: 42 },
    disks: [{ mountpoint: '/', filesystem: 'btrfs', used_bytes: 40, total_bytes: 100, usage_percent: 40, inodes_usage_percent: 2 }],
    disk_io: [],
    network: [],
    interfaces: [],
    processes: [],
    services: [{ name: 'systemd-journald.service', active_state: 'active', sub_state: 'running', main_pid: 1, last_result: 'success', restart_count: 0 }],
    warnings: [],
  },
}

test('sign-in validation, fleet overview, and host details render API data', async ({ page }) => {
  let loginAttempts = 0
  await page.route('**/api/v1/**', async route => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname

    if (path === '/api/v1/auth/login' && request.method() === 'POST') {
      loginAttempts += 1
      if (loginAttempts === 1) {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({ error: { message: 'Invalid credentials' } }),
        })
        return
      }
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ token: 'browser-test-session', user: { role: 'admin' } }),
      })
      return
    }
    if (path === '/api/v1/auth/me') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ role: 'admin' }) })
      return
    }
    if (path === '/api/v1/hosts/arch-linux') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(host) })
      return
    }
    if (path === '/api/v1/hosts/arch-linux/metrics') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ series: [] }) })
      return
    }
    if (path.startsWith('/api/v1/incidents/')) {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: [] }) })
      return
    }
    if (path === '/api/v1/hosts') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: [host] }) })
      return
    }
    if (path === '/api/v1/incidents' || path === '/api/v1/recoveries' || path === '/api/v1/groups') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: [] }) })
      return
    }
    if (path === '/api/v1/policies') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ items: [], recovery_enabled: false, dry_run: true }) })
      return
    }
    if (path === '/api/v1/overview') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ total_hosts: 1, online_hosts: 1, healthy_hosts: 1, critical_hosts: 0, active_incidents: 0, successful_recoveries: 0 }) })
      return
    }

    await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: { message: `Unhandled test API request: ${path}` } }) })
  })

  await page.goto('/')
  await page.getByLabel('Email').fill('admin@example.org')
  await page.getByLabel('Password').fill('incorrect password')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText('Invalid credentials')).toBeVisible()

  await page.getByLabel('Password').fill('correct test password')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Fleet overview' })).toBeVisible()
  await expect(page.getByText('1', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('arch-linux')).toBeVisible()

  await page.getByRole('row').filter({ hasText: 'arch-linux' }).click()
  await expect(page.getByRole('heading', { name: 'arch' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'CPU by core' })).toBeVisible()
  await expect(page.getByText('systemd-journald.service')).toBeVisible()
  await expect(page.getByText('No historical samples yet.').first()).toBeVisible()

  await page.getByRole('button', { name: 'CPU monitoring' }).click()
  await expect(page.getByRole('heading', { name: 'CPU monitoring' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'CPU by host' })).toBeVisible()
  await page.getByRole('button', { name: 'Memory monitoring' }).click()
  await expect(page.getByRole('heading', { name: 'Memory by host' })).toBeVisible()
  await page.getByRole('button', { name: 'Disk monitoring' }).click()
  await expect(page.getByRole('heading', { name: 'Filesystem capacity' })).toBeVisible()
  await page.getByRole('button', { name: 'Process monitoring' }).click()
  await expect(page.getByRole('heading', { name: 'Top reported processes' })).toBeVisible()
  await page.getByRole('button', { name: 'Service monitoring' }).click()
  await expect(page.getByRole('heading', { name: 'Configured systemd units' })).toBeVisible()
  await page.getByRole('button', { name: 'Active incidents' }).click()
  await expect(page.getByRole('heading', { level: 2, name: 'Active incidents' })).toBeVisible()
  await page.getByRole('button', { name: 'Incident history' }).click()
  await expect(page.getByRole('heading', { level: 2, name: 'Incident history' })).toBeVisible()
})
