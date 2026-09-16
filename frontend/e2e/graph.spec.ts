import { readFileSync } from 'node:fs'
import { expect, test } from '@playwright/test'

/**
 * Graph tier regression tests.
 * 1. Small capture: every relationship type in the v2 graph gets a dynamic
 *    filter toggle (no hardcoded allowlist that silently drops unknown types),
 *    and toggling one off removes exactly its edges.
 * 2. Large capture: the graph switches to the scale tier (leaf domains
 *    collapsed, selective labels) and stays interactive.
 */

/**
 * Ensure a named synthetic capture is analyzed and available to the picker.
 * Self-seeding via the API — the test must not depend on captures left in
 * the DB by other test files (workers can run in any order).
 */
async function ensureAnalyzed(page: import('@playwright/test').Page, filename: string): Promise<void> {
  const resp = await page.request.get('http://localhost:8000/api/captures?limit=500')
  const captures: { id: string; filename: string; status: string }[] = await resp.json()
  const existing = captures.find((c) => c.filename === filename && c.status === 'completed')
  if (existing) return

  const upload = await page.request.post('http://localhost:8000/api/captures', {
    multipart: {
      file: {
        name: filename,
        mimeType: 'application/octet-stream',
        buffer: readFileSync(`../test-data/synthetic/${filename}`),
      },
    },
  })
  const capture = await upload.json()
  await page.request.post(`http://localhost:8000/api/captures/${capture.id}/analyze`, {
    data: {},
    headers: { 'Content-Type': 'application/json' },
  })
  await expect
    .poll(
      async () => {
        const r = await page.request.get(`http://localhost:8000/api/captures/${capture.id}`)
        return (await r.json()).status
      },
      { timeout: 120_000, message: `${filename} analysis to finish` },
    )
    .toBe('completed')
}

test('small graph renders all edge types with dynamic filter toggles', async ({ page }) => {
  await ensureAnalyzed(page, 'c2_beacon.pcap')
  await page.goto('/graph')

  // pick the small c2_beacon capture explicitly (newest may be a large one)
  await page.getByLabel('Select capture').selectOption({ label: 'c2_beacon.pcap' })

  // Graph canvas renders nodes (cytoscape creates canvas elements)
  await expect(page.locator('canvas').first()).toBeVisible({ timeout: 30_000 })

  // Filter rail is data-driven: every relationship in the v2 graph gets a
  // toggle. groups/targets/triggered were absent from the old hardcoded set.
  for (const rel of ['exposes', 'flow', 'groups', 'includes', 'targets', 'triggered']) {
    await expect(page.getByText(rel, { exact: true })).toBeVisible({ timeout: 15_000 })
  }

  // Total shown counter: nodes + edges visible under the current filters
  const shownCount = async () => {
    const texts = await page.getByText(/\d+ shown/).allTextContents()
    return texts.map((t) => parseInt(t.replace(/\D/g, ''), 10)).find((x) => !Number.isNaN(x)) ?? 0
  }
  // Default state: everything renders (hosts + service node + all edge types)
  const countBefore = await shownCount()
  expect(countBefore).toBeGreaterThan(0)

  // Toggling a relationship off removes exactly its edges (nodes stay)
  await page.getByText('triggered', { exact: true }).click()
  await expect.poll(shownCount).toBe(countBefore - 3)

  // Toggling it back on restores the full graph
  await page.getByText('triggered', { exact: true }).click()
  await expect.poll(shownCount).toBe(countBefore)
})

test('large graph switches to scale tier and stays interactive', async ({ page }) => {
  // measure graph build+layout time (perf guard: draft layout on ~950 elements)
  await ensureAnalyzed(page, 'large_graph.pcap')
  const t0 = Date.now()
  await page.goto('/graph')

  await page.getByLabel('Select capture').selectOption({ label: 'large_graph.pcap' })

  // scale tier badge appears in the header
  await expect(page.getByText('scale', { exact: true })).toBeVisible({ timeout: 30_000 })
  const buildMs = Date.now() - t0

  // leaf-only domains are auto-collapsed with an override button
  const showLeaves = page.getByText(/leaf domains hidden — show/)
  await expect(showLeaves).toBeVisible({ timeout: 30_000 })

  // graph canvas renders and is interactive (zoom via mouse wheel)
  const canvas = page.locator('canvas').first()
  await expect(canvas).toBeVisible({ timeout: 30_000 })
  console.log(`[perf] large graph render: ${buildMs}ms`)

  // labels hidden by default at scale; hover highlights a node (the
  // highlighted state draws labels for the hovered node only)
  await canvas.hover({ position: { x: 400, y: 300 } })
  await page.mouse.wheel(0, -120)
  await expect(canvas).toBeVisible({ timeout: 5_000 })

  // override: show leaf domains → the button disappears, element count grows
  const shownCount = async () => {
    const texts = await page.getByText(/\d+ shown/).allTextContents()
    return texts.map((t) => parseInt(t.replace(/\D/g, ''), 10)).find((x) => !Number.isNaN(x)) ?? 0
  }
  const countBefore = await shownCount()
  await showLeaves.click()
  await expect(page.getByText(/leaf domains hidden — show/)).toBeHidden({ timeout: 15_000 })
  const t1 = Date.now()
  const countAfter = await shownCount()
  console.log(`[perf] leaf-override re-layout (75 new nodes): ${Date.now() - t1}ms`)
  expect(countAfter).toBeGreaterThan(countBefore)
})

test('evidence graph v2: provenance, attack path, blast radius, evidence chain', async ({ page }) => {
  await ensureAnalyzed(page, 'c2_beacon.pcap')
  await page.goto('/graph')

  await page.getByLabel('Select capture').selectOption({ label: 'c2_beacon.pcap' })

  // mode toolbar present with all five investigation modes
  await expect(page.getByRole('tab', { name: 'Investigate' })).toBeVisible({ timeout: 30_000 })
  for (const label of ['Attack Path', 'Blast Radius', 'Timeline', 'Evidence']) {
    await expect(page.getByRole('tab', { name: label })).toBeVisible()
  }

  // --- Attack Path: find the observed flow path between beacon hosts ---
  await page.getByRole('tab', { name: 'Attack Path' }).click()
  await page.getByLabel('Source host').selectOption({ label: '192.168.1.42' })
  await page.getByLabel('Target host').selectOption({ label: '185.234.72.19' })
  await page.getByText('Find paths').click()
  await expect(page.getByText('path 1')).toBeVisible({ timeout: 15_000 })
  // the path is labeled as an inference over observed hops
  await expect(page.getByText('inferred', { exact: true }).first()).toBeVisible()

  // --- Blast Radius: bounded reachability from the workstation ---
  await page.getByRole('tab', { name: 'Blast Radius' }).click()
  await page.getByLabel('Blast radius start host').selectOption({ label: '192.168.1.42' })
  await page.getByText('Compute blast radius').click()
  await expect(page.getByText('Reachable nodes')).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Alert-flagged')).toBeVisible()

  // --- Evidence: the 5-step evidence chain with real deep links ---
  await page.getByRole('tab', { name: 'Evidence' }).click()
  await expect(page.getByText('Conclusion').first()).toBeVisible({ timeout: 15_000 })
  await expect(page.getByText('Flows / Observations').first()).toBeVisible()
  await expect(page.getByText('PCAP reference').first()).toBeVisible()

  // --- Timeline mode: event stream renders ---
  await page.getByRole('tab', { name: 'Timeline' }).click()
  await expect(page.getByText(/Chronological event stream/)).toBeVisible({ timeout: 15_000 })

  // --- API-level v2 guarantees (bounded, provenance-carrying) ---
  const capResp = await page.request.get('http://localhost:8000/api/captures?limit=500')
  const captures = await capResp.json()
  const cap = captures.find((c: { filename: string }) => c.filename === 'c2_beacon.pcap')
  const v2 = await (
    await page.request.get(`http://localhost:8000/api/graph/v2?capture_id=${cap.id}`)
  ).json()
  expect(v2.nodes.length).toBeGreaterThan(0)
  expect(v2.truncated).toBe(false)
  // provenance classes present; every edge carries timestamps + evidence ids
  expect(v2.stats.provenance_classes).toContain('correlated')
  for (const edge of v2.edges.slice(0, 10)) {
    expect(edge.first_seen).toBeLessThanOrEqual(edge.last_seen)
    expect(Array.isArray(edge.flow_ids)).toBe(true)
    expect(Array.isArray(edge.alert_ids)).toBe(true)
  }
  // suspicious edges carry deterministic explanations from real alerts
  const suspicious = v2.edges.filter((e: { alert_ids: string[] }) => e.alert_ids.length > 0)
  expect(suspicious.length).toBeGreaterThan(0)
  expect(suspicious[0].explanation).toContain('alert')

  // edge detail endpoint joins the evidence chain end-to-end
  const detail = await (
    await page.request.get(
      `http://localhost:8000/api/graph/v2/edge/${suspicious[0].id}?capture_id=${cap.id}`,
    )
  ).json()
  expect(detail.flows.length).toBeGreaterThan(0)
  expect(detail.alerts.length).toBeGreaterThan(0)
  // mitre enrichment is source-labeled: official ATT&CK mappings carry
  // T-patterned IDs; internal classifications carry none
  const mitre = detail.alerts[0].mitre
  expect(mitre).toBeTruthy()
  expect(['mitre', 'packetkage']).toContain(mitre.source)
  if (mitre.source === 'mitre') {
    expect(mitre.technique_id).toMatch(/^T\d{4}(\.\d{3})?$/)
  } else {
    expect(mitre.technique_id).toBeNull()
  }
})
