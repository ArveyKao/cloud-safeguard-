#!/usr/bin/env node
/**
 * Cloud Safeguard console E2E (A13) — independent verifier, black-box over the
 * shipped bundle served by the real control plane.
 *
 * Tooling lives under /tmp only (playwright-core + cached Chromium); this file
 * is the durable, re-runnable evidence script.
 *
 * Env: BASE, ADMIN_TOKEN, AGENT_TOKEN, SHOTS (screenshot dir), SHOTS_URL optional
 * Writes screenshots as PNG and prints PASS/FAIL lines; exits nonzero on failure.
 * Never prints tokens or writes them to logs.
 */
import { createRequire } from 'node:module'
import fs from 'node:fs'
import path from 'node:path'

const require = createRequire(import.meta.url)
const { chromium } = require(process.env.PW_MODULE || '/tmp/csg-verify/ui/node_modules/playwright-core')
const BASE = process.env.BASE
const ADMIN = process.env.ADMIN_TOKEN
const AGENT = process.env.AGENT_TOKEN
const SHOTS = process.env.SHOTS
const CHROME = process.env.CHROME || `${process.env.HOME}/Library/Caches/ms-playwright/chromium-1228/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing`
if (!BASE || !ADMIN || !AGENT || !SHOTS) { console.error('missing env'); process.exit(2) }
fs.mkdirSync(SHOTS, { recursive: true })

let pass = 0, fail = 0
const failures = []
const ok = (name) => { pass++; console.log(`PASS ${name}`) }
const no = (name, detail) => { fail++; failures.push(name); console.log(`FAIL ${name} -- ${detail}`) }
const check = (name, cond, detail = '') => (cond ? ok(name) : no(name, detail))

async function api(method, p, token, body) {
  const res = await fetch(BASE + p, {
    method,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let json = null
  try { json = await res.json() } catch { /* ignore */ }
  return { status: res.status, json }
}

const consoleErrors = []
function watch(page, tag) {
  page.on('pageerror', (e) => consoleErrors.push(`${tag} pageerror: ${e.message}`))
  page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(`${tag} console: ${m.text()}`) })
}
const shot = async (page, name) => {
  await page.screenshot({ path: path.join(SHOTS, name), fullPage: false })
  console.log(`  screenshot: ${name}`)
}

const browser = await chromium.launch({ executablePath: CHROME, headless: true })
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } })
const page = await context.newPage()
page.setDefaultTimeout(10000)
watch(page, 'app')

try {
  // ---------- seed pending work for the queue (via real agent API) ----------
  const seeds = []
  for (const [cap, reason, params] of [
    ['aliyun.dns.manage', 'add ACME DNS-01 TXT record for renewal', { domain: 'arveykao.com' }],
    ['aliyun.ecs.instance.ops', 'restart web-01 after deploy', { instance_id: 'i-2ze0demo001' }],
    ['aliyun.cert.dns01', 'DNS-01 challenge for cert renew', { domain: 'guanlanstudio.com' }],
  ]) {
    const r = await api('POST', '/api/v1/agent/leases', AGENT, { capability_id: cap, params, reason, ttl_seconds: 600 })
    check(`seed pending lease ${cap}`, r.status === 201 && r.json?.data?.status === 'pending', `status=${r.status}`)
    if (r.json?.data?.id) seeds.push(r.json.data.id)
  }
  // an auto-approved lease so "Active leases" is non-zero
  const ar = await api('POST', '/api/v1/agent/leases', AGENT, { capability_id: 'aliyun.cloud.read', reason: 'console E2E active lease seed', ttl_seconds: 300 })
  check('seed active lease', ar.status === 201 && ar.json?.data?.status === 'active', `status=${ar.status}`)

  const overviewApi = await api('GET', '/api/v1/admin/overview', ADMIN)
  const counts = overviewApi.json?.data?.counts
  check('admin overview API shape', Boolean(counts), JSON.stringify(overviewApi.json).slice(0, 120))

  // ---------- login ----------
  await page.goto(BASE + '/', { waitUntil: 'networkidle' })
  check('login page renders', await page.locator('#admin-token').count() === 1)
  check('login tagline present', (await page.locator('body').innerText()).includes('not long-lived keys'))
  await shot(page, '01-login.png')
  await page.fill('#admin-token', ADMIN)
  await page.click('button[type="submit"]')
  await page.waitForSelector('.grid-stats', { timeout: 10000 })
  check('login succeeds -> overview', page.url().endsWith('/overview'))

  // ---------- overview counts match API ----------
  const statsText = await page.locator('.grid-stats').innerText()
  const body = await page.locator('body').innerText()
  const st = statsText.toLowerCase()
  check('overview stat cards', ['agents', 'active leases', 'pending approvals', 'audit events'].every((t) => st.includes(t)), JSON.stringify(statsText.replace(/\n/g, ' | ').slice(0, 200)))
  const pendingUi = await page.locator('.approval-item').count()
  check('overview pending queue shows seeded leases', pendingUi >= 2, `ui=${pendingUi} api=${counts.pending_leases}`)
  check('overview pending count matches API', pendingUi === Math.min(counts.pending_leases, 20), `ui=${pendingUi} api=${counts.pending_leases}`)
  await shot(page, '02-overview-pending-queue.png')

  // ---------- approve a pending lease from the UI (modal TTL + note) ----------
  const target = seeds[0]
  const item = page.locator('.approval-item').filter({ hasText: target })
  check('pending lease visible in queue', await item.count() === 1)
  await item.getByRole('button', { name: 'Approve', exact: true }).click()
  await page.waitForSelector('.approval-form', { timeout: 5000 })
  check('approve form exposes TTL + note', await page.locator('input[id^="ttl-"]').count() === 1 && await page.locator('input[id^="note-"]').count() === 1)
  await page.fill('input[id^="note-"]', 'console E2E approval note')
  await page.fill('input[id^="ttl-"]', '10m')
  await shot(page, '03-approve-modal.png')
  await page.getByRole('button', { name: /Approve & issue/ }).click()
  await page.waitForTimeout(1200)
  const leaseAfter = await api('GET', `/api/v1/admin/leases/${target}`, ADMIN)
  check('UI approve -> lease active', leaseAfter.json?.data?.status === 'active', `status=${leaseAfter.json?.data?.status}`)
  check('UI approve -> approved_by admin', leaseAfter.json?.data?.approved_by === 'admin', `approved_by=${leaseAfter.json?.data?.approved_by}`)
  check('UI approve -> credential available', leaseAfter.json?.data?.credential_available === true, `available=${leaseAfter.json?.data?.credential_available}`)
  const cred = await api('POST', `/api/v1/agent/leases/${target}/credential`, AGENT)
  check('credential fetch after UI approval', cred.status === 200 && Array.isArray(cred.json?.data?.env) && cred.json.data.env.length === 6, `status=${cred.status}`)
  await page.waitForTimeout(500)
  await shot(page, '04-after-approval-overview.png')

  // ---------- leases page ----------
  await page.locator('a.nav__item', { hasText: 'Leases' }).first().click()
  await page.waitForTimeout(700)
  check('leases page renders', (await page.locator('body').innerText()).includes('Lease history') || (await page.locator('table').count()) > 0)
  await shot(page, '05-leases.png')

  // ---------- agents page + create agent + one-time token modal ----------
  await page.locator('a.nav__item', { hasText: 'Agents' }).first().click()
  await page.waitForTimeout(700)
  await shot(page, '06-agents.png')
  await page.getByRole('button', { name: /Create agent/ }).first().click()
  await page.waitForSelector('#agent-name', { timeout: 5000 })
  await page.fill('#agent-name', 'verifier-ui-agent')
  await page.getByRole('button', { name: 'Create agent', exact: true }).last().click()
  await page.waitForTimeout(1200)
  const tokenModal = page.locator('pre[aria-label="Agent bearer token"]')
  check('one-time token modal shown', await tokenModal.count() === 1)
  const shownToken = await tokenModal.innerText()
  check('one-time token is agent-shaped', /^csg_agt_/.test(shownToken.trim()))
  await shot(page, '07-agent-token-once.png')
  // Invalidate the token that appears in the screenshot before continuing.
  const agents = await api('GET', '/api/v1/admin/agents', ADMIN)
  const uiAgent = (agents.json?.data?.items || []).find((a) => a.name === 'verifier-ui-agent')
  check('agent created via UI', Boolean(uiAgent))
  if (uiAgent) {
    const rot = await api('POST', `/api/v1/admin/agents/${uiAgent.id}/token/rotate`, ADMIN)
    check('token from screenshot invalidated via rotate', rot.status === 200)
  }
  await page.locator('label.checkbox input[type="checkbox"]').last().check()
  await page.getByRole('button', { name: /I have stored the token/ }).click()
  await page.waitForTimeout(400)

  // ---------- capabilities ----------
  await page.locator('a.nav__item', { hasText: 'Capabilities' }).first().click()
  await page.waitForTimeout(700)
  check('capabilities page renders', (await page.locator('body').innerText()).includes('aliyun.cloud.read'))
  await shot(page, '08-capabilities.png')

  // ---------- providers & vault ----------
  await page.locator('a.nav__item', { hasText: 'Providers' }).first().click()
  await page.waitForTimeout(700)
  const provBody = await page.locator('body').innerText()
  check('providers page renders masked AK', provBody.includes('****') || provBody.includes('LTAI'))
  await shot(page, '09-providers-vault.png')

  // ---------- audit + verify chain ----------
  await page.locator('a.nav__item', { hasText: 'Audit log' }).first().click()
  await page.waitForTimeout(900)
  await page.getByRole('button', { name: /Verify chain/ }).click()
  await page.waitForSelector('.verify-panel', { timeout: 8000 })
  const verifyText = await page.locator('.verify-panel').innerText()
  check('audit chain verifies in UI', /intact|verified/i.test(verifyText) && !/failed/i.test(verifyText), verifyText.slice(0, 120))
  await shot(page, '10-audit-verify.png')

  // ---------- settings save ----------
  await page.locator('a.nav__item', { hasText: 'Settings' }).first().click()
  await page.waitForTimeout(700)
  await shot(page, '11-settings.png')
  const riskSelect = page.locator('select[aria-label="Auto-approve maximum risk"]')
  check('settings editor renders risk select', await riskSelect.count() === 1)
  await riskSelect.selectOption('medium')
  await page.getByRole('button', { name: /Save guardrails/ }).click()
  await page.waitForTimeout(1200)
  const pol = await api('GET', '/api/v1/admin/policy', ADMIN)
  check('settings save persists to API', pol.json?.data?.auto_approve_max_risk === 'medium', `risk=${pol.json?.data?.auto_approve_max_risk}`)
  await api('PUT', '/api/v1/admin/policy', ADMIN, { ...pol.json.data, auto_approve_max_risk: 'low' })

  // ---------- logout ----------
  await page.getByRole('button', { name: 'Log out' }).click()
  await page.waitForTimeout(500)
  check('logout returns to login screen', await page.locator('#admin-token').count() === 1)
  check('token cleared from localStorage', (await page.evaluate(() => localStorage.getItem('csg.adminToken'))) === null)

  // ---------- SPA deep link ----------
  await page.fill('#admin-token', ADMIN)
  await page.click('button[type="submit"]')
  await page.waitForTimeout(800)
  await page.goto(BASE + '/leases', { waitUntil: 'networkidle' })
  await page.waitForTimeout(800)
  const deepBody = (await page.locator('body').innerText()).toLowerCase()
  check('SPA deep link /leases loads app', (await page.locator('.nav').count()) === 1 && deepBody.includes('lease') && deepBody.includes('status'), JSON.stringify(deepBody.slice(0, 160)))
  check('deep link stays on /leases', page.url().endsWith('/leases'))

  // ---------- responsive 1024 ----------
  await page.setViewportSize({ width: 1024, height: 768 })
  await page.goto(BASE + '/overview', { waitUntil: 'networkidle' })
  await page.waitForTimeout(900)
  check('1024px responsive renders overview', (await page.locator('.grid-stats').count()) === 1)
  const hScroll = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 4)
  check('1024px no horizontal overflow', !hScroll)
  await shot(page, '12-responsive-1024.png')
  await page.setViewportSize({ width: 1440, height: 900 })

  // ---------- console error audit ----------
  check('no uncaught console/page errors on any page', consoleErrors.length === 0, consoleErrors.slice(0, 3).join(' | '))
} catch (e) {
  no('e2e-uncaught', e.message)
  try { await shot(page, '99-failure.png') } catch { /* ignore */ }
} finally {
  await browser.close()
  console.log(`\nconsole E2E summary: PASS=${pass} FAIL=${fail}`)
  if (failures.length) console.log('FAILED: ' + failures.join(', '))
  process.exit(fail === 0 ? 0 : 1)
}
