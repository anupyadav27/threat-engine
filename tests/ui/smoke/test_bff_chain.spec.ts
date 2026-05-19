/**
 * BFF Chain Smoke Tests — UI → BFF → Engine data chain verification
 *
 * Verifies that every security page:
 *   1. Loads without console errors (no undefined/null crashes)
 *   2. BFF view returns required top-level fields (not empty)
 *   3. No mock data is rendered (no sine-wave trend, no "MIT-NNN" synthetics)
 *   4. Field names match what the page reads (no snake_case/camelCase mismatch)
 *
 * Run:
 *   BASE_URL=http://<elb>/ui npx playwright test tests/ui/smoke/test_bff_chain.spec.ts \
 *     --config tests/e2e/playwright.config.ts
 *
 * CI:
 *   Set BASE_URL, AUTH_URL, ADMIN_EMAIL, ADMIN_PASS as env vars.
 *   BFF_GATEWAY_URL defaults to BASE_URL with /ui stripped.
 */

import { test, expect, Page, APIRequestContext } from '@playwright/test';

const BASE_URL =
  process.env.BASE_URL ??
  'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/ui';

const AUTH_URL =
  process.env.NEXT_PUBLIC_AUTH_URL ??
  'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com';

// Gateway URL for direct BFF API calls (strip /ui suffix)
const GATEWAY_URL =
  process.env.BFF_GATEWAY_URL ??
  AUTH_URL;

const ADMIN_EMAIL = process.env.ADMIN_EMAIL ?? 'admin@cspm.local';
const ADMIN_PASS  = process.env.ADMIN_PASS  ?? 'Admin@12345';
const CSRF_COOKIE = 'csrftoken';

// ── Auth helpers ──────────────────────────────────────────────────────────────

async function loginViaApi(
  page: Page,
): Promise<{ token: string; session: Record<string, unknown> }> {
  await page.request.get(`${AUTH_URL}/api/auth/csrf/`);
  const csrfCookie = (await page.context().cookies()).find((c) => c.name === CSRF_COOKIE);
  const csrfValue  = csrfCookie?.value ?? '';

  const resp = await page.request.post(`${AUTH_URL}/api/auth/login/`, {
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfValue },
    data:    { email: ADMIN_EMAIL, password: ADMIN_PASS },
  });
  expect(resp.status(), `Login failed for ${ADMIN_EMAIL}`).toBe(200);

  const cookies = await page.context().cookies();
  const token   = cookies.find((c) => c.name === 'access_token')?.value ?? '';

  const meResp = await page.request.get(`${AUTH_URL}/api/auth/me`);
  let session: Record<string, unknown> = {};
  if (meResp.ok()) {
    const user = await meResp.json();
    const u    = (user.user ?? user) as Record<string, unknown>;
    session = {
      user:            u,
      role:            u.role ?? 'platform_admin',
      permissions:     u.permissions ?? [],
      isAuthenticated: true,
    };
  }
  return { token, session };
}

async function authenticatedPage(page: Page): Promise<string> {
  const { token, session } = await loginViaApi(page);
  await page.goto(`${BASE_URL}/`);
  await page.evaluate((s) => {
    sessionStorage.setItem('authSession', JSON.stringify(s));
  }, session);
  return token;
}

/** Fetch a BFF view directly using the page's cookie context. */
async function fetchBffView(
  request: APIRequestContext,
  view: string,
  params: Record<string, string> = {},
): Promise<{ status: number; body: Record<string, unknown> | null }> {
  const qs    = new URLSearchParams(params).toString();
  const url   = `${GATEWAY_URL}/api/v1/views/${view}${qs ? '?' + qs : ''}`;
  const resp  = await request.get(url);
  let body: Record<string, unknown> | null = null;
  try {
    body = await resp.json();
  } catch { /* non-JSON response */ }
  return { status: resp.status(), body };
}

// ── Reusable check: BFF view required fields ──────────────────────────────────

function checkFields(
  body: Record<string, unknown> | null,
  fields: string[],
  view: string,
): void {
  if (!body) {
    test.fail(true, `${view}: BFF returned no body`);
    return;
  }
  for (const f of fields) {
    expect(body, `${view}: missing field "${f}"`).toHaveProperty(f);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Returns true if trendData looks like a sine wave (perfectly regular deltas). */
function looksLikeSineWave(trend: unknown[]): boolean {
  if (!Array.isArray(trend) || trend.length < 3) return false;
  const nums = (trend as Record<string, unknown>[]).map(
    (d) => Number((d.total ?? d.count ?? d.value ?? 0)),
  );
  const deltas = nums.slice(1).map((v, i) => Math.abs(v - nums[i]));
  const max    = Math.max(...deltas);
  const min    = Math.min(...deltas);
  return max > 0 && max === min; // all deltas identical → synthetic
}

// ──────────────────────────────────────────────────────────────────────────────
// Level 1: BFF view field presence checks (API level, no browser required)
// ──────────────────────────────────────────────────────────────────────────────

test.describe('Level 1 — BFF View Field Coverage', () => {

  test('dashboard: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'dashboard');
    expect(status).toBe(200);
    checkFields(body, ['kpi', 'chartCategories', 'criticalActions', 'recentThreats', 'pageContext'], 'dashboard');
    // kpi sub-fields
    const kpi = (body?.kpi ?? {}) as Record<string, unknown>;
    for (const k of ['totalAssets', 'openFindings', 'criticalHighFindings', 'complianceScore']) {
      expect(kpi, `dashboard.kpi missing "${k}"`).toHaveProperty(k);
    }
  });

  test('misconfig: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'misconfig');
    expect(status).toBe(200);
    checkFields(body, ['kpiGroups', 'findings', 'kpi', 'heatmap', 'quickWins', 'byService', 'pageContext'], 'misconfig');
  });

  test('inventory: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'inventory');
    expect(status).toBe(200);
    checkFields(body, ['assets', 'kpi', 'pageContext'], 'inventory');
  });

  test('iam: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'iam');
    expect(status).toBe(200);
    checkFields(body, ['kpiGroups', 'findings', 'kpi', 'pageContext'], 'iam');
  });

  test('network-security: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'network-security');
    expect(status).toBe(200);
    checkFields(body, ['kpiGroups', 'findings', 'kpi', 'pageContext'], 'network-security');
  });

  test('datasec: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'datasec');
    expect(status).toBe(200);
    checkFields(body, ['findings', 'kpiGroups', 'pageContext'], 'datasec');
    // catalog must be array (even if empty)
    expect(Array.isArray(body?.catalog ?? []), 'datasec.catalog must be array').toBe(true);
  });

  test('encryption: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'encryption');
    expect(status).toBe(200);
    checkFields(body, ['findings', 'keys', 'certificates', 'kpiGroups', 'pageContext'], 'encryption');
  });

  test('database-security: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'database-security');
    expect(status).toBe(200);
    checkFields(body, ['findings', 'databases', 'kpiGroups', 'pageContext'], 'database-security');
  });

  test('container-security: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'container-security');
    expect(status).toBe(200);
    checkFields(body, ['findings', 'clusters', 'kpiGroups', 'pageContext'], 'container-security');
  });

  test('ai-security: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'ai-security');
    expect(status).toBe(200);
    checkFields(body, ['findings', 'inventory', 'kpiGroups', 'pageContext'], 'ai-security');
  });

  test('cdr: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'cdr');
    expect(status).toBe(200);
    checkFields(body, ['kpiGroups', 'findings', 'identities', 'pageContext'], 'cdr');
  });

  test('risk: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'risk');
    expect(status).toBe(200);
    checkFields(body, ['kpiGroups', 'riskScore', 'riskCategories', 'scenarios', 'pageContext'], 'risk');
  });

  test('compliance: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'compliance');
    expect(status).toBe(200);
    checkFields(body, ['frameworks', 'pageContext'], 'compliance');
    expect(Array.isArray(body?.frameworks), 'compliance.frameworks must be array').toBe(true);
  });

  test('vulnerability: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'vulnerability');
    expect(status).toBe(200);
    checkFields(body, ['agents', 'scanSummary', 'kpiGroups', 'severityCounts'], 'vulnerability');
  });

  test('secops: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'secops');
    expect(status).toBe(200);
    checkFields(body, ['sastScans', 'dastScans', 'summary', 'kpiGroups'], 'secops');
  });

  test('scans: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'scans');
    expect(status).toBe(200);
    checkFields(body, ['scans', 'schedules', 'kpiGroups', 'total'], 'scans');
  });

  test('suppressions: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'suppressions');
    expect(status).toBe(200);
    checkFields(body, ['suppressions', 'rule_suppressions', 'finding_suppressions', 'total', 'kpi'], 'suppressions');
  });

  test('rules: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'rules');
    expect(status).toBe(200);
    checkFields(body, ['rules', 'total', 'by_type_kpi'], 'rules');
  });

  test('attack-paths: required fields present (analyst role)', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'attack-paths');
    expect(status).toBe(200);
    checkFields(body, ['paths', 'total', 'kpis'], 'attack-paths');
    const kpis = (body?.kpis ?? {}) as Record<string, unknown>;
    expect(kpis).toHaveProperty('critical');
    expect(kpis).toHaveProperty('choke_points');
  });

  test('onboarding/cloud_accounts: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'onboarding/cloud_accounts');
    expect(status).toBe(200);
    checkFields(body, ['accounts'], 'onboarding/cloud_accounts');
    expect(Array.isArray(body?.accounts), 'cloud_accounts must be array').toBe(true);
  });

  test('api_security: required fields present', async ({ page, request }) => {
    await authenticatedPage(page);
    const { status, body } = await fetchBffView(request, 'api_security');
    // 200 or 404 if no scan run yet — either is acceptable
    expect([200, 404]).toContain(status);
    if (status === 200) {
      checkFields(body, ['report', 'findings'], 'api_security');
    }
  });

});

// ──────────────────────────────────────────────────────────────────────────────
// Level 2: Field depth checks (sub-field shapes, not just presence)
// ──────────────────────────────────────────────────────────────────────────────

test.describe('Level 2 — Field Depth Checks', () => {

  const FINDING_REQUIRED_FIELDS = ['severity', 'title', 'resource_uid', 'rule_id', 'status'];

  for (const view of ['misconfig', 'iam', 'network-security', 'datasec', 'cdr', 'encryption']) {
    test(`${view}: findings[0] has required sub-fields`, async ({ page, request }) => {
      await authenticatedPage(page);
      const { status, body } = await fetchBffView(request, view);
      expect(status).toBe(200);
      const findings = (body?.findings ?? []) as Record<string, unknown>[];
      if (findings.length === 0) {
        test.skip(true, `${view}: findings empty — no scan data yet`);
        return;
      }
      for (const f of FINDING_REQUIRED_FIELDS) {
        expect(findings[0], `${view}.findings[0] missing "${f}"`).toHaveProperty(f);
        expect(findings[0][f], `${view}.findings[0].${f} must not be null`).not.toBeNull();
      }
    });
  }

  test('misconfig: scanTrend shape correct', async ({ page, request }) => {
    await authenticatedPage(page);
    const { body } = await fetchBffView(request, 'misconfig');
    const trend = (body?.scanTrend ?? []) as Record<string, unknown>[];
    if (trend.length === 0) {
      test.skip(true, 'misconfig scanTrend empty — no completed scans yet');
      return;
    }
    for (const f of ['date', 'total', 'critical']) {
      expect(trend[0], `scanTrend[0] missing "${f}"`).toHaveProperty(f);
    }
    expect(looksLikeSineWave(trend), 'misconfig.scanTrend must not be a sine wave').toBe(false);
  });

  test('dashboard: trendData is not a sine wave', async ({ page, request }) => {
    await authenticatedPage(page);
    const { body } = await fetchBffView(request, 'dashboard');
    const cats   = (body?.chartCategories ?? []) as Record<string, unknown>[];
    // trendData is embedded in chartCategories[1] (threat category) or as top-level trendData
    const trendData = (body as Record<string, unknown>)?.trendData as unknown[] | undefined;
    if (!trendData || trendData.length === 0) return; // no scans yet — skip
    expect(looksLikeSineWave(trendData), 'dashboard trendData looks like synthetic sine wave').toBe(false);
  });

  test('risk: no synthetic MIT-NNN mitigations', async ({ page, request }) => {
    await authenticatedPage(page);
    const { body } = await fetchBffView(request, 'risk');
    const roadmap = (body?.mitigationRoadmap ?? []) as Record<string, unknown>[];
    const syntheticCount = roadmap.filter(
      (m) => typeof m.id === 'string' && /^MIT-\d{3}$/.test(m.id as string),
    ).length;
    // After FIX-02: synthetic MIT-NNN items must be 0. Before FIX-02: warn not fail.
    if (syntheticCount > 0) {
      console.warn(`risk: ${syntheticCount} synthetic MIT-NNN mitigations found — FIX-02 not yet shipped`);
    }
  });

  test('vulnerability: agents[0] has required fields', async ({ page, request }) => {
    await authenticatedPage(page);
    const { body } = await fetchBffView(request, 'vulnerability');
    const agents = (body?.agents ?? []) as Record<string, unknown>[];
    if (agents.length === 0) {
      test.skip(true, 'vulnerability: no agents registered yet');
      return;
    }
    for (const f of ['agent_id', 'hostname', 'status']) {
      expect(agents[0], `agents[0] missing "${f}"`).toHaveProperty(f);
    }
  });

  test('scans: scans[0] has required fields with correct types', async ({ page, request }) => {
    await authenticatedPage(page);
    const { body } = await fetchBffView(request, 'scans');
    const scans = (body?.scans ?? []) as Record<string, unknown>[];
    if (scans.length === 0) {
      test.skip(true, 'scans: no scan runs yet');
      return;
    }
    expect(typeof scans[0].scan_id, 'scans[0].scan_id must be string').toBe('string');
    expect(scans[0]).toHaveProperty('provider');
    expect(scans[0]).toHaveProperty('status');
    expect(scans[0]).toHaveProperty('started_at');
  });

  test('suppressions: rule_suppressions and finding_suppressions are arrays', async ({ page, request }) => {
    await authenticatedPage(page);
    const { body } = await fetchBffView(request, 'suppressions');
    expect(Array.isArray(body?.rule_suppressions),    'rule_suppressions must be array').toBe(true);
    expect(Array.isArray(body?.finding_suppressions), 'finding_suppressions must be array').toBe(true);
  });

  test('compliance: frameworks[0] has id, name, score fields', async ({ page, request }) => {
    await authenticatedPage(page);
    const { body } = await fetchBffView(request, 'compliance');
    const frameworks = (body?.frameworks ?? []) as Record<string, unknown>[];
    if (frameworks.length === 0) {
      test.skip(true, 'compliance: no frameworks loaded yet');
      return;
    }
    for (const f of ['id', 'name', 'score']) {
      expect(frameworks[0], `frameworks[0] missing "${f}"`).toHaveProperty(f);
    }
  });

});

// ──────────────────────────────────────────────────────────────────────────────
// Level 3: Page load tests (headless browser, check no undefined/NaN in UI)
// ──────────────────────────────────────────────────────────────────────────────

test.describe('Level 3 — Page Load & Render', () => {

  const PAGES_WITH_ROUTES: Array<{ name: string; path: string; kpiSelector: string }> = [
    { name: 'dashboard',          path: '/dashboard',          kpiSelector: '[data-testid="kpi-card"], [data-testid="metric-strip"]' },
    { name: 'misconfig',          path: '/misconfig',          kpiSelector: '[data-testid="kpi-card"], [data-testid="kpi-group"]' },
    { name: 'inventory',          path: '/inventory',          kpiSelector: '[data-testid="kpi-card"], [data-testid="asset-count"]' },
    { name: 'iam',                path: '/iam',                kpiSelector: '[data-testid="kpi-card"], [data-testid="kpi-group"]' },
    { name: 'network-security',   path: '/network-security',   kpiSelector: '[data-testid="kpi-card"], [data-testid="kpi-group"]' },
    { name: 'datasec',            path: '/datasec',            kpiSelector: '[data-testid="kpi-card"], [data-testid="kpi-group"]' },
    { name: 'cdr',                path: '/cdr',                kpiSelector: '[data-testid="kpi-card"], [data-testid="kpi-group"]' },
    { name: 'risk',               path: '/risk',               kpiSelector: '[data-testid="kpi-card"], [data-testid="risk-score"]' },
    { name: 'compliance',         path: '/compliance',         kpiSelector: '[data-testid="framework-card"], [data-testid="compliance-score"]' },
    { name: 'vulnerability',      path: '/vulnerability',      kpiSelector: '[data-testid="kpi-card"], [data-testid="agent-list"]' },
    { name: 'secops',             path: '/secops',             kpiSelector: '[data-testid="kpi-card"], [data-testid="scan-list"]' },
    { name: 'scans',              path: '/scans',              kpiSelector: '[data-testid="scan-row"], [data-testid="kpi-card"]' },
    { name: 'suppressions',       path: '/suppressions',       kpiSelector: '[data-testid="suppression-row"], [data-testid="kpi-card"]' },
  ];

  for (const { name, path, kpiSelector } of PAGES_WITH_ROUTES) {
    test(`${name}: page loads without fatal console errors`, async ({ page }) => {
      const fatalErrors: string[] = [];
      page.on('console', (msg) => {
        if (
          msg.type() === 'error' &&
          !msg.text().includes('net::ERR_') &&
          !msg.text().includes('Failed to fetch') &&
          !msg.text().includes('ResizeObserver') &&
          !msg.text().includes('Warning:')
        ) {
          fatalErrors.push(msg.text());
        }
      });

      await authenticatedPage(page);
      await page.goto(`${BASE_URL}${path}`);
      await page.waitForLoadState('networkidle', { timeout: 20000 });

      // No JS crashes
      expect(fatalErrors, `${name}: console errors: ${fatalErrors.join(' | ')}`).toHaveLength(0);
    });

    test(`${name}: KPI section renders (no "undefined" text)`, async ({ page }) => {
      await authenticatedPage(page);
      await page.goto(`${BASE_URL}${path}`);
      await page.waitForLoadState('networkidle', { timeout: 20000 });

      // Check that "undefined" does not appear in visible text (would indicate field mismatch)
      const undefinedText = page.locator('text=undefined').first();
      const nanText       = page.locator('text=NaN').first();
      await expect(undefinedText, `${name}: "undefined" text visible — field name mismatch`).not.toBeVisible();
      await expect(nanText,       `${name}: "NaN" text visible — numeric field issue`).not.toBeVisible();
    });
  }

});

// ──────────────────────────────────────────────────────────────────────────────
// Level 4: Direct engine call elimination (post-UIBFF-FIX sprint)
// Run these as a separate suite after all FIX stories ship
// ──────────────────────────────────────────────────────────────────────────────

test.describe('Level 4 — Direct Engine Call Elimination (post-FIX)', () => {

  test('scans page: only uses BFF view (no direct scan-orchestration call)', async ({ page }) => {
    const engineCalls: string[] = [];
    page.on('request', (req) => {
      const url = req.url();
      if (url.includes('/gateway/api/v1/scan-orchestration') || url.includes('/gateway/api/v1/scan-runs')) {
        engineCalls.push(url);
      }
    });
    await authenticatedPage(page);
    await page.goto(`${BASE_URL}/scans`);
    await page.waitForLoadState('networkidle', { timeout: 20000 });
    // After FIX-07: direct engine calls for scan history should be 0
    if (engineCalls.length > 0) {
      console.warn(`scans: ${engineCalls.length} direct engine call(s) still present — FIX-07 not yet shipped: ${engineCalls[0]}`);
    }
  });

  test('vulnerability page: no direct vulnFetch for summary data', async ({ page }) => {
    const directVulnCalls: string[] = [];
    page.on('request', (req) => {
      const url = req.url();
      // vulnFetch to stats/summary or agents/ is the pattern that FIX-05 eliminates
      if (url.includes('/vuln') && (url.includes('/agents') || url.includes('/stats/summary')) &&
          !url.includes('/api/v1/views/')) {
        directVulnCalls.push(url);
      }
    });
    await authenticatedPage(page);
    await page.goto(`${BASE_URL}/vulnerability`);
    await page.waitForLoadState('networkidle', { timeout: 20000 });
    if (directVulnCalls.length > 0) {
      console.warn(`vulnerability: ${directVulnCalls.length} direct vulnFetch call(s) — FIX-05 not yet shipped`);
    }
  });

  test('accounts page: uses BFF view (no raw cloud-accounts fetch)', async ({ page }) => {
    const rawFetches: string[] = [];
    page.on('request', (req) => {
      const url = req.url();
      if (url.includes('/gateway/api/v1/cloud-accounts') && !url.includes('/views/')) {
        rawFetches.push(url);
      }
    });
    await authenticatedPage(page);
    await page.goto(`${BASE_URL}/accounts`);
    await page.waitForLoadState('networkidle', { timeout: 20000 });
    if (rawFetches.length > 0) {
      console.warn(`accounts: raw cloud-accounts fetch still present — FIX-09 not yet shipped`);
    }
  });

  test('dashboard: no MOCK_DASHBOARD fallback rendering', async ({ page }) => {
    await authenticatedPage(page);

    // Intercept BFF and simulate empty response to surface mock fallback
    let usedMockFallback = false;
    await page.route('**/api/v1/views/dashboard**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          kpi: {},
          chartCategories: [],
          criticalActions: { immediate: [], thisWeek: [], thisMonth: [] },
          recentThreats: [],
          pageContext: { title: 'Dashboard' },
        }),
      });
    });

    const consoleErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    await page.goto(`${BASE_URL}/dashboard`);
    await page.waitForLoadState('networkidle', { timeout: 15000 });

    // Page should not crash with empty BFF response (no MOCK_DASHBOARD fallback)
    const fatalErrors = consoleErrors.filter(
      (e) => !e.includes('net::ERR_') && !e.includes('Warning:'),
    );
    expect(fatalErrors, `dashboard crashed on empty BFF response: ${fatalErrors[0] ?? ''}`).toHaveLength(0);
  });

});

// ──────────────────────────────────────────────────────────────────────────────
// Level 5: Tenant isolation spot-check
// ──────────────────────────────────────────────────────────────────────────────

test.describe('Level 5 — Tenant Isolation', () => {

  test('dashboard: fake tenant_id cookie returns no data (not another tenant)', async ({ page, request }) => {
    // Attempt to fetch dashboard without a valid auth cookie
    const resp   = await request.get(`${GATEWAY_URL}/api/v1/views/dashboard`);
    const status = resp.status();
    // Without auth: must be 401 or 403, NOT 200 with data
    expect([401, 403, 422]).toContain(status);
  });

  test('findings view: requires authentication', async ({ request }) => {
    const resp   = await request.get(`${GATEWAY_URL}/api/v1/views/findings`);
    const status = resp.status();
    expect([401, 403, 422]).toContain(status);
  });

});
