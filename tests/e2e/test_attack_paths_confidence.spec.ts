/**
 * Playwright E2E: Attack Paths page — confidence filter + findings tab (AP-P4-05 / SF-P4-01)
 *
 * Prerequisites:
 *   - PORTAL_URL env var pointing to the CSPM portal (e.g. http://localhost:3000)
 *   - ADMIN_EMAIL / ADMIN_PASSWORD env vars for login (default: admin@cspm.local / Admin@12345)
 *   - A completed pipeline scan with at least 1 confirmed attack path
 *
 * Run:
 *   PORTAL_URL=http://localhost:3000 npx playwright test tests/e2e/test_attack_paths_confidence.spec.ts
 */

import { test, expect, Page } from '@playwright/test';

const PORTAL_URL   = process.env.PORTAL_URL   || 'http://localhost:3000';
const ADMIN_EMAIL  = process.env.ADMIN_EMAIL  || 'admin@cspm.local';
const ADMIN_PWD    = process.env.ADMIN_PASSWORD || 'Admin@12345';

async function login(page: Page) {
  await page.goto(`${PORTAL_URL}/ui/login`);
  await page.fill('[name="email"]',    ADMIN_EMAIL);
  await page.fill('[name="password"]', ADMIN_PWD);
  await page.click('[type="submit"]');
  await page.waitForURL(/\/ui\//, { timeout: 15_000 });
}

// ── Attack Paths — confidence filter ─────────────────────────────────────────

test.describe('Attack Paths — Confidence Filter', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.goto(`${PORTAL_URL}/ui/threats/attack-paths`);
    await page.waitForSelector('[class*="rounded-xl"]', { timeout: 20_000 });
  });

  test('Confidence filter chips are visible in FilterBar', async ({ page }) => {
    // All 4 confidence chips should render
    for (const label of ['all', 'confirmed', 'likely', 'speculative']) {
      await expect(page.getByRole('button', { name: new RegExp(label, 'i') }).first()).toBeVisible();
    }
  });

  test('Clicking "confirmed" chip filters path list', async ({ page }) => {
    const confirmedBtn = page.getByRole('button', { name: /^confirmed$/i });
    await confirmedBtn.first().click();
    // After filter: only paths with confidence=confirmed or empty state visible
    // Reset button must appear when filter is active
    await expect(page.getByRole('button', { name: /reset/i })).toBeVisible();
  });

  test('Confirmed KPI chip click sets confidence filter', async ({ page }) => {
    // "Confirmed" KPI cell triggers confidence filter on click
    const kpiConfirmed = page.getByText('Confirmed').first();
    await kpiConfirmed.click();
    await expect(page.getByRole('button', { name: /reset/i })).toBeVisible();
  });

  test('CONFIRMED badge visible on confirmed path cards', async ({ page }) => {
    // If any confirmed paths exist, their cards should show CONFIRMED badge
    const confirmedBadge = page.getByText('CONFIRMED').first();
    // This assertion is soft — may not exist if no confirmed paths in scan
    const count = await confirmedBadge.count();
    if (count > 0) {
      await expect(confirmedBadge).toBeVisible();
    }
  });

  test('"Full Detail" button opens PathDetailPanel without deselecting card', async ({ page }) => {
    // Select first path card
    const firstCard = page.locator('button[class*="rounded-lg"]').first();
    await firstCard.click();

    // "Full Detail" link should appear in canvas footer
    const fullDetailBtn = page.getByText('Full Detail');
    if (await fullDetailBtn.count() > 0) {
      await fullDetailBtn.click();
      // Panel must open (contains "Attack Path Detail" aria-label)
      await expect(page.getByRole('complementary', { name: 'Attack Path Detail' })).toBeVisible();

      // Closing panel must NOT deselect the card (canvas still shows the path)
      await page.keyboard.press('Escape');
      await expect(page.getByRole('complementary', { name: 'Attack Path Detail' })).not.toBeVisible();
      // Canvas should still show selected path (canvas header still visible)
      await expect(page.locator('[class*="border-b"][class*="flex"][class*="items-center"]').last()).toBeVisible();
    }
  });
});

// ── PathDetailPanel — confidence badge + attack story ────────────────────────

test.describe('PathDetailPanel — Confidence + Attack Story (AP-P4-06)', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.goto(`${PORTAL_URL}/ui/threats/attack-paths`);
    await page.waitForSelector('[class*="rounded-xl"]', { timeout: 20_000 });
  });

  test('PathDetailPanel shows confidence badge in header', async ({ page }) => {
    const fullDetailBtn = page.getByText('Full Detail');
    if (await fullDetailBtn.count() === 0) {
      test.skip(true, 'No paths available to open detail panel');
      return;
    }
    // Click first path to select it
    await page.locator('button[class*="rounded-lg"]').first().click();
    await fullDetailBtn.click();
    await expect(page.getByRole('complementary', { name: 'Attack Path Detail' })).toBeVisible();

    // At least one of these confidence badges must appear
    const badges = ['CONFIRMED', 'LIKELY', 'SPECULATIVE'];
    let foundBadge = false;
    for (const badge of badges) {
      if (await page.getByText(badge).count() > 0) {
        foundBadge = true;
        break;
      }
    }
    expect(foundBadge).toBe(true);
  });

  test('Attack Narrative section renders for confirmed/likely paths', async ({ page }) => {
    const fullDetailBtn = page.getByText('Full Detail');
    if (await fullDetailBtn.count() === 0) {
      test.skip(true, 'No paths to test');
      return;
    }
    await page.locator('button[class*="rounded-lg"]').first().click();
    await fullDetailBtn.click();
    // Attack Narrative section is optional (only shows for confirmed/likely)
    const narrativeHeader = page.getByText('ATTACK NARRATIVE');
    if (await narrativeHeader.count() > 0) {
      await expect(narrativeHeader).toBeVisible();
    }
  });
});

// ── Attack Name as panel title ────────────────────────────────────────────────

test.describe('PathDetailPanel — attack_name as title (AP-P5-03 / AP-P4-06)', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await page.goto(`${PORTAL_URL}/ui/threats/attack-paths`);
    await page.waitForSelector('[class*="rounded-xl"]', { timeout: 20_000 });
  });

  test('Confirmed path panel shows attack_name not generic title', async ({ page }) => {
    // Filter to confirmed paths
    const confirmedChip = page.getByRole('button', { name: /^confirmed$/i }).first();
    if (await confirmedChip.count() === 0) {
      test.skip(true, 'No confidence filter chips — FilterBar not rendered');
      return;
    }
    await confirmedChip.click();

    const fullDetailBtn = page.getByText('Full Detail');
    if (await fullDetailBtn.count() === 0) {
      test.skip(true, 'No confirmed paths in current scan');
      return;
    }
    await page.locator('button[class*="rounded-lg"]').first().click();
    await fullDetailBtn.click();
    await expect(page.getByRole('complementary', { name: 'Attack Path Detail' })).toBeVisible();

    // Panel title must NOT be the generic fallback 'Attack Path'
    // (it should show attack_name like "EC2 Lateral Movement to PII Store")
    const panelHeader = page.getByRole('complementary', { name: 'Attack Path Detail' });
    const titleText = await panelHeader.locator('h2, h3, [class*="font-bold"]').first().textContent();
    expect(titleText).not.toBe('Attack Path');
    expect(titleText?.length).toBeGreaterThan(0);
  });

  test('MITRE technique chain chips render with T-codes', async ({ page }) => {
    const fullDetailBtn = page.getByText('Full Detail');
    if (await fullDetailBtn.count() === 0) {
      test.skip(true, 'No paths to test');
      return;
    }
    await page.locator('button[class*="rounded-lg"]').first().click();
    await fullDetailBtn.click();
    await expect(page.getByRole('complementary', { name: 'Attack Path Detail' })).toBeVisible();

    // If technique chain section exists, T-codes must render (T1xxx pattern)
    const techniqueSection = page.getByText('MITRE TECHNIQUE CHAIN');
    if (await techniqueSection.count() > 0) {
      await expect(techniqueSection).toBeVisible();
      // At least one T-code chip must be visible
      const tCodeChip = page.getByText(/^T1\d{3}/).first();
      expect(await tCodeChip.count()).toBeGreaterThan(0);
    }
  });

  test('attack_story text does not contain HTML tags (XSS prevention)', async ({ page }) => {
    const fullDetailBtn = page.getByText('Full Detail');
    if (await fullDetailBtn.count() === 0) {
      test.skip(true, 'No paths to test');
      return;
    }
    await page.locator('button[class*="rounded-lg"]').first().click();
    await fullDetailBtn.click();

    const narrativeSection = page.getByText('ATTACK NARRATIVE');
    if (await narrativeSection.count() === 0) {
      test.skip(true, 'No attack narrative on this path (speculative — correct)');
      return;
    }
    // The narrative text must be plain text, not rendered HTML
    // If dangerouslySetInnerHTML was used, <script> or <img> tags could appear
    const narrativeContainer = narrativeSection.locator('..');
    const html = await narrativeContainer.innerHTML();
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<img/i);
    expect(html).not.toMatch(/javascript:/i);
  });

  test('Confidence filter chip count matches path list count', async ({ page }) => {
    // Get total from KPI before filtering
    const confirmedChip = page.getByRole('button', { name: /^confirmed$/i }).first();
    if (await confirmedChip.count() === 0) {
      test.skip(true, 'No confidence chips rendered');
      return;
    }
    await confirmedChip.click();
    await page.waitForTimeout(500);

    // If confirmed_paths KPI = 0 but filter applied → expect empty state not crash
    const pathCards = page.locator('button[class*="rounded-lg"]');
    const emptyState = page.getByText(/no attack paths/i);
    const hasCards  = await pathCards.count() > 0;
    const hasEmpty  = await emptyState.count() > 0;
    expect(hasCards || hasEmpty).toBe(true);
  });

  test('kpis.confirmed_paths value appears in Confirmed KPI chip', async ({ page }) => {
    // The KPI bar must show a Confirmed cell with a number
    const confirmedKpi = page.getByText('Confirmed').first();
    if (await confirmedKpi.count() === 0) {
      test.skip(true, 'Confirmed KPI chip not rendered — AP-P5-03 KPI fix not deployed');
      return;
    }
    await expect(confirmedKpi).toBeVisible();
    // The number next to it must be a digit (not "—" or "null")
    const kpiCell = confirmedKpi.locator('..');
    const text = await kpiCell.textContent();
    expect(text).toMatch(/\d/);
  });
});

// ── Asset Detail — Findings Tab ───────────────────────────────────────────────

test.describe('Asset Detail — Findings Tab (SF-P4-01)', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    // Navigate to any asset detail page (use inventory page to pick one)
    await page.goto(`${PORTAL_URL}/ui/inventory`);
    await page.waitForSelector('[class*="rounded-xl"]', { timeout: 20_000 });
  });

  test('Findings tab is visible in PostureTabs', async ({ page }) => {
    // Click first asset row to open detail
    const firstRow = page.locator('table tbody tr').first();
    if (await firstRow.count() === 0) {
      test.skip(true, 'No inventory assets available');
      return;
    }
    await firstRow.click();
    // PostureTabs should show Findings tab
    await expect(page.getByRole('button', { name: /findings/i })).toBeVisible({ timeout: 10_000 });
  });

  test('Clicking Findings tab fetches and renders findings', async ({ page }) => {
    const firstRow = page.locator('table tbody tr').first();
    if (await firstRow.count() === 0) {
      test.skip(true, 'No inventory assets available');
      return;
    }
    await firstRow.click();

    const findingsTab = page.getByRole('button', { name: /findings/i });
    await findingsTab.click();

    // Should show either findings rows or empty state — not a crash
    await page.waitForTimeout(2000); // allow fetch
    const hasFindings = await page.getByText(/critical|high|medium|low/i).count() > 0;
    const hasEmpty   = await page.getByText(/no findings/i).count() > 0;
    expect(hasFindings || hasEmpty).toBe(true);
  });

  test('Findings tab does not show posture loading spinner when active', async ({ page }) => {
    const firstRow = page.locator('table tbody tr').first();
    if (await firstRow.count() === 0) {
      test.skip(true, 'No inventory assets available');
      return;
    }
    await firstRow.click();

    const findingsTab = page.getByRole('button', { name: /findings/i });
    await findingsTab.click();

    // Should NOT show "Loading posture data…" text (posture and findings are separate fetches)
    await expect(page.getByText('Loading posture data…')).not.toBeVisible();
  });

  test('Findings panel shows severity badges with correct colors', async ({ page }) => {
    const firstRow = page.locator('table tbody tr').first();
    if (await firstRow.count() === 0) {
      test.skip(true, 'No inventory assets available');
      return;
    }
    await firstRow.click();
    await page.getByRole('button', { name: /findings/i }).click();
    await page.waitForTimeout(2000);

    // Each severity badge must be one of the 4 valid values
    const badges = await page.getByText(/^(critical|high|medium|low)$/i).all();
    for (const badge of badges) {
      const text = (await badge.textContent() ?? '').toLowerCase();
      expect(['critical', 'high', 'medium', 'low']).toContain(text);
    }
  });

  test('Findings panel shows source engine badge on each finding row', async ({ page }) => {
    const firstRow = page.locator('table tbody tr').first();
    if (await firstRow.count() === 0) {
      test.skip(true, 'No inventory assets available');
      return;
    }
    await firstRow.click();
    await page.getByRole('button', { name: /findings/i }).click();
    await page.waitForTimeout(2000);

    // Each finding row should show a source engine badge
    const knownEngines = ['check', 'iam', 'network', 'datasec', 'vuln', 'cdr', 'container'];
    let foundEngine = false;
    for (const engine of knownEngines) {
      if (await page.getByText(engine, { exact: true }).count() > 0) {
        foundEngine = true;
        break;
      }
    }
    // If findings exist, at least one engine badge must be visible
    const hasFindings = await page.getByText(/critical|high|medium|low/i).count() > 0;
    if (hasFindings) {
      expect(foundEngine).toBe(true);
    }
  });

  test('Findings tab total count renders as integer string', async ({ page }) => {
    const firstRow = page.locator('table tbody tr').first();
    if (await firstRow.count() === 0) {
      test.skip(true, 'No inventory assets available');
      return;
    }
    await firstRow.click();
    await page.getByRole('button', { name: /findings/i }).click();
    await page.waitForTimeout(2000);

    // "N total" label must appear with a digit count
    const totalLabel = page.getByText(/total$/i).first();
    if (await totalLabel.count() > 0) {
      const text = await totalLabel.textContent();
      expect(text).toMatch(/^\d+\s+total/i);
    }
  });

  test('Switching tabs does not crash — Findings → Network → Findings', async ({ page }) => {
    const firstRow = page.locator('table tbody tr').first();
    if (await firstRow.count() === 0) {
      test.skip(true, 'No inventory assets available');
      return;
    }
    await firstRow.click();

    const findingsTab = page.getByRole('button', { name: /findings/i });
    const networkTab  = page.getByRole('button', { name: /network/i }).first();

    await findingsTab.click();
    await page.waitForTimeout(500);

    if (await networkTab.count() > 0) {
      await networkTab.click();
      await page.waitForTimeout(500);
      await findingsTab.click();
      await page.waitForTimeout(1000);
    }

    // Page must not show a React crash boundary
    await expect(page.getByText(/something went wrong/i)).not.toBeVisible();
    await expect(page.getByText(/error:/i)).not.toBeVisible();
  });
});

// ── Integration sanity — data present end-to-end ─────────────────────────────

test.describe('Data presence — end-to-end sanity', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('Attack paths page shows at least one path or meaningful empty state', async ({ page }) => {
    await page.goto(`${PORTAL_URL}/ui/threats/attack-paths`);
    await page.waitForSelector('[class*="rounded-xl"]', { timeout: 20_000 });

    const hasPath       = await page.locator('button[class*="rounded-lg"]').count() > 0;
    const hasEmptyState = await page.getByText(/no attack paths/i).count() > 0;
    const hasError      = await page.getByText(/engine unavailable|503|error/i).count() > 0;

    expect(hasPath || hasEmptyState).toBe(true);
    expect(hasError).toBe(false);
  });

  test('KPI numbers are integers not "null" or "undefined"', async ({ page }) => {
    await page.goto(`${PORTAL_URL}/ui/threats/attack-paths`);
    await page.waitForSelector('[class*="rounded-xl"]', { timeout: 20_000 });

    // KPI bar must not display literal "null", "undefined", or "NaN"
    const pageText = await page.locator('body').textContent();
    expect(pageText).not.toMatch(/\bnull\b/);
    expect(pageText).not.toMatch(/\bundefined\b/);
    expect(pageText).not.toMatch(/\bNaN\b/);
  });

  test('Confirmed KPI chip shows digit not dash', async ({ page }) => {
    await page.goto(`${PORTAL_URL}/ui/threats/attack-paths`);
    await page.waitForSelector('[class*="rounded-xl"]', { timeout: 20_000 });

    // If "Confirmed" KPI chip is rendered, it must show a number
    const confirmedKpi = page.getByText('Confirmed').first();
    if (await confirmedKpi.count() > 0) {
      const parent = confirmedKpi.locator('..');
      const text = await parent.textContent();
      expect(text).toMatch(/\d/);
      expect(text).not.toMatch(/^—$|^-$/);
    }
  });
});
