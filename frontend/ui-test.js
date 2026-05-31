// Playwright headless UI test for all CSPM pages
const { chromium } = require('playwright');

const BASE = 'http://localhost:3000';

const PAGES = [
  { name: 'dashboard',            path: '/dashboard' },
  { name: 'inventory',            path: '/inventory' },
  { name: 'threats-v1',           path: '/threats-v1' },
  { name: 'threats',              path: '/threats' },
  { name: 'misconfig',            path: '/misconfig' },
  { name: 'compliance',           path: '/compliance' },
  { name: 'iam',                  path: '/iam' },
  { name: 'network-security',     path: '/network-security' },
  { name: 'datasec',              path: '/datasec' },
  { name: 'encryption',           path: '/encryption' },
  { name: 'database-security',    path: '/database-security' },
  { name: 'container-security',   path: '/container-security' },
  { name: 'ai-security',          path: '/ai-security' },
  { name: 'cdr',                  path: '/cdr' },
  { name: 'cwpp',                 path: '/cwpp' },
  { name: 'cnapp',                path: '/cnapp' },
  { name: 'risk',                 path: '/risk' },
  { name: 'vulnerability',        path: '/vulnerability' },
  { name: 'secops',               path: '/secops' },
  { name: 'rules',                path: '/rules',           timeout: 120000 },
  { name: 'suppressions',         path: '/suppressions' },
  { name: 'policies',             path: '/policies' },
  { name: 'scans',                path: '/scans' },
  { name: 'reports',              path: '/reports' },
  { name: 'billing',              path: '/billing' },
  { name: 'platform-admin',       path: '/admin/dashboard' },
  { name: 'attack-paths',         path: '/threats/attack-paths' },
  { name: 'api-security',         path: '/api-security' },
  { name: 'onboarding',           path: '/onboarding' },
];

function isRealError(text) {
  if (!text) return false;
  if (text.includes('React does not recognize')) return false;
  if (text.includes('Warning: ')) return false;
  if (text.includes('Each child in a list should have a unique')) return false;
  if (text.includes('whitespace text nodes')) return false;
  if (text.includes('Download the React DevTools')) return false;
  if (text.includes('NaN')) return false;  // SVG rendering NaN — visual only
  return true;
}

async function testPage(page, { name, path, timeout = 50000 }) {
  const errors = [];
  const failedRequests = [];
  const apiCalls = [];

  page.on('console', msg => {
    if (msg.type() === 'error') {
      const text = msg.text();
      if (isRealError(text)) errors.push(text);
    }
  });

  page.on('pageerror', err => errors.push(`PAGE ERROR: ${err.message}`));

  page.on('response', resp => {
    const url = resp.url();
    const status = resp.status();
    if (url.includes('/api/') || url.includes('/gateway/') || url.includes('/views/') || url.includes('/onboarding/')) {
      const shortUrl = url.replace(BASE, '').split('?')[0];
      apiCalls.push({ url: shortUrl, status });
      if (status >= 400) {
        if (!shortUrl.includes('/api/auth/me') && !shortUrl.includes('trial-status')) {
          failedRequests.push({ url: shortUrl, status });
        }
      }
    }
  });

  const start = Date.now();
  try {
    await page.goto(`${BASE}${path}`, { waitUntil: 'networkidle', timeout });
  } catch (e) {
    if (!e.message.includes('net::ERR_ABORTED') && !e.message.includes('ERR_CONNECTION')) {
      errors.push(`NAV: ${e.message.substring(0, 80)}`);
    }
  }
  const elapsed = Date.now() - start;

  return { name, path, elapsed, errors: errors.slice(0, 5), failedRequests, apiCalls, ok: errors.length === 0 && failedRequests.length === 0 };
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, bypassCSP: true });
  const results = [];

  for (const pageConfig of PAGES) {
    process.stdout.write(`Testing ${pageConfig.name}...`);
    const page = await context.newPage();
    try {
      const result = await testPage(page, pageConfig);
      results.push(result);
      const sym = result.ok ? '✓' : '✗';
      const failInfo = result.failedRequests.length > 0 ? ` [${result.failedRequests.map(r => r.status+':'+r.url).join(', ')}]` : '';
      const errInfo = result.errors.length > 0 ? ` ERR: ${result.errors[0].substring(0, 80)}` : '';
      console.log(` ${sym} (${result.elapsed}ms)${failInfo}${errInfo}`);
    } catch (e) {
      results.push({ name: pageConfig.name, ok: false, errors: [e.message], failedRequests: [], apiCalls: [] });
      console.log(` ERROR: ${e.message.substring(0, 80)}`);
    } finally {
      await page.close();
    }
  }

  await browser.close();
  const passing = results.filter(r => r.ok);
  const failing = results.filter(r => !r.ok);
  console.log(`\n===== SUMMARY =====`);
  console.log(`PASSING (${passing.length}/${results.length}): ${passing.map(r => r.name).join(', ')}`);
  if (failing.length) {
    console.log(`\nFAILING (${failing.length}):`);
    for (const r of failing) {
      console.log(`  ${r.name}:`);
      if (r.failedRequests.length) console.log(`    HTTP: ${r.failedRequests.map(f => f.status+' '+f.url).join('; ')}`);
      if (r.errors.length) r.errors.forEach(e => console.log(`    Error: ${e.substring(0, 120)}`));
    }
  }
  require('fs').writeFileSync('/tmp/ui-test-results.json', JSON.stringify(results, null, 2));
  console.log('\nFull results: /tmp/ui-test-results.json');
}

main().catch(e => { console.error(e); process.exit(1); });
