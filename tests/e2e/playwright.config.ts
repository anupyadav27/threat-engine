import { defineConfig, devices } from '@playwright/test';

/**
 * E2E test config — runs against live EKS cluster via ELB.
 *
 * Usage:
 *   BASE_URL=http://<elb>/ui npx playwright test tests/e2e/ --config tests/e2e/playwright.config.ts
 *
 * Defaults to the production ELB when BASE_URL is not set.
 */

const BASE_URL =
  process.env.BASE_URL ??
  'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/ui';

const AUTH_URL =
  process.env.NEXT_PUBLIC_AUTH_URL ??
  'http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com';

export default defineConfig({
  testDir: '.',
  fullyParallel: false,
  retries: 1,
  timeout: 45_000,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['html', { outputFolder: 'playwright-report', open: 'never' }]],

  use: {
    baseURL: BASE_URL,
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium-headless',
      use: { ...devices['Desktop Chrome'], headless: true },
    },
  ],
});
