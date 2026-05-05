import { notFound } from 'next/navigation';

const ID_REGEX = /^[A-Za-z0-9._:/\-]+$/;

/**
 * Server-side validation gate for /risk/scenario/[id].
 * Validates id charset + length only — auth/tenant resolution lives in
 * middleware/AppShell. Keeps the BFF receiving well-formed params.
 */
export default function RiskScenarioLayout({ children, params }) {
  const { id } = params || {};
  if (!id || typeof id !== 'string' || id.length < 1 || id.length > 64 || !ID_REGEX.test(id)) {
    notFound();
  }
  return children;
}
