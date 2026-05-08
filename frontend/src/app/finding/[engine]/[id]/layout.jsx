import { notFound } from 'next/navigation';

// CP-2 B1: long slugs (K8s service names) are canonical.
// Short slugs (network/container/ai) are mapped to long form by BFF.
export const ENGINE_SLUG_WHITELIST = new Set([
  'iam',
  'network-security',
  'datasec',
  'encryption',
  'container-security',
  'dbsec',
  'ai-security',
  'ciem',
  'check',
  'threat',
  'secops',
]);

const ID_REGEX = /^[A-Za-z0-9._:/\-]+$/;
const ID_MIN = 1;
const ID_MAX = 128;

/**
 * Server-side validation gate for /finding/[engine]/[id].
 *
 * - Validates engine slug against whitelist.
 * - Validates id charset + length.
 * - Auth context (tenant_id) is resolved by middleware/AppShell on the
 *   client; this layout intentionally does not duplicate that — it only
 *   guards URL shape so the BFF receives well-formed params.
 */
export default function FindingLayout({ children, params }) {
  const { engine, id } = params || {};

  if (!engine || !ENGINE_SLUG_WHITELIST.has(engine)) {
    notFound();
  }

  if (
    !id ||
    typeof id !== 'string' ||
    id.length < ID_MIN ||
    id.length > ID_MAX ||
    !ID_REGEX.test(id)
  ) {
    notFound();
  }

  return children;
}
