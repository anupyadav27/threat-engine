import FindingPageClient from '@/components/finding/FindingPageClient';

/**
 * Universal finding-detail route: /finding/[engine]/[id]
 *
 * Server component shell — slug + id validation runs in layout.jsx.
 * The actual fetch + render happens in <FindingPageClient> so the rest of
 * the App stays consistent with existing detail pages (threats/[threatId]
 * etc.) which all use client-side fetchView via the gateway.
 *
 * AC-6: single fetch on mount; tab switches stay client-side via ?tab=
 * query param without re-fetching.
 */
export default function FindingPage({ params }) {
  const { engine, id } = params || {};
  return <FindingPageClient engine={engine} id={id} />;
}
