'use client';

/**
 * Blast Radius has moved to Inventory.
 *
 * Per-asset blast radius analysis is now shown in the asset detail page:
 *   Inventory → click any asset row → "Blast Radius" tab
 *
 * This page redirects users there automatically after a brief message.
 */

import { useEffect } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Layers, ArrowRight } from 'lucide-react';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';

export default function BlastRadiusRedirectPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const resourceUid = searchParams.get('resource_uid');

  // Auto-redirect to inventory if a resource_uid was provided
  useEffect(() => {
    if (resourceUid) {
      const dest = `/inventory/${encodeURIComponent(resourceUid)}?tab=blast-radius`;
      const timer = setTimeout(() => router.replace(dest), 2500);
      return () => clearTimeout(timer);
    }
  }, [resourceUid, router]);

  const inventoryLink = resourceUid
    ? `/inventory/${encodeURIComponent(resourceUid)}?tab=blast-radius`
    : '/inventory';

  return (
    <div className="space-y-4">
      <ThreatsSubNav />

      <div
        className="rounded-xl border p-10 flex flex-col items-center gap-5 text-center"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div
          className="w-14 h-14 rounded-full flex items-center justify-center"
          style={{ backgroundColor: 'var(--accent-primary)20' }}
        >
          <Layers className="w-7 h-7" style={{ color: 'var(--accent-primary)' }} />
        </div>

        <div className="space-y-2">
          <h2 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
            Blast Radius has moved
          </h2>
          <p className="text-sm max-w-md" style={{ color: 'var(--text-secondary)' }}>
            Per-asset blast radius analysis is now in{' '}
            <strong style={{ color: 'var(--text-primary)' }}>Inventory</strong>. Open any asset
            row and switch to the <strong style={{ color: 'var(--text-primary)' }}>Blast Radius</strong> tab
            to see the impact graph, hop layers, and impacted resource breakdown.
          </p>
          {resourceUid && (
            <p className="text-xs mt-2" style={{ color: 'var(--text-muted)' }}>
              Redirecting automatically in 2 seconds…
            </p>
          )}
        </div>

        <a
          href={inventoryLink}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium transition-opacity hover:opacity-80"
          style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
        >
          {resourceUid ? 'Open Asset Blast Radius' : 'Go to Inventory'}
          <ArrowRight className="w-4 h-4" />
        </a>
      </div>
    </div>
  );
}
