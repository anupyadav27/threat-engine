'use client';

/**
 * Threat Timeline has moved into the Threat Detail page.
 *
 * Per-threat activity history (first detected, severity changes, assignments,
 * suppressed/resolved) is now shown inside each threat:
 *   Threats → click any threat row → "Timeline" tab
 *
 * This page redirects users there automatically.
 */

import { useRouter } from 'next/navigation';
import { Clock, ArrowRight } from 'lucide-react';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';

export default function TimelineRedirectPage() {
  const router = useRouter();

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
          <Clock className="w-7 h-7" style={{ color: 'var(--accent-primary)' }} />
        </div>

        <div className="space-y-2">
          <h2 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
            Timeline is now inside each threat
          </h2>
          <p className="text-sm max-w-md" style={{ color: 'var(--text-secondary)' }}>
            Per-threat activity history — when it was detected, severity changes, who it was
            assigned to, suppressed, and resolved — is now on the{' '}
            <strong style={{ color: 'var(--text-primary)' }}>Timeline tab</strong> inside each
            threat detail view.
          </p>
        </div>

        <button
          onClick={() => router.push('/threats')}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium transition-opacity hover:opacity-80"
          style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
        >
          Go to Threats
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
}
