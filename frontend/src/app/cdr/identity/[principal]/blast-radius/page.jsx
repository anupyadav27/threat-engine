'use client';

import { useParams, useRouter } from 'next/navigation';
import { ChevronLeft, Lock } from 'lucide-react';

/**
 * Blast Radius page — SECURITY BLOCK (BLOCK-CDR-05-1).
 *
 * This page MUST remain a placeholder until the BFF enforces max_hops=3
 * server-side. Rendering unbounded graph traversal results without the
 * hop cap creates a DoS vector and exposes cross-tenant paths.
 *
 * Follow-on story required before removing this placeholder.
 */
export default function BlastRadiusPage() {
  const params    = useParams();
  const router    = useRouter();
  const principal = decodeURIComponent(params.principal || '');
  const back      = `/cdr/identity/${encodeURIComponent(principal)}`;

  return (
    <div className="space-y-4">
      <button
        onClick={() => router.push(back)}
        className="flex items-center gap-1.5 text-sm hover:opacity-75 transition-opacity"
        style={{ color: 'var(--text-secondary)' }}>
        <ChevronLeft className="w-4 h-4" />
        Identity Profile
      </button>

      <div className="flex flex-col items-center justify-center py-24 rounded-xl border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="w-14 h-14 rounded-full flex items-center justify-center mb-5"
          style={{ backgroundColor: 'rgba(99,102,241,0.1)', border: '1px solid rgba(99,102,241,0.3)' }}>
          <Lock className="w-7 h-7 text-indigo-400" />
        </div>
        <h2 className="text-lg font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
          Blast Radius — Coming Soon
        </h2>
        <p className="text-sm text-center max-w-md mb-4" style={{ color: 'var(--text-secondary)' }}>
          The blast radius graph visualises how far a compromised identity can reach across your cloud.
          This feature is pending a security gate: the BFF must enforce <code className="font-mono text-xs px-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>max_hops=3</code> before the full traversal page can go live.
        </p>
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
          BLOCK-CDR-05-1 — Traversal depth cap required
        </p>
      </div>
    </div>
  );
}
