import Link from 'next/link';
import EmptyState from '@/components/shared/EmptyState';
import { ENGINE_META } from '@/components/finding/engine-meta';

export default function FindingNotFound({ params }) {
  // Next.js does not pass params to not-found by default; derive from URL on
  // client. Keep this simple: link to global findings list.
  const engine = params?.engine;
  const meta = engine ? ENGINE_META[engine] : null;
  const backLabel = meta ? `Back to ${meta.label}` : 'Back to Dashboard';
  const backHref = meta ? meta.route : '/dashboard';

  return (
    <div className="p-8">
      <EmptyState
        title="Finding not found"
        description="This finding either doesn't exist, has been resolved, or is outside your tenant scope."
        action={{
          label: backLabel,
          onClick: () => {
            if (typeof window !== 'undefined') {
              window.location.href = backHref;
            }
          },
        }}
      />
      <div className="mt-4 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
        <Link href={backHref} style={{ color: 'var(--accent-primary)' }}>
          {backLabel}
        </Link>
      </div>
    </div>
  );
}
