import Link from 'next/link';
import EmptyState from '@/components/shared/EmptyState';

export default function RiskScenarioNotFound() {
  return (
    <div className="p-8">
      <EmptyState
        title="Risk scenario not found"
        description="This scenario either doesn't exist or is outside your tenant scope."
        action={{
          label: 'Back to Risk',
          onClick: () => {
            if (typeof window !== 'undefined') window.location.href = '/risk';
          },
        }}
      />
      <div className="mt-4 text-center text-xs" style={{ color: 'var(--text-muted)' }}>
        <Link href="/risk" style={{ color: 'var(--accent-primary)' }}>
          Back to Risk
        </Link>
      </div>
    </div>
  );
}
