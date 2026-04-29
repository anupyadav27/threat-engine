'use client';

/**
 * InsightRow — Slot 3 in the universal page layout.
 * Renders 1-3 chart components side-by-side in a responsive grid.
 *
 * Props:
 *   left    - ReactNode (required) — left chart/widget
 *   right   - ReactNode (optional) — right chart/widget
 *   third   - ReactNode (optional) — third chart/widget (e.g. scan trend)
 *   ratio   - string (optional) — grid ratio for left+right, default "1fr 1fr"
 */
export default function InsightRow({ left, right, third, ratio = '1fr 1fr' }) {
  if (!left && !right && !third) return null;

  // Replace 1fr tokens with minmax(0,1fr) to prevent content from expanding grid tracks
  const normalize = (s) => s.replace(/(\d*\.?\d+)fr/g, 'minmax(0, $1fr)');
  const baseCols = third ? `${ratio} 1.1fr` : right ? ratio : '1fr';
  const cols = normalize(baseCols);

  return (
    <div className="grid gap-4" style={{ gridTemplateColumns: cols, width: '100%', minWidth: 0 }}>
      {left && (
        <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {left}
        </div>
      )}
      {right && (
        <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {right}
        </div>
      )}
      {third && (
        <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {third}
        </div>
      )}
    </div>
  );
}
