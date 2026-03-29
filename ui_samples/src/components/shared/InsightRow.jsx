'use client';

/**
 * InsightRow — Slot 3 in the universal page layout.
 * Renders 1-2 chart components side-by-side in a responsive grid.
 *
 * Props:
 *   left    - ReactNode (required) — left chart/widget
 *   right   - ReactNode (optional) — right chart/widget
 *   ratio   - string (optional) — grid ratio, default "1fr 1fr"
 */
export default function InsightRow({ left, right, ratio = '1fr 1fr' }) {
  if (!left && !right) return null;

  if (!right) {
    return (
      <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        {left}
      </div>
    );
  }

  return (
    <div className="grid gap-4" style={{ gridTemplateColumns: ratio }}>
      <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        {left}
      </div>
      <div className="rounded-xl border p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        {right}
      </div>
    </div>
  );
}
