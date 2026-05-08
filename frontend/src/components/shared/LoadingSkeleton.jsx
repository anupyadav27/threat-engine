'use client';

/**
 * LoadingSkeleton component for displaying loading states.
 *
 * @component
 * @param {Object} props - Component props
 * @param {number} [props.rows=5] - Number of skeleton rows
 * @param {number} [props.cols=4] - Number of skeleton columns
 * @returns {JSX.Element}
 */
export default function LoadingSkeleton({ rows = 5, cols = 4 }) {
  const WIDTHS = ['w-3/4', 'w-4/5', 'w-5/6', 'w-full'];

  // Deterministic width based on row+col index to avoid hydration mismatch
  const getWidth = (rowIdx, colIdx) => WIDTHS[(rowIdx * 3 + colIdx * 7) % WIDTHS.length];

  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, rowIdx) => (
        <div
          key={rowIdx}
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          className="flex gap-4 p-4 rounded-lg border transition-colors duration-200"
        >
          {Array.from({ length: cols }).map((_, colIdx) => (
            <div
              key={colIdx}
              style={{ backgroundColor: 'var(--bg-tertiary)' }}
              className={`h-4 rounded animate-pulse transition-colors duration-200 ${getWidth(rowIdx, colIdx)}`}
            />
          ))}
        </div>
      ))}
    </div>
  );
}
