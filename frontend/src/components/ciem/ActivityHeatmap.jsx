'use client';

const DOW_LABELS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

function cellColor(count, maxCount) {
  if (!count || !maxCount) return 'bg-slate-700';
  const ratio = count / maxCount;
  if (ratio < 0.25) return 'bg-blue-900';
  if (ratio < 0.5)  return 'bg-blue-700';
  if (ratio < 0.75) return 'bg-blue-600';
  return 'bg-blue-500';
}

export default function ActivityHeatmap({ hourlyData, dowData }) {
  const hours = Array.isArray(hourlyData) && hourlyData.length === 24
    ? hourlyData
    : Array.from({ length: 24 }, (_, i) => ({ hour: i, count: 0 }));

  const dows = Array.isArray(dowData) && dowData.length === 7
    ? dowData
    : Array.from({ length: 7 }, (_, i) => ({ dow: i, count: 0 }));

  const maxCount = Math.max(
    ...hours.map(h => h.count || 0),
    ...dows.map(d => d.count || 0),
    1,
  );

  return (
    <div className="rounded-xl border p-4" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="text-xs font-semibold mb-3 uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
        Activity Pattern
      </div>

      {/* 24-col × 7-row heatmap */}
      <div className="mb-4">
        {/* Hour labels */}
        <div className="flex mb-1 ml-10">
          {hours.map((h, i) => (
            <div key={i} className="w-3 h-3 flex-shrink-0 flex items-center justify-center">
              {[0, 6, 12, 18].includes(i) && (
                <span className="text-[8px] absolute" style={{ color: 'var(--text-muted)' }}>{i}</span>
              )}
            </div>
          ))}
        </div>

        {/* Rows (day of week × hours) */}
        {dows.map((d, di) => (
          <div key={di} className="flex items-center gap-px mb-px">
            <span className="text-[10px] w-10 text-right pr-1.5 flex-shrink-0" style={{ color: 'var(--text-muted)' }}>
              {DOW_LABELS[di] || `D${di}`}
            </span>
            {hours.map((h, hi) => {
              const count = (d.hours?.[hi] ?? h.count ?? 0);
              return (
                <div
                  key={hi}
                  title={`${DOW_LABELS[di]} ${hi}:00 — ${count} events`}
                  className={`w-3 h-3 rounded-sm flex-shrink-0 ${cellColor(count, maxCount)}`}
                />
              );
            })}
          </div>
        ))}
      </div>

      {/* Hourly bar summary */}
      <div>
        <div className="text-[10px] mb-1" style={{ color: 'var(--text-muted)' }}>Events by hour</div>
        <div className="flex items-end gap-px h-8">
          {hours.map((h, i) => {
            const ratio = maxCount > 0 ? (h.count || 0) / maxCount : 0;
            return (
              <div
                key={i}
                title={`${i}:00 — ${h.count || 0} events`}
                className="flex-1 bg-blue-600 rounded-t opacity-80"
                style={{ height: `${Math.max(ratio * 100, 4)}%` }}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}
