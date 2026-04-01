'use client';

import Link from 'next/link';
import { ArrowRight } from 'lucide-react';

/* All platform domains */
const DOMAIN_META = {
  compliance: { label: 'Compliance', href: '?tab=compliance' },
  threats:    { label: 'Threats',    href: '?tab=threats'    },
  iam:        { label: 'IAM',        href: '?tab=iam'        },
  misconfigs: { label: 'Misconfigs', href: '?tab=posture'    },
  dataSec:    { label: 'Data Sec',   href: '?tab=datasec'    },
  network:    { label: 'Network',    href: '?tab=network'    },
  codeSec:    { label: 'Code Sec',   href: '?tab=codesec'    },
  risk:       { label: 'Risk',       href: '?tab=risk'       },
};

function scoreThreshold(v) {
  if (v >= 75) return { color: '#22c55e', label: 'Good' };
  if (v >= 50) return { color: '#f97316', label: 'Fair' };
  return { color: '#ef4444', label: 'Poor' };
}

/* SVG donut ring — score 0-100 fills the arc */
function DonutRing({ score, size = 64 }) {
  const r     = (size - 10) / 2;
  const circ  = 2 * Math.PI * r;
  const fill  = circ * (score / 100);
  const cx    = size / 2;
  const cy    = size / 2;
  const color = scoreThreshold(score).color;

  return (
    <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
      {/* Track */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--bg-tertiary)" strokeWidth="6" />
      {/* Fill arc */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="6"
        strokeDasharray={`${fill} ${circ}`} strokeLinecap="round"
        style={{ transition: 'stroke-dasharray 0.6s ease' }} />
    </svg>
  );
}

/**
 * PostureScoreHero — domain breakdown as donut ring grid.
 * The overall 67/100 score has been promoted to the PostureScoreBanner
 * in the KPI strip above. This component shows WHERE the risk sits.
 *
 * @param {{
 *   score: number,
 *   criticalActions: number,
 *   domainScores: Record<string, number>,
 *   domainCritical: Record<string, number>,
 * }} props
 */
export default function PostureScoreHero({
  criticalActions,
  domainScores,
  domainCritical = {},
  filterLabel = null,   // e.g. "Acme Corp / AWS Production" — shows active filter context
}) {
  const activeDomains = Object.keys(DOMAIN_META).filter(
    key => domainScores?.[key] != null
  );

  const poorCount = activeDomains.filter(k => domainScores[k] < 50).length;
  const fairCount = activeDomains.filter(k => domainScores[k] >= 50 && domainScores[k] < 75).length;
  const goodCount = activeDomains.filter(k => domainScores[k] >= 75).length;

  return (
    <div
      className="rounded-xl border transition-colors duration-200"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      {/* ── Header ── */}
      <div className="flex items-center justify-between px-5 py-3 border-b"
        style={{ borderColor: 'var(--border-primary)' }}>
        <div>
          <div className="flex items-center gap-2">
            <p className="text-xs font-semibold uppercase tracking-wider"
              style={{ color: 'var(--text-muted)' }}>
              Security Domain Breakdown
            </p>
            {filterLabel && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded"
                style={{ backgroundColor: '#8b5cf620', color: '#8b5cf6' }}>
                {filterLabel}
              </span>
            )}
          </div>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            <span className="font-semibold" style={{ color: '#22c55e' }}>{goodCount} good</span>
            {' · '}
            <span className="font-semibold" style={{ color: '#f97316' }}>{fairCount} fair</span>
            {' · '}
            <span className="font-semibold" style={{ color: '#ef4444' }}>{poorCount} poor</span>
          </p>
        </div>
        {/* Summary chip */}
        {criticalActions > 0 && (
          <span className="text-xs font-semibold px-2.5 py-1 rounded-full"
            style={{ backgroundColor: '#ef444420', color: '#ef4444' }}>
            {criticalActions} critical actions
          </span>
        )}
      </div>

      {/* ── Donut Ring Grid ── */}
      <div className="p-5 grid grid-cols-2 sm:grid-cols-4 gap-4">
        {activeDomains.map(key => {
          const val       = domainScores[key];
          const meta      = DOMAIN_META[key];
          const theme     = scoreThreshold(val);
          const critCount = domainCritical[key];

          return (
            <Link key={key} href={meta.href}
              className="flex flex-col items-center gap-2 p-3 rounded-lg border cursor-pointer group
                         hover:border-slate-600 transition-colors"
              style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>

              {/* Ring with score centered */}
              <div className="relative">
                <DonutRing score={val} size={60} />
                <span className="absolute inset-0 flex items-center justify-center text-sm font-black"
                  style={{ color: theme.color }}>
                  {val}
                </span>
              </div>

              {/* Domain label */}
              <span className="text-xs font-medium text-center leading-tight"
                style={{ color: 'var(--text-secondary)' }}>
                {meta.label}
              </span>

              {/* Status label + critical count */}
              <div className="flex items-center gap-1.5">
                <span className="text-xs px-1.5 py-0.5 rounded font-semibold"
                  style={{ backgroundColor: `${theme.color}18`, color: theme.color }}>
                  {theme.label}
                </span>
                {critCount != null && critCount > 0 && (
                  <span className="text-xs font-semibold px-1.5 py-0.5 rounded"
                    style={{ backgroundColor: '#ef444420', color: '#ef4444' }}>
                    ▲{critCount}
                  </span>
                )}
              </div>

              {/* Hover arrow */}
              <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-50 transition-opacity"
                style={{ color: 'var(--text-muted)' }} />
            </Link>
          );
        })}
      </div>

      {/* ── Legend ── */}
      <div className="flex items-center gap-4 px-5 py-3 border-t"
        style={{ borderColor: 'var(--border-primary)' }}>
        {[
          { color: '#22c55e', label: 'Good  ≥75' },
          { color: '#f97316', label: 'Fair  50–74' },
          { color: '#ef4444', label: 'Poor  <50' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: color }} />
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</span>
          </div>
        ))}
        <div className="ml-auto flex items-center gap-1">
          <span className="text-xs px-1.5 py-0.5 rounded font-semibold"
            style={{ backgroundColor: '#ef444420', color: '#ef4444' }}>▲n</span>
          <span className="text-xs ml-1" style={{ color: 'var(--text-muted)' }}>= critical findings</span>
        </div>
      </div>
    </div>
  );
}
