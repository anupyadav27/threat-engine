'use client';

import { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

const TYPE_BADGE = {
  iam_role:        { label: 'Role',            cls: 'bg-blue-950 text-blue-300 border-blue-800'     },
  iam_user:        { label: 'User',            cls: 'bg-green-950 text-green-300 border-green-800'   },
  service_account: { label: 'Service Account', cls: 'bg-orange-950 text-orange-300 border-orange-800' },
  root:            { label: 'Root',            cls: 'bg-red-950 text-red-300 border-red-800'         },
};

function gaugeColor(score) {
  if (score >= 80) return '#ef4444';
  if (score >= 60) return '#f97316';
  if (score >= 40) return '#eab308';
  return '#22c55e';
}

function CircularGauge({ score }) {
  const size = 100;
  const strokeW = 8;
  const r = (size - strokeW) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;
  const pct = Math.min(Math.max(score, 0), 100) / 100;
  const color = gaugeColor(score);

  return (
    <svg width={size} height={size} style={{ display: 'block', flexShrink: 0 }}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e293b" strokeWidth={strokeW} />
      <circle
        cx={cx} cy={cy} r={r}
        fill="none"
        stroke={color}
        strokeWidth={strokeW}
        strokeLinecap="round"
        strokeDasharray={`${circumference * pct} ${circumference * (1 - pct)}`}
        transform={`rotate(-90 ${cx} ${cy})`}
      />
      <text x={cx} y={cy + 1} textAnchor="middle" dominantBaseline="middle"
        style={{ fontSize: 22, fontWeight: 900, fill: color, fontFamily: 'inherit', fontVariantNumeric: 'tabular-nums' }}>
        {score}
      </text>
      <text x={cx} y={cy + 17} textAnchor="middle"
        style={{ fontSize: 9, fill: '#64748b', fontFamily: 'inherit' }}>
        risk
      </text>
    </svg>
  );
}

function fmtTs(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function IdentityProfileHeader({
  principal,
  type,
  riskScore = 0,
  l2Count = 0,
  l3Count = 0,
  accountCount = 0,
  lastSeen,
  sourceIps = [],
}) {
  const [expanded, setExpanded] = useState(false);
  const [ipsOpen, setIpsOpen] = useState(false);

  const badgeCfg = TYPE_BADGE[type] || { label: type || 'Unknown', cls: 'bg-slate-800 text-slate-300 border-slate-700' };
  const truncPrincipal = principal?.length > 48 ? principal.slice(0, 48) + '…' : principal;
  const displayPrincipal = expanded ? principal : truncPrincipal;

  return (
    <div className="flex gap-6 rounded-xl p-6 items-center"
      style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>

      {/* Left 1/3: ARN + type badge */}
      <div style={{ flex: 1 }}>
        <div className="flex items-start gap-1.5">
          <span className="font-mono text-sm break-all" style={{ color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            {displayPrincipal}
          </span>
          {principal?.length > 48 && (
            <button
              onClick={() => setExpanded(p => !p)}
              className="flex-shrink-0 mt-0.5 hover:opacity-75 transition-opacity"
              style={{ color: 'var(--text-muted)' }}>
              {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>
          )}
        </div>
        <div className="mt-2">
          <span className={`inline-flex items-center text-xs font-semibold px-2 py-0.5 rounded-full border ${badgeCfg.cls}`}>
            {badgeCfg.label}
          </span>
        </div>
      </div>

      {/* Center 1/3: risk gauge */}
      <div className="flex flex-col items-center gap-1" style={{ flexShrink: 0 }}>
        <CircularGauge score={riskScore} />
      </div>

      {/* Right 1/3: badges + metadata */}
      <div style={{ flex: 1 }}>
        <div className="flex flex-wrap gap-2 mb-3">
          <span className="bg-orange-950 text-orange-300 text-xs px-2 py-1 rounded-full border border-orange-800">
            L2 Chains: {l2Count}
          </span>
          <span className="bg-purple-950 text-purple-300 text-xs px-2 py-1 rounded-full border border-purple-800">
            Anomalies: {l3Count}
          </span>
          <span className="bg-blue-950 text-blue-300 text-xs px-2 py-1 rounded-full border border-blue-800">
            Accounts: {accountCount}
          </span>
        </div>

        <div className="text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
          Last seen: {fmtTs(lastSeen)}
        </div>

        {sourceIps?.length > 0 && (
          <div>
            <button
              onClick={() => setIpsOpen(p => !p)}
              className="flex items-center gap-1 text-xs hover:opacity-75 transition-opacity"
              style={{ color: 'var(--text-secondary)' }}>
              <span className="bg-slate-800 text-slate-300 border border-slate-700 text-xs px-2 py-0.5 rounded-full">
                {sourceIps.length} IPs
              </span>
              {ipsOpen ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </button>
            {ipsOpen && (
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {sourceIps.map((ip, i) => (
                  <span key={i} className="font-mono text-[10px] px-1.5 py-0.5 rounded"
                    style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                    {ip}
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
