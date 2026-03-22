'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { Shield, ChevronRight, AlertTriangle, Globe, ArrowRight, Target, Network, Zap } from 'lucide-react';
import { fetchView } from '@/lib/api';
import MetricStrip from '@/components/shared/MetricStrip';
import SeverityBadge from '@/components/shared/SeverityBadge';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';
import { useGlobalFilter } from '@/lib/global-filter-context';

// ── Constants ────────────────────────────────────────────────────────────────

const CHAIN_TYPE_LABELS = {
  internet_to_data: 'Internet \u2192 Data',
  internet_to_secrets: 'Internet \u2192 Secrets',
  internet_to_compute: 'Internet \u2192 Compute',
  internet_to_identity: 'Internet \u2192 Identity',
  internal_privilege_escalation: 'Priv Escalation',
  internal_lateral_movement: 'Lateral Movement',
};

const CATEGORY_COLORS = {
  network: '#3b82f6', compute: '#f97316', data: '#22c55e', identity: '#a855f7', storage: '#eab308',
};

const scoreColor = (s) => (s >= 80 ? '#ef4444' : s >= 60 ? '#f97316' : s >= 40 ? '#eab308' : '#22c55e');

// ── Hop Chain Visualization ──────────────────────────────────────────────────

function HopNode({ name, category }) {
  const color = CATEGORY_COLORS[category] || 'var(--text-muted)';
  return (
    <div className="flex flex-col items-center gap-1">
      <div
        className="rounded-lg border px-3 py-2 text-center"
        style={{ backgroundColor: `${color}10`, borderColor: `${color}40`, minWidth: 72, maxWidth: 100 }}
      >
        <span className="text-xs font-semibold block truncate" style={{ color: 'var(--text-primary)' }}>
          {name || 'N/A'}
        </span>
      </div>
      <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{category || ''}</span>
    </div>
  );
}

function HopArrow() {
  return (
    <div className="flex items-center flex-shrink-0 px-1" style={{ color: 'var(--text-muted)' }}>
      <div className="w-4 h-px" style={{ backgroundColor: 'rgba(255,255,255,0.2)' }} />
      <ArrowRight className="w-3.5 h-3.5" />
      <div className="w-4 h-px" style={{ backgroundColor: 'rgba(255,255,255,0.2)' }} />
    </div>
  );
}

function HopChain({ steps }) {
  if (!steps || steps.length === 0) return null;
  return (
    <div className="flex items-start gap-0 overflow-x-auto py-2 px-1">
      {steps.map((step, idx) => (
        <div key={idx} className="flex items-center">
          <HopNode name={step.from || step.to} category={step.category} />
          {idx < steps.length - 1 && <HopArrow />}
          {idx === steps.length - 1 && (
            <>
              <HopArrow />
              <HopNode name={step.to} category={step.category} />
            </>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Chain Type Filter Pills ──────────────────────────────────────────────────

function ChainTypePills({ chainTypes, activeType, onSelect }) {
  const entries = Object.entries(chainTypes || {});
  const total = entries.reduce((sum, [, v]) => sum + v, 0);

  return (
    <div className="flex items-center gap-2 overflow-x-auto pb-1">
      <button
        onClick={() => onSelect(null)}
        className="text-xs font-medium px-3 py-1.5 rounded-full border whitespace-nowrap transition-colors"
        style={{
          backgroundColor: !activeType ? 'var(--accent-primary)' : 'var(--bg-secondary)',
          color: !activeType ? '#fff' : 'var(--text-secondary)',
          borderColor: !activeType ? 'var(--accent-primary)' : 'var(--border-primary)',
        }}
      >
        All ({total})
      </button>
      {entries.map(([type, count]) => (
        <button
          key={type}
          onClick={() => onSelect(type === activeType ? null : type)}
          className="text-xs font-medium px-3 py-1.5 rounded-full border whitespace-nowrap transition-colors"
          style={{
            backgroundColor: activeType === type ? 'var(--accent-primary)' : 'var(--bg-secondary)',
            color: activeType === type ? '#fff' : 'var(--text-secondary)',
            borderColor: activeType === type ? 'var(--accent-primary)' : 'var(--border-primary)',
          }}
        >
          {CHAIN_TYPE_LABELS[type] || type} ({count})
        </button>
      ))}
    </div>
  );
}

// ── Attack Path Card ─────────────────────────────────────────────────────────

function AttackPathCard({ path }) {
  const color = scoreColor(path.pathScore || 0);
  const techniques = path.mitreTechniques || [];

  return (
    <div
      className="rounded-xl border overflow-hidden"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      {/* Card header */}
      <div className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <SeverityBadge severity={path.severity || 'info'} />
            <div className="flex-1 min-w-0">
              <h3 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>{path.title}</h3>
              {path.description && (
                <p className="text-xs mt-0.5 line-clamp-1" style={{ color: 'var(--text-secondary)' }}>
                  {path.description}
                </p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-1.5 flex-shrink-0">
            <span className="text-[10px] font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>Score</span>
            <span className="text-lg font-bold tabular-nums" style={{ color }}>{path.pathScore || 0}</span>
          </div>
        </div>

        {/* Hop chain */}
        <div className="mt-3">
          <HopChain steps={path.steps || []} />
        </div>

        {/* Footer metadata */}
        <div className="flex items-center flex-wrap gap-3 mt-3 pt-3 border-t" style={{ borderColor: 'var(--border-primary)' }}>
          <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            <Target style={{ width: 12, height: 12 }} /> {path.depth || 0} hops
          </span>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Provider: <span style={{ color: 'var(--text-secondary)' }}>{path.provider || 'AWS'}</span>
          </span>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Account: <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{(path.accountId || '').slice(0, 6)}..</span>
          </span>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Region: <span style={{ color: 'var(--text-secondary)' }}>{path.region || '-'}</span>
          </span>
          {path.isInternetReachable && (
            <span className="flex items-center gap-1 text-xs" style={{ color: '#ef4444' }}>
              <Globe style={{ width: 12, height: 12 }} /> Internet Reachable
            </span>
          )}
        </div>

        {/* MITRE + action */}
        <div className="flex items-center flex-wrap gap-2 mt-2.5">
          {techniques.length > 0 && (
            <span className="text-[10px] font-semibold uppercase" style={{ color: 'var(--text-muted)' }}>MITRE:</span>
          )}
          {techniques.map((t) => (
            <span
              key={t}
              className="text-[10px] px-2 py-0.5 rounded font-bold font-mono"
              style={{ backgroundColor: 'rgba(239,68,68,0.10)', color: '#f87171', border: '1px solid rgba(239,68,68,0.20)' }}
            >
              {t}
            </span>
          ))}
          {path.detectionId && (
            <a
              href={`/ui/threats/${path.detectionId}`}
              className="ml-auto inline-flex items-center gap-1 text-xs font-medium hover:opacity-75 transition-opacity"
              style={{ color: 'var(--accent-primary)' }}
            >
              View Detection <ArrowRight style={{ width: 12, height: 12 }} />
            </a>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function AttackPathsPage() {
  const { account } = useGlobalFilter();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);
  const [activeChainType, setActiveChainType] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      const result = await fetchView('threats/attack-paths');
      if (cancelled) return;
      result?.error ? setError(result.error) : setData(result);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [account]);

  const kpi = data?.kpi ?? {};
  const chainTypes = data?.chainTypes ?? {};

  const attackPaths = useMemo(() => {
    let items = data?.attackPaths ?? [];
    if (activeChainType) items = items.filter((p) => p.chainType === activeChainType);
    return [...items].sort((a, b) => (b.pathScore ?? 0) - (a.pathScore ?? 0));
  }, [data, activeChainType]);

  const metricGroups = useMemo(() => [
    {
      label: 'ATTACK PATHS', color: 'var(--accent-danger)',
      cells: [
        { label: 'TOTAL PATHS', value: kpi.total ?? 0, noTrend: true },
        { label: 'CRITICAL', value: kpi.critical ?? 0, valueColor: '#ef4444', noTrend: true },
        { label: 'HIGH', value: kpi.high ?? 0, valueColor: '#f97316', noTrend: true },
        { label: 'INTERNET REACHABLE', value: kpi.internetReachable ?? 0, valueColor: '#ef4444', noTrend: true },
      ],
    },
  ], [kpi]);

  return (
    <div className="space-y-4">
      {/* Header + Breadcrumb */}
      <div>
        <div className="flex items-center gap-2 text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
          <a href="/ui/threats" className="hover:underline" style={{ color: 'var(--text-secondary)' }}>Threats</a>
          <ChevronRight className="w-3 h-3" />
          <span style={{ color: 'var(--text-primary)' }}>Attack Paths</span>
        </div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Attack Paths</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Multi-step attack chains through your cloud infrastructure — entry points to critical targets.
        </p>
      </div>

      <ThreatsSubNav />

      {loading && (
        <div className="space-y-4">
          <div className="h-[100px] rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
          <LoadingSkeleton rows={6} cols={4} />
        </div>
      )}

      {!loading && error && (
        <div className="rounded-xl p-5 border" style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.3)' }}>
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
            <div>
              <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Failed to load attack paths</p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</p>
            </div>
          </div>
        </div>
      )}

      {!loading && !error && (
        <>
          <MetricStrip groups={metricGroups} />

          <ChainTypePills chainTypes={chainTypes} activeType={activeChainType} onSelect={setActiveChainType} />

          {attackPaths.length === 0 ? (
            <EmptyState
              icon={<Network className="w-12 h-12" />}
              title="No Attack Paths"
              description="No multi-step attack paths detected. Run a threat scan to analyze your infrastructure for potential attack chains."
            />
          ) : (
            <div className="space-y-4">
              {attackPaths.map((path) => (
                <AttackPathCard key={path.id} path={path} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
