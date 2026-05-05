'use client';

import { useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { fetchView } from '@/lib/api';
import { emit } from '@/lib/telemetry';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import SeverityBadge from '@/components/shared/SeverityBadge';
import PivotLink from '@/components/shared/PivotLink';
import { Gauge, AlertTriangle, Wrench, Clock } from 'lucide-react';

const TABS = [
  { key: 'overview',     label: 'Overview',          icon: Gauge },
  { key: 'findings',     label: 'Driving Findings',  icon: AlertTriangle },
  { key: 'mitigations',  label: 'Mitigations',       icon: Wrench },
  { key: 'timeline',     label: 'Timeline',          icon: Clock },
];

function formatCurrency(value) {
  if (value === null || value === undefined) return '—';
  const num = Number(value);
  if (!Number.isFinite(num)) return '—';
  if (num >= 1_000_000) return `$${(num / 1_000_000).toFixed(2)}M`;
  if (num >= 1_000)     return `$${(num / 1_000).toFixed(1)}k`;
  return `$${num.toFixed(0)}`;
}

function MetaCell({ label, value }) {
  return (
    <div className="flex flex-col">
      <span className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
        {label}
      </span>
      <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
        {value || '—'}
      </span>
    </div>
  );
}

export default function RiskScenarioPageClient({ id }) {
  const router = useRouter();
  const search = useSearchParams();
  const tab = search.get('tab') || 'overview';
  const [state, setState] = useState({ status: 'loading', data: null, error: null });

  useEffect(() => {
    let cancelled = false;
    setState({ status: 'loading', data: null, error: null });
    fetchView(`risk/scenario/${id}`)
      .then((res) => {
        if (cancelled) return;
        if (res?.error) {
          setState({ status: 'error', data: null, error: { message: res.error } });
          return;
        }
        setState({ status: 'ready', data: res, error: null });
        emit('risk_scenario.page_view', {
          scenario_id: id,
          risk_tier: res?.riskTier,
          source_engine: res?.sourceEngine,
        });
      })
      .catch((err) => {
        if (cancelled) return;
        setState({ status: 'error', data: null, error: err });
      });
    return () => { cancelled = true; };
  }, [id]);

  if (state.status === 'loading') {
    return (
      <div className="p-6 space-y-4">
        <LoadingSkeleton rows={3} cols={6} />
        <LoadingSkeleton rows={6} cols={4} />
      </div>
    );
  }

  if (state.status === 'error') {
    const msg = state.error?.message || '';
    const isNotFound = /404|not found/i.test(msg);
    return (
      <div className="p-8">
        <EmptyState
          title={isNotFound ? 'Risk scenario not found' : 'Failed to load scenario'}
          description={isNotFound
            ? "This scenario either doesn't exist or is outside your tenant scope."
            : (msg || 'An unexpected error occurred.')}
          action={{
            label: 'Back to Risk',
            onClick: () => { window.location.href = '/risk'; },
          }}
        />
      </div>
    );
  }

  const d = state.data || {};
  const switchTab = (next) => {
    const params = new URLSearchParams(search.toString());
    params.set('tab', next);
    router.replace(`/risk/scenario/${id}?${params.toString()}`);
  };

  return (
    <div className="p-6 space-y-4">
      {/* Header card */}
      <div
        className="rounded-lg p-5 space-y-4"
        style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}
      >
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={(d.riskTier || 'low').toLowerCase()} />
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                Risk Scenario
              </span>
            </div>
            <h1 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
              {d.name || 'Risk Scenario'}
            </h1>
            {d.description && (
              <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                {d.description}
              </p>
            )}
          </div>
          <div className="text-right">
            <div className="text-[10px] uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>
              FAIR Risk Score
            </div>
            <div className="text-2xl font-bold" style={{ color: 'var(--accent-primary)' }}>
              {formatCurrency(d.fairScore)}
            </div>
            <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {d.riskBand || '—'} band
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <MetaCell label="Asset" value={d.assetId} />
          <MetaCell label="Asset Type" value={d.assetType} />
          <MetaCell label="Account" value={d.accountId} />
          <MetaCell label="Region" value={d.region} />
          <MetaCell label="Source Engine" value={d.sourceEngine} />
          <MetaCell label="Blast Radius" value={d.blastRadiusScore} />
          <MetaCell label="Loss Likely" value={formatCurrency(d.totalExposureLikely)} />
          <MetaCell label="Loss Max" value={formatCurrency(d.totalExposureMax)} />
        </div>
      </div>

      {/* Tabs */}
      <div
        className="flex gap-1 border-b"
        style={{ borderColor: 'var(--border-primary)' }}
      >
        {TABS.map((t) => {
          const Icon = t.icon;
          const active = tab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => switchTab(t.key)}
              className="flex items-center gap-2 px-4 py-2 text-sm border-b-2 -mb-px"
              style={{
                borderColor: active ? 'var(--accent-primary)' : 'transparent',
                color: active ? 'var(--accent-primary)' : 'var(--text-secondary)',
                fontWeight: active ? 600 : 400,
              }}
            >
              <Icon size={14} />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Tab bodies */}
      {tab === 'overview' && (
        <div className="space-y-4">
          <Section title="MITRE ATT&CK Techniques">
            {d.mitreTechniques?.length ? (
              <div className="flex flex-wrap gap-2">
                {d.mitreTechniques.map((tid) => (
                  <PivotLink key={tid} to="technique" id={tid}>
                    {tid}
                  </PivotLink>
                ))}
              </div>
            ) : <Empty text="No techniques mapped." />}
          </Section>
          <Section title="Regulatory Flags">
            {d.regulatoryFlags?.length ? (
              <div className="flex flex-wrap gap-2 text-xs">
                {d.regulatoryFlags.map((r) => (
                  <span key={r} className="px-2 py-1 rounded"
                    style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>
                    {r}
                  </span>
                ))}
              </div>
            ) : <Empty text="No regulatory flags." />}
          </Section>
        </div>
      )}

      {tab === 'findings' && (
        <Section title="Driving Findings">
          {d.drivingFindings?.length ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide"
                    style={{ color: 'var(--text-muted)' }}>
                  <th className="py-2">Engine</th>
                  <th className="py-2">Finding ID</th>
                  <th className="py-2">Title</th>
                </tr>
              </thead>
              <tbody>
                {d.drivingFindings.map((f, idx) => (
                  <tr key={idx} className="border-t"
                      style={{ borderColor: 'var(--border-primary)' }}>
                    <td className="py-2" style={{ color: 'var(--text-secondary)' }}>
                      {f.sourceEngine || '—'}
                    </td>
                    <td className="py-2">
                      {f.findingId && f.sourceEngine ? (
                        <PivotLink to="finding" engine={f.sourceEngine} id={f.findingId}>
                          {f.findingId}
                        </PivotLink>
                      ) : (f.findingId || '—')}
                    </td>
                    <td className="py-2" style={{ color: 'var(--text-primary)' }}>
                      {f.title || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <Empty text="No driving findings recorded." />}
        </Section>
      )}

      {tab === 'mitigations' && (
        <Section title="Mitigation Checklist">
          {d.mitigations?.length ? (
            <ul className="space-y-2">
              {d.mitigations.map((m) => (
                <li key={m.order}
                    className="flex items-start gap-3 p-3 rounded"
                    style={{ background: 'var(--bg-secondary)',
                             border: '1px solid var(--border-primary)' }}>
                  <span className="text-xs px-2 py-1 rounded"
                        style={{ background: 'var(--bg-tertiary)',
                                 color: 'var(--text-secondary)' }}>
                    {m.status}
                  </span>
                  <div className="flex-1">
                    <div className="text-sm" style={{ color: 'var(--text-primary)' }}>
                      {m.action}
                    </div>
                    {m.expectedReduction !== null && m.expectedReduction !== undefined && (
                      <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                        Expected reduction: {(m.expectedReduction * 100).toFixed(0)}%
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          ) : <Empty text="No mitigations available." />}
        </Section>
      )}

      {tab === 'timeline' && (
        <Section title="Timeline">
          {d.timeline?.length ? (
            <ol className="space-y-3 border-l-2 pl-4"
                style={{ borderColor: 'var(--border-primary)' }}>
              {d.timeline.map((ev, idx) => (
                <li key={idx}>
                  <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    {ev.timestamp || '—'}
                  </div>
                  <div className="text-sm" style={{ color: 'var(--text-primary)' }}>
                    {ev.label}
                  </div>
                  {ev.detail && (
                    <div className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                      {ev.detail}
                    </div>
                  )}
                </li>
              ))}
            </ol>
          ) : <Empty text="No timeline events." />}
        </Section>
      )}
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div
      className="rounded-lg p-4"
      style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}
    >
      <h2 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>
        {title}
      </h2>
      {children}
    </div>
  );
}

function Empty({ text }) {
  return <div className="text-xs" style={{ color: 'var(--text-muted)' }}>{text}</div>;
}
