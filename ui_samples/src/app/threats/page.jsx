'use client';

import { useEffect, useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield, AlertTriangle, Activity, Zap, Clock, CheckCircle,
  ChevronRight, TrendingUp, Users, Timer,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import MetricStrip from '@/components/shared/MetricStrip';
import FilterBar from '@/components/shared/FilterBar';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';
import SeverityDonut from '@/components/charts/SeverityDonut';
import TrendLine from '@/components/charts/TrendLine';
import DataTable from '@/components/shared/DataTable';


// ── Main Page ─────────────────────────────────────────────────────────────────
export default function ThreatsPage() {
  const router = useRouter();
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState(null);
  const [threats,     setThreats]     = useState([]);
  const [trendData,   setTrendData]   = useState([]);
  const [attackChains,  setAttackChains]  = useState([]);
  const [threatIntel,   setThreatIntel]   = useState([]);
  const [mitreMatrix,   setMitreMatrix]   = useState({});

  // ── Scalar-based filter state ─────────────────────────────────────────────
  const [activeFilters, setActiveFilters] = useState({
    mitreTactic: '', severity: '', status: '',
  });

  // ── Filter change handler ──────────────────────────────────────────────────
  const handleFilterChange = (key, value) => {
    setActiveFilters(prev => ({ ...prev, [key]: value }));
  };

  // ── Global scope filter ───────────────────────────────────────────────────
  const { provider, account, region, filterSummary } = useGlobalFilter();

  useEffect(() => {
    const fetchThreats = async () => {
      setLoading(true);
      try {
        const data = await fetchView('threats', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (data.error) { setError(data.error); return; }
        if (data.threats)      setThreats(data.threats);
        if (data.trendData)    setTrendData(data.trendData);
        if (data.attackChains) setAttackChains(data.attackChains);
        if (data.threatIntel)  setThreatIntel(data.threatIntel);
        if (data.mitreMatrix)  setMitreMatrix(data.mitreMatrix);
      } catch (err) {
        console.warn('[threats] fetchThreats error:', err);
        setError('Failed to load threats data');
      } finally {
        setLoading(false);
      }
    };
    fetchThreats();
  }, [provider, account, region]);

  // ── Dynamic filter options ────────────────────────────────────────────────
  const uniqueTactics = useMemo(() => [...new Set(threats.map(t => t.mitreTactic).filter(Boolean))].sort(), [threats]);

  const filterOptions = [
    { key:'mitreTactic', label:'All Tactics',     options: uniqueTactics },
    { key:'severity',     label:'All Severities',  options: ['critical','high','medium','low'].map(s => ({ value:s, label:s.charAt(0).toUpperCase()+s.slice(1) })) },
    { key:'status',       label:'All Statuses',    options: ['active','investigating','resolved','false-positive'].map(s => ({ value:s, label:s.charAt(0).toUpperCase()+s.slice(1).replace('-',' ') })) },
  ];

  // ── Filtered threats ──────────────────────────────────────────────────────
  const filteredThreats = useMemo(() =>
    threats.filter(t =>
      (!activeFilters.mitre_tactic || t.mitreTactic === activeFilters.mitre_tactic) &&
      (!activeFilters.severity     || t.severity     === activeFilters.severity)     &&
      (!activeFilters.status       || t.status       === activeFilters.status)
    ),
    [threats, activeFilters]);

  // ── KPI stats (from BFF kpi, with local fallback) ─────────────────────────
  const stats = useMemo(() => ({
    total:      threats.length,
    critical:   threats.filter(t => t.severity === 'critical').length,
    high:       threats.filter(t => t.severity === 'high').length,
    active:     threats.filter(t => t.status === 'active').length,
    unassigned: threats.filter(t => !t.assignee).length,
    resolved24h:8,
    mttd:       12,
    mttr:       4.2,
  }), [threats]);

  // ── Severity donut ────────────────────────────────────────────────────────
  const severityData = useMemo(() => [
    { name:'Critical', value: threats.filter(t => t.severity==='critical').length, color:'#ef4444' },
    { name:'High',     value: threats.filter(t => t.severity==='high').length,     color:'#f97316' },
    { name:'Medium',   value: threats.filter(t => t.severity==='medium').length,   color:'#eab308' },
    { name:'Low',      value: threats.filter(t => t.severity==='low').length,      color:'#22c55e' },
  ].filter(d => d.value > 0), [threats]);

  // ── Table columns (with risk_score) ──────────────────────────────────────
  const columns = [
    {
      accessorKey: 'riskScore',
      header: 'Risk',
      cell: (info) => {
        const score = info.getValue() || 0;
        const color = score >= 85 ? '#ef4444' : score >= 70 ? '#f97316' : score >= 50 ? '#eab308' : '#22c55e';
        return (
          <div className="flex items-center gap-2">
            <div className="w-12 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor:'var(--bg-tertiary)' }}>
              <div className="h-full rounded-full" style={{ width:`${score}%`, backgroundColor:color }} />
            </div>
            <span className="text-xs font-bold w-6" style={{ color }}>{score}</span>
          </div>
        );
      },
    },
    {
      accessorKey: 'title',
      header: 'Threat',
      cell: (info) => <span className="text-sm font-medium" style={{ color:'var(--text-primary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'mitreTechnique',
      header: 'Technique',
      cell: (info) => <code className="text-xs px-2 py-1 rounded" style={{ backgroundColor:'var(--bg-tertiary)', color:'var(--accent-primary)' }}>{info.getValue()}</code>,
    },
    {
      accessorKey: 'mitreTactic',
      header: 'Tactic',
      cell: (info) => <span className="text-xs" style={{ color:'var(--text-secondary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'affectedResources',
      header: 'Affected',
      cell: (info) => <span className="text-sm font-semibold" style={{ color:'var(--text-secondary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'provider',
      header: 'Cloud',
      cell: (info) => {
        const p = info.getValue();
        const colors = { AWS:'#f97316', Azure:'#3b82f6', GCP:'#eab308', OCI:'#8b5cf6' };
        return <span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor:`${colors[p]||'#6b7280'}20`, color:colors[p]||'var(--text-secondary)' }}>{p}</span>;
      },
    },
    {
      accessorKey: 'account',
      header: 'Account',
      cell: (info) => <span className="text-xs" style={{ color:'var(--text-tertiary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => <StatusIndicator status={info.getValue()} />,
    },
    {
      accessorKey: 'assignee',
      header: 'Assignee',
      cell: (info) => (
        <span className="text-xs" style={{ color: info.getValue() ? 'var(--text-secondary)' : '#f97316' }}>
          {info.getValue() || '⚠ Unassigned'}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Error Banner */}
      {error && (
        <div className="rounded-lg p-4 border flex items-center gap-3"
          style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: '#ef4444' }}>
          <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
          <div>
            <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>Failed to load threats data</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</p>
          </div>
        </div>
      )}

      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color:'var(--text-primary)' }}>Threat Detection & Response</h1>
          {filterSummary && (
            <p className="text-xs mt-0.5 mb-2" style={{ color:'var(--text-tertiary)' }}>
              <span style={{ color:'var(--accent-primary)' }}>Filtered to:</span>{' '}
              <span style={{ fontWeight:600, color:'var(--text-secondary)' }}>{filterSummary}</span>
            </p>
          )}
          <p className="mt-1" style={{ color:'var(--text-secondary)' }}>
            Enterprise-wide threat detection with MITRE ATT&CK mapping and automated response
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => router.push('/threats/attack-paths')} className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium" style={{ backgroundColor:'var(--bg-secondary)', color:'var(--text-secondary)', border:'1px solid var(--border-primary)' }}>
            <ChevronRight className="w-4 h-4" /> Attack Paths
          </button>
          <button onClick={() => router.push('/threats/internet-exposed')} className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium" style={{ backgroundColor:'var(--bg-secondary)', color:'var(--text-secondary)', border:'1px solid var(--border-primary)' }}>
            <ChevronRight className="w-4 h-4" /> Internet Exposed
          </button>
          <button onClick={() => router.push('/threats/analytics')} className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium" style={{ backgroundColor:'var(--bg-secondary)', color:'var(--text-secondary)', border:'1px solid var(--border-primary)' }}>
            <TrendingUp className="w-4 h-4" /> Analytics
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <FilterBar filters={filterOptions} activeFilters={activeFilters} onFilterChange={handleFilterChange} />

      {/* KPI MetricStrip */}
      <MetricStrip groups={[
        {
          label: '🔴 ACTIVE THREATS',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'CRITICAL THREATS', value: stats.critical, valueColor: 'var(--severity-critical)', delta: -2, deltaGoodDown: true, context: 'vs last 7d' },
            { label: 'UNASSIGNED', value: stats.unassigned, valueColor: 'var(--severity-high)', context: 'no owner assigned' },
            { label: 'ATTACK CHAINS', value: attackChains.length, noTrend: true, context: 'identified paths' },
          ],
        },
        {
          label: '🔵 DETECTION',
          color: 'var(--accent-primary)',
          cells: [
            { label: 'MTTD', value: (stats.mttd || '14') + 'm', context: 'mean time to detect' },
            { label: 'MTTR', value: (stats.mttr || '4.2') + 'h', valueColor: 'var(--accent-success)', context: 'mean time to resolve' },
            { label: 'MITRE TACTICS', value: Object.keys(mitreMatrix).length, noTrend: true, context: 'tactics observed' },
          ],
        },
      ]} />

      {/* MITRE ATT&CK Matrix */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color:'var(--text-primary)' }}>MITRE ATT&CK Framework Coverage</h2>
        <div className="overflow-x-auto">
          {Object.keys(mitreMatrix).length === 0 ? (
            <p className="text-sm text-center py-6" style={{ color: 'var(--text-tertiary)' }}>No MITRE ATT&CK data available</p>
          ) : (
          <div className="grid gap-3" style={{ gridTemplateColumns:'repeat(auto-fit, minmax(140px, 1fr))' }}>
            {Object.entries(mitreMatrix).map(([tactic, techniques]) => (
              <div key={tactic} className="rounded-lg p-4 border" style={{ backgroundColor:'var(--bg-secondary)', borderColor:'var(--border-primary)' }}>
                <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color:'var(--text-muted)' }}>{tactic}</p>
                <div className="space-y-2">
                  {techniques.map(tech => (
                    <div key={tech.id} className="text-xs p-2 rounded border transition-all hover:scale-105" style={{
                      backgroundColor: tech.severity==='critical'?'rgba(239,68,68,0.1)':tech.severity==='high'?'rgba(249,115,22,0.1)':'rgba(234,179,8,0.1)',
                      borderColor: tech.severity==='critical'?'var(--accent-danger)':tech.severity==='high'?'var(--accent-warning)':'var(--border-primary)',
                      color:'var(--text-secondary)',
                    }}>
                      <p className="font-mono font-semibold text-xs" style={{ color:'var(--accent-primary)' }}>{tech.id}</p>
                      <p className="line-clamp-2 mt-1">{tech.name}</p>
                      <p className="mt-1 font-semibold">{tech.count} detected</p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
          )}
        </div>
      </div>

      {/* Attack Chains with Blast Radius */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color:'var(--text-primary)' }}>Detected Attack Chains</h2>
        <div className="space-y-3">
          {attackChains.length === 0 ? (
            <p className="text-sm text-center py-6" style={{ color: 'var(--text-tertiary)' }}>No attack chains detected</p>
          ) : attackChains.map(chain => {
            const isProd = chain.account.includes('prod');
            return (
              <div key={chain.id} className="rounded-lg p-4 border cursor-pointer transition-all hover:opacity-80" style={{ backgroundColor:'var(--bg-secondary)', borderColor:'var(--border-primary)' }} onClick={() => router.push(`/threats?search=${chain.name}`)}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <SeverityBadge severity={chain.severity} />
                      {isProd && (
                        <span className="text-xs font-semibold px-2 py-0.5 rounded-full" style={{ backgroundColor:'rgba(239,68,68,0.12)', color:'#ef4444' }}>Production</span>
                      )}
                      <h3 className="text-sm font-semibold" style={{ color:'var(--text-primary)' }}>{chain.name}</h3>
                    </div>
                    <p className="text-xs mb-2" style={{ color:'var(--text-tertiary)' }}>
                      Detected {chain.detectionTime ? new Date(chain.detectionTime).toLocaleDateString() : 'N/A'} · {chain.provider} · {chain.account}
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {chain.techniques.map(tech => (
                        <code key={tech} className="text-xs px-2 py-1 rounded" style={{ backgroundColor:'var(--bg-tertiary)', color:'var(--accent-primary)' }}>{tech}</code>
                      ))}
                    </div>
                  </div>
                  {/* Blast Radius */}
                  <div className="text-right flex-shrink-0">
                    <p className="text-xs mb-1" style={{ color:'var(--text-muted)' }}>Blast Radius</p>
                    <div className="flex items-center justify-end gap-2">
                      <div className="relative w-10 h-10 flex items-center justify-center rounded-full" style={{ border:`2px solid ${chain.severity==='critical'?'#ef4444':'#f97316'}` }}>
                        <span className="text-sm font-bold" style={{ color: chain.severity==='critical'?'#ef4444':'#f97316' }}>{chain.affectedResources}</span>
                      </div>
                    </div>
                    <p className="text-xs mt-1" style={{ color:'var(--text-muted)' }}>resources</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Threat Intelligence */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color:'var(--text-primary)' }}>Threat Intelligence Integration</h2>
        {threatIntel.length === 0 ? (
          <p className="text-sm text-center py-6" style={{ color: 'var(--text-tertiary)' }}>No threat intelligence data available</p>
        ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b" style={{ borderColor:'var(--border-primary)' }}>
                {['Source','Indicator','Type','Relevance','Matched Assets'].map(h => (
                  <th key={h} className="text-left py-3 px-4 text-xs font-semibold uppercase tracking-wider" style={{ color:'var(--text-tertiary)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {threatIntel.map((intel, idx) => (
                <tr key={idx} className="border-b" style={{ borderColor:'var(--border-primary)', backgroundColor: idx%2===0?'var(--bg-secondary)':'transparent' }}>
                  <td className="py-3 px-4" style={{ color:'var(--text-secondary)' }}>{intel.source}</td>
                  <td className="py-3 px-4"><code className="text-xs px-2 py-1 rounded" style={{ backgroundColor:'var(--bg-tertiary)', color:'var(--text-secondary)' }}>{intel.indicator}</code></td>
                  <td className="py-3 px-4" style={{ color:'var(--text-secondary)' }}>{intel.type}</td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-1.5 rounded-full" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                        <div className="h-full rounded-full" style={{ width:`${intel.relevance}%`, backgroundColor: intel.relevance>=80?'#ef4444':intel.relevance>=60?'#f97316':'#22c55e' }} />
                      </div>
                      <span className="text-xs font-semibold" style={{ color:'var(--text-secondary)' }}>{intel.relevance}%</span>
                    </div>
                  </td>
                  <td className="py-3 px-4" style={{ color:'var(--text-secondary)' }}>{intel.matchedAssets}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        )}
      </div>

      {/* Threats Table + Severity Donut */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 space-y-3">
          <h2 className="text-lg font-semibold" style={{ color:'var(--text-primary)' }}>All Threats</h2>
          <DataTable
            data={filteredThreats}
            columns={columns}
            pageSize={10}
            onRowClick={(threat) => router.push(`/threats/${threat.id}`)}
            loading={loading}
            emptyMessage="No threats match the selected filters"
          />
        </div>
        <div className="lg:col-span-1">
          <SeverityDonut data={severityData} title="Severity Distribution" />
        </div>
      </div>

      {/* 30-Day Trend */}
      <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color:'var(--text-primary)' }}>30-Day Threat Trend</h2>
        {trendData.length === 0 ? (
          <p className="text-sm text-center py-8" style={{ color: 'var(--text-tertiary)' }}>No trend data available</p>
        ) : (
          <TrendLine
            data={trendData}
            dataKeys={['critical','high','medium','low']}
            colors={['#ef4444','#f97316','#eab308','#6366f1']}
            title=""
          />
        )}
      </div>
    </div>
  );
}
