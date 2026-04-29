'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { GitBranch, ChevronRight, ArrowRight, Database, AlertTriangle } from 'lucide-react';
import { getFromEngineScan } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import DataTable from '@/components/shared/DataTable';


function RiskColor(risk) {
  const map = { critical: 'var(--accent-danger)', high: 'var(--accent-warning)', medium: '#f59e0b', low: 'var(--accent-success)' };
  return map[risk] || 'var(--text-muted)';
}

function LineageFlowCard({ chain }) {
  const allSteps = [chain.source, ...chain.transforms, chain.sink];

  return (
    <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={chain.risk} />
          <code className="text-xs" style={{ color: 'var(--text-muted)' }}>{chain.chain_id}</code>
        </div>
        <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
          {chain.cross_region && (
            <span className="px-2 py-0.5 rounded" style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: 'var(--accent-danger)' }}>
              Cross-Region
            </span>
          )}
          {!chain.encryption_in_transit && (
            <span className="px-2 py-0.5 rounded" style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: 'var(--accent-danger)' }}>
              No Transit Encryption
            </span>
          )}
          {!chain.encryption_at_rest && (
            <span className="px-2 py-0.5 rounded" style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: 'var(--accent-danger)' }}>
              No At-Rest Encryption
            </span>
          )}
          <span>{(chain.records_per_day || 0).toLocaleString()} records/day</span>
        </div>
      </div>

      {/* Flow diagram */}
      <div className="flex items-center gap-1 flex-wrap">
        {/* Source */}
        <div className="flex flex-col items-center">
          <div className="rounded-lg px-3 py-2 border" style={{ borderColor: 'var(--accent-primary)', backgroundColor: 'rgba(59,130,246,0.08)' }}>
            <p className="text-xs font-medium" style={{ color: 'var(--accent-primary)' }}>{chain.source.name}</p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{chain.source.type}</p>
          </div>
          <span className="text-xs mt-1 px-1 rounded" style={{ backgroundColor: 'rgba(16,185,129,0.1)', color: 'var(--accent-success)' }}>
            {chain.source.classification}
          </span>
        </div>

        {/* Transforms */}
        {chain.transforms.map((t, i) => (
          <div key={i} className="flex items-center gap-1">
            <ArrowRight className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
            <div className="flex flex-col items-center">
              <div className="rounded-lg px-3 py-2 border" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-card)' }}>
                <p className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>{t.name}</p>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{t.type}</p>
              </div>
              <span className="text-xs mt-1 px-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
                {t.action}
              </span>
            </div>
          </div>
        ))}

        {/* Sink */}
        <div className="flex items-center gap-1">
          <ArrowRight className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
          <div className="flex flex-col items-center">
            <div className="rounded-lg px-3 py-2 border" style={{ borderColor: chain.risk === 'critical' ? 'var(--accent-danger)' : 'var(--border-primary)', backgroundColor: chain.risk === 'critical' ? 'rgba(239,68,68,0.08)' : 'var(--bg-card)' }}>
              <p className="text-xs font-medium" style={{ color: chain.risk === 'critical' ? 'var(--accent-danger)' : 'var(--text-secondary)' }}>{chain.sink.name}</p>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{chain.sink.type}</p>
            </div>
            <span className="text-xs mt-1 px-1 rounded" style={{ backgroundColor: chain.sink.classification === 'Unknown' ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)', color: chain.sink.classification === 'Unknown' ? 'var(--accent-danger)' : 'var(--accent-success)' }}>
              {chain.sink.classification}
            </span>
          </div>
        </div>
      </div>

      {/* Data types */}
      <div className="mt-3 flex items-center gap-2 flex-wrap">
        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Data types:</span>
        {chain.data_types.map((dt) => (
          <span key={dt} className="text-xs px-2 py-0.5 rounded font-mono" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
            {dt}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function DataLineagePage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [chains, setChains] = useState([]);
  const [riskFilter, setRiskFilter] = useState('All');

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const res = await getFromEngineScan('datasec', '/api/v1/data-security/lineage');
        if (res && !res.error && res.lineage_chains) {
          setChains(res.lineage_chains);
        }
      } catch (err) {
        console.warn('[lineage] fetch error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const criticalChains = chains.filter((c) => c.risk === 'critical').length;
  const highChains = chains.filter((c) => c.risk === 'high').length;
  const unencrypted = chains.filter((c) => !c.encryption_at_rest || !c.encryption_in_transit).length;

  const filtered = riskFilter === 'All' ? chains : chains.filter((c) => c.risk === riskFilter);

  const tableColumns = [
    { accessorKey: 'chain_id', header: 'Chain ID', cell: (info) => <code className="text-xs" style={{ color: 'var(--accent-primary)' }}>{info.getValue()}</code> },
    { accessorKey: 'risk', header: 'Risk', cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    {
      accessorKey: 'source',
      header: 'Source',
      cell: (info) => {
        const s = info.getValue();
        return <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{s?.name}</span>;
      },
    },
    {
      accessorKey: 'sink',
      header: 'Sink',
      cell: (info) => {
        const s = info.getValue();
        return <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{s?.name}</span>;
      },
    },
    {
      accessorKey: 'records_per_day',
      header: 'Volume',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-muted)' }}>{(info.getValue() || 0).toLocaleString()}/day</span>,
    },
    {
      accessorKey: 'encryption_at_rest',
      header: 'Encrypted',
      cell: (info) => {
        const row = info.row.original;
        const ok = row.encryption_at_rest && row.encryption_in_transit;
        return (
          <span className="text-xs" style={{ color: ok ? 'var(--accent-success)' : 'var(--accent-danger)' }}>
            {ok ? 'Yes' : 'Partial/No'}
          </span>
        );
      },
    },
    {
      accessorKey: 'cross_region',
      header: 'Cross-Region',
      cell: (info) => (
        <span className="text-xs" style={{ color: info.getValue() ? 'var(--accent-warning)' : 'var(--text-muted)' }}>
          {info.getValue() ? 'Yes' : 'No'}
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <button onClick={() => router.push('/datasec')} className="text-sm" style={{ color: 'var(--text-muted)' }}>Data Security</button>
        <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Data Lineage</h1>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Pipelines" value={chains.length} subtitle="Data flow chains" icon={<GitBranch className="w-5 h-5" />} color="blue" />
        <KpiCard title="Critical Risk" value={criticalChains} subtitle="Immediate attention" icon={<AlertTriangle className="w-5 h-5" />} color="red" />
        <KpiCard title="High Risk" value={highChains} subtitle="High exposure" icon={<AlertTriangle className="w-5 h-5" />} color="orange" />
        <KpiCard title="Unencrypted" value={unencrypted} subtitle="Missing encryption" icon={<Database className="w-5 h-5" />} color="red" />
      </div>

      {/* Flow Diagrams */}
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Data Flow Diagrams</h2>
          <div className="flex gap-2">
            {['All', 'critical', 'high', 'medium', 'low'].map((r) => (
              <button
                key={r}
                onClick={() => setRiskFilter(r)}
                className="text-xs px-3 py-1 rounded-full border capitalize"
                style={{
                  backgroundColor: riskFilter === r ? 'var(--accent-primary)' : 'transparent',
                  color: riskFilter === r ? 'white' : 'var(--text-secondary)',
                  borderColor: riskFilter === r ? 'var(--accent-primary)' : 'var(--border-primary)',
                }}
              >
                {r}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="space-y-4">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-32 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
            ))}
          </div>
        ) : (
          <div className="space-y-4">
            {filtered.map((chain) => (
              <LineageFlowCard key={chain.chain_id} chain={chain} />
            ))}
          </div>
        )}
      </div>

      {/* Summary Table */}
      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Pipeline Summary</h2>
        {loading ? (
          <div className="h-48 animate-pulse rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        ) : (
          <DataTable columns={tableColumns} data={chains} />
        )}
      </div>
    </div>
  );
}
