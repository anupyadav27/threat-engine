'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Search, ChevronRight, AlertTriangle, Activity } from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import MetricStrip from '@/components/shared/MetricStrip';
import SeverityBadge from '@/components/shared/SeverityBadge';
import DataTable from '@/components/shared/DataTable';


export default function ThreatHuntingPage() {
  const router = useRouter();
  const { provider, account, filterSummary } = useGlobalFilter();
  const [loading, setLoading] = useState(true);
  const [iocs, setIocs] = useState([]);
  const [queries, setQueries] = useState([]);
  const [error, setError] = useState(null);

  // Fetch threat intelligence (IOCs) and hunt queries from the threat engine
  useEffect(() => {
    const fetchIntel = async () => {
      setLoading(true);
      setError(null);
      try {
        const [intelRes, queriesRes] = await Promise.allSettled([
          getFromEngine('threat', '/api/v1/intel'),
          getFromEngine('threat', '/api/v1/hunt/queries'),
        ]);

        if (intelRes.status === 'fulfilled' && intelRes.value && !intelRes.value.error) {
          const result = intelRes.value;
          const raw = Array.isArray(result) ? result : (result.intel || result.iocs || result.results || result.indicators || []);
          setIocs(raw.map((item, idx) => ({
            ioc_id:         item.ioc_id || item.id || `ioc-${idx}`,
            type:           item.indicator_type || item.type || 'Unknown',
            value:          item.indicator_value || item.value || item.indicator || '',
            source:         item.source || item.feed || 'Threat Intel',
            severity:       (item.severity || item.risk_level || 'info').toLowerCase(),
            matched_assets: item.matched_assets || item.matches || 0,
            last_seen:      item.last_seen || item.updated_at || new Date().toISOString(),
            status:         item.status || 'active',
          })));
        }

        if (queriesRes.status === 'fulfilled' && queriesRes.value && !queriesRes.value.error) {
          const raw = Array.isArray(queriesRes.value) ? queriesRes.value : (queriesRes.value.queries || queriesRes.value.results || []);
          setQueries(raw);
        }

        if (
          (intelRes.status !== 'fulfilled' || !intelRes.value || intelRes.value.error) &&
          (queriesRes.status !== 'fulfilled' || !queriesRes.value || queriesRes.value.error)
        ) {
          setError('Failed to load threat hunting data.');
        }
      } catch (err) {
        console.warn('Could not fetch threat hunting data:', err);
        setError('Failed to load threat hunting data.');
      } finally {
        setLoading(false);
      }
    };
    fetchIntel();
  }, []);

  const activeIocs = iocs.filter((i) => i.status === 'active').length;
  const criticalIocs = iocs.filter((i) => i.severity === 'critical').length;
  const matchedAssets = iocs.reduce((sum, i) => sum + i.matched_assets, 0);

  const iocColumns = [
    { accessorKey: 'type', header: 'Type', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'value', header: 'Indicator', cell: (info) => <code className="text-xs" style={{ color: 'var(--accent-primary)' }}>{info.getValue()}</code> },
    { accessorKey: 'source', header: 'Source', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{info.getValue()}</span> },
    { accessorKey: 'severity', header: 'Severity', cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    { accessorKey: 'matched_assets', header: 'Matches', cell: (info) => <span className="text-sm font-bold" style={{ color: info.getValue() > 0 ? 'var(--accent-danger)' : 'var(--text-muted)' }}>{info.getValue()}</span> },
    { accessorKey: 'last_seen', header: 'Last Seen', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{new Date(info.getValue()).toLocaleDateString()}</span> },
  ];

  const queryColumns = [
    { accessorKey: 'name', header: 'Hunt Query', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'description', header: 'Description', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'findings', header: 'Findings', cell: (info) => <span className="text-sm font-bold" style={{ color: info.getValue() > 0 ? 'var(--accent-warning)' : 'var(--accent-success)' }}>{info.getValue()}</span> },
    { accessorKey: 'last_run', header: 'Last Run', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{new Date(info.getValue()).toLocaleDateString()}</span> },
    { accessorKey: 'status', header: 'Status', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'rgba(16,185,129,0.1)', color: 'var(--accent-success)' }}>{info.getValue()}</span> },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <button onClick={() => router.push('/threats')} className="text-sm" style={{ color: 'var(--text-muted)' }}>Threats</button>
        <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Threat Hunting</h1>
      </div>
      {filterSummary && (
        <p className="text-xs mt-0.5 mb-2" style={{ color:'var(--text-tertiary)' }}>
          <span style={{ color:'var(--accent-primary)' }}>Filtered to:</span>{' '}
          <span style={{ fontWeight:600, color:'var(--text-secondary)' }}>{filterSummary}</span>
        </p>
      )}

      {/* Error state */}
      {error && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: '#ef4444' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      )}

      <MetricStrip groups={[
        {
          label: '🔴 INTEL',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'ACTIVE IOCs', value: activeIocs, valueColor: 'var(--severity-critical)', context: 'indicators of compromise' },
            { label: 'CRITICAL IOCs', value: criticalIocs, valueColor: 'var(--severity-critical)', context: 'severity: critical' },
            { label: 'MATCHED ASSETS', value: matchedAssets, valueColor: 'var(--severity-high)', context: 'assets affected' },
          ],
        },
        {
          label: '🔵 HUNT STATUS',
          color: 'var(--accent-primary)',
          cells: [
            { label: 'HUNT QUERIES', value: queries.length, noTrend: true, context: 'active hunts' },
            { label: 'CONFIRMED HITS', value: 12, valueColor: 'var(--accent-success)', noTrend: true, context: 'validated' },
            { label: 'FALSE POS RATE', value: '8%', noTrend: true, context: 'of all hits' },
          ],
        },
      ]} />

      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Threat Intelligence Indicators (IOCs)</h2>
        <DataTable columns={iocColumns} data={iocs} />
      </div>

      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Hunt Queries</h2>
        <DataTable columns={queryColumns} data={queries} />
      </div>
    </div>
  );
}
