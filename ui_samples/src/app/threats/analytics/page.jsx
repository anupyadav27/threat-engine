'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { TrendingUp, ChevronRight, Activity, AlertTriangle } from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import MetricStrip from '@/components/shared/MetricStrip';
import SeverityDonut from '@/components/charts/SeverityDonut';
import TrendLine from '@/components/charts/TrendLine';
import BarChartComponent from '@/components/charts/BarChartComponent';


export default function ThreatAnalyticsPage() {
  const router = useRouter();
  const { provider, account, filterSummary } = useGlobalFilter();
  const [loading, setLoading] = useState(true);
  const [distribution, setDistribution] = useState(null);
  const [trendData, setTrendData] = useState([]);
  const [topServices, setTopServices] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const [distRes, trendRes, servicesRes] = await Promise.allSettled([
          getFromEngine('threat', '/api/v1/threat/analytics/distribution', { scan_run_id: 'latest' }),
          getFromEngine('threat', '/api/v1/threat/analytics/trend'),
          getFromEngine('threat', '/api/v1/threat/analytics/top-services'),
        ]);
        if (distRes.status === 'fulfilled' && distRes.value && !distRes.value.error) {
          setDistribution(distRes.value);
        }
        if (trendRes.status === 'fulfilled' && trendRes.value && !trendRes.value.error && Array.isArray(trendRes.value)) {
          setTrendData(trendRes.value);
        }
        if (servicesRes.status === 'fulfilled' && servicesRes.value && !servicesRes.value.error && Array.isArray(servicesRes.value)) {
          setTopServices(servicesRes.value);
        }
        if (
          (distRes.status !== 'fulfilled' || !distRes.value || distRes.value.error) &&
          (trendRes.status !== 'fulfilled' || !trendRes.value || trendRes.value.error)
        ) {
          setError('Failed to load threat analytics data.');
        }
      } catch {
        setError('Failed to load threat analytics data.');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const total = distribution
    ? (distribution.critical || 0) + (distribution.high || 0) + (distribution.medium || 0) + (distribution.low || 0)
    : 0;

  const barData = topServices.map((s) => ({
    name: s.name,
    critical: s.critical,
    high: s.high,
  }));

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <button onClick={() => router.push('/threats')} className="text-sm" style={{ color: 'var(--text-muted)' }}>Threats</button>
        <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Threat Analytics</h1>
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
          label: '🔴 THREAT VOLUME',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'TOTAL ACTIVE', value: total ?? distribution?.total ?? 0, valueColor: 'var(--severity-critical)', delta: +12, deltaGoodDown: true, context: 'vs last 7d' },
            { label: 'CRITICAL + HIGH', value: (distribution?.critical ?? 0) + (distribution?.high ?? 0), valueColor: 'var(--severity-critical)', context: 'combined' },
            { label: 'NEW THIS WEEK', value: 18, valueColor: 'var(--severity-high)', noTrend: true, context: 'last 7 days' },
          ],
        },
        {
          label: '🔵 TREND',
          color: 'var(--accent-primary)',
          cells: [
            { label: 'RESOLVED/WEEK', value: 23, valueColor: 'var(--accent-success)', noTrend: true, context: 'last 7 days' },
            { label: 'AVG MTTD', value: '14m', context: 'mean detection time' },
            { label: 'TOP TACTIC', value: 'Exfiltration', noTrend: true, context: 'most observed' },
          ],
        },
      ]} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Severity Distribution</h2>
          {loading ? (
            <div className="h-48 animate-pulse rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
          ) : distribution ? (
            <SeverityDonut data={distribution} />
          ) : (
            <p className="text-sm text-center py-12" style={{ color: 'var(--text-muted)' }}>No distribution data available</p>
          )}
        </div>

        <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Top Affected Services</h2>
          {loading ? (
            <div className="h-48 animate-pulse rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
          ) : barData.length > 0 ? (
            <BarChartComponent data={barData} dataKeys={['critical', 'high']} xKey="name" />
          ) : (
            <p className="text-sm text-center py-12" style={{ color: 'var(--text-muted)' }}>No service data available</p>
          )}
        </div>
      </div>

      <div className="rounded-xl p-6 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>30-Day Threat Trend</h2>
        {loading ? (
          <div className="h-64 animate-pulse rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        ) : trendData.length > 0 ? (
          <TrendLine data={trendData} dataKeys={['critical', 'high', 'medium']} xKey="date" />
        ) : (
          <p className="text-sm text-center py-16" style={{ color: 'var(--text-muted)' }}>No trend data available</p>
        )}
      </div>
    </div>
  );
}
