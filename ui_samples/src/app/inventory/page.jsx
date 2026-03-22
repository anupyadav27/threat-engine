'use client';

import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  Server,
  AlertTriangle,
  Database,
  Cloud,
  Lock,
  Search,
  Download,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Zap,
  KeyRound,
  Network,
  Shield,
  Box,
  HardDrive,
  Globe,
  MessageSquare,
  Activity,
  ClipboardCheck,
  Brain,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { RESOURCE_DOMAINS, classifyResourceDomain } from '@/lib/inventory-taxonomy';
import MetricStrip from '@/components/shared/MetricStrip';
import DataTable from '@/components/shared/DataTable';
import FilterBar from '@/components/shared/FilterBar';
import SeverityBadge from '@/components/shared/SeverityBadge';
import StatusIndicator from '@/components/shared/StatusIndicator';
import SeverityDonut from '@/components/charts/SeverityDonut';

const DOMAIN_ICON_MAP = {
  KeyRound, Network, Shield, Server, Box, Zap, HardDrive, Database,
  Lock, Globe, MessageSquare, Activity, ClipboardCheck, Brain,
};


export default function InventoryPage() {
  const router = useRouter();
  const { provider, account, region, filterSummary } = useGlobalFilter();
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filters, setFilters] = useState({
    service: '',
    compliance_status: '',
    risk_level: '',
    environment: '',
  });

  // BFF handles scope filtering — scopeFiltered is now just assets
  const scopeFiltered = assets;

  // Fetch assets and summary via BFF
  useEffect(() => {
    const loadAssets = async () => {
      setLoading(true);
      try {
        const data = await fetchView('inventory', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (data.error) { setError(data.error); return; }
        if (data.assets) setAssets(data.assets);
        if (data.summary) setSummary(data.summary);
      } catch (err) {
        console.warn('[inventory] loadAssets error:', err);
        setError('Failed to load inventory data');
      } finally {
        setLoading(false);
      }
    };

    loadAssets();
  }, [provider, account, region]);

  // Filter and search assets (starts from scope-filtered set)
  const filteredAssets = useMemo(() => {
    return scopeFiltered.filter((asset) => {
      const search = searchTerm.toLowerCase();
      const matchesSearch = !searchTerm ||
        (asset.resource_name || '').toLowerCase().includes(search) ||
        (asset.resource_id || '').toLowerCase().includes(search) ||
        (asset.owner || '').toLowerCase().includes(search);

      if (!matchesSearch) return false;
      if (filters.service && asset.service !== filters.service) return false;

      if (filters.risk_level) {
        const riskLevel = getRiskLevel(asset.risk_score);
        if (riskLevel !== filters.risk_level) return false;
      }

      if (filters.environment) {
        const env = asset.tags?.Environment;
        if (env !== filters.environment) return false;
      }

      return true;
    });
  }, [scopeFiltered, filters, searchTerm]);

  // Helper function to get risk level
  const getRiskLevel = (score) => {
    if (score >= 70) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
  };

  // Calculate KPI metrics from scope-filtered set
  const totalAssets = scopeFiltered.length;
  const newThisWeek = scopeFiltered.filter(
    (a) =>
      new Date(a.created_at) >
      new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
  ).length;
  const unmanagedCount = scopeFiltered.filter((a) => !a.tags || Object.keys(a.tags).length === 0).length;
  const unmanagedAssets = unmanagedCount;
  const publiclyExposedAssets = scopeFiltered.filter((a) => a.risk_score > 70).length;
  const nonCompliantAssets = scopeFiltered.filter((a) => a.findings && (a.findings.critical > 0 || a.findings.high > 0))
    .length;
  const criticalFindingsAssets = scopeFiltered.filter((a) => a.findings && a.findings.critical > 0).length;
  const awsAssets = scopeFiltered.filter((a) => a.provider === 'aws').length;
  const azureAssets = scopeFiltered.filter((a) => a.provider === 'azure').length;
  const gcpAssets = scopeFiltered.filter((a) => a.provider === 'gcp').length;
  const multiCloudCount = [
    awsAssets > 0 ? 1 : 0,
    azureAssets > 0 ? 1 : 0,
    gcpAssets > 0 ? 1 : 0,
  ].reduce((a, b) => a + b, 0);
  const driftDetected = summary?.total_drift ?? scopeFiltered.filter((a) => a.risk_score > 60).length;

  // MetricStrip computed values
  const exposedCount = scopeFiltered.filter((a) => a.internet_exposed === true || a.public === true || a.risk_score > 70).length;
  const criticalCount = scopeFiltered.filter((a) => a.severity === 'critical' || a.risk_level === 'critical' || (a.findings && a.findings.critical > 0)).length;
  const driftCount = summary?.total_drift ?? 0;
  const uniqueProviders = new Set(scopeFiltered.map((r) => r.provider)).size;

  // Get unique values for filters
  const services = Array.from(new Set(assets.map((a) => a.service).filter(Boolean)))
    .sort()
    .map((service) => ({ value: service, label: service.toUpperCase() }));

  const environments = ['prod', 'staging', 'dev'];

  // Dynamic domain breakdown from taxonomy
  const domainBreakdown = useMemo(() => {
    const counts = {};
    const findings = {};
    scopeFiltered.forEach((asset) => {
      const domain = classifyResourceDomain(asset.resource_type || asset.service);
      const key = domain.key;
      counts[key] = (counts[key] || 0) + 1;
      if (!findings[key]) findings[key] = { critical: 0, high: 0 };
      findings[key].critical += asset.findings?.critical || 0;
      findings[key].high += asset.findings?.high || 0;
    });
    return Object.entries(RESOURCE_DOMAINS)
      .map(([key, meta]) => ({
        key,
        ...meta,
        count: counts[key] || 0,
        findings: findings[key] || { critical: 0, high: 0 },
      }))
      .filter((d) => d.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [scopeFiltered]);

  // Table columns — essential CSPM inventory view
  const columns = [
    {
      accessorKey: 'provider',
      header: 'Provider',
      size: 90,
      cell: (info) => {
        const icons = { aws: '🟠', azure: '🔵', gcp: '🔴', oci: '🟡', alicloud: '🟤', ibm: '⚪' };
        const v = info.getValue() || '';
        return (
          <span className="text-xs font-medium whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
            {icons[v] || '☁️'} {v.toUpperCase()}
          </span>
        );
      },
    },
    {
      accessorKey: 'account_id',
      header: 'Account',
      size: 120,
      cell: (info) => (
        <span className="text-xs font-mono whitespace-nowrap" style={{ color: 'var(--text-tertiary)' }}>
          {info.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'region',
      header: 'Region',
      size: 110,
      cell: (info) => (
        <span className="text-xs whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue() || '—'}
        </span>
      ),
    },
    {
      accessorKey: 'resource_name',
      header: 'Resource',
      cell: (info) => {
        const row = info.row.original;
        const raw = info.getValue() || row.name || row.resource_uid || '';
        // When name == uid, extract a short label from the last segment
        const name = (raw === row.resource_uid && raw.includes(':'))
          ? raw.split(':').pop() || raw.split(':').slice(-2).join(':')
          : raw;
        const rtype = (row.resource_type || '').replace('.', ' · ');
        const status = (row.status || 'active').toLowerCase();
        const dotColor = status === 'active' || status === 'running'
          ? 'var(--accent-success)'
          : status === 'stopped' ? 'var(--accent-warning)' : 'var(--text-tertiary)';
        return (
          <div className="flex items-start gap-2">
            <div className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0" style={{ backgroundColor: dotColor }} title={status} />
            <div>
              <div className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>{name}</div>
              <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{rtype}</div>
            </div>
          </div>
        );
      },
    },
    {
      accessorKey: 'internet_exposed',
      header: 'Exposure',
      size: 85,
      cell: (info) => {
        const exposed = info.getValue();
        const row = info.row.original;
        const isPublic = exposed === true || row.public === true || row.internet_exposure?.exposed === true;
        if (!isPublic) return null;
        const expType = row.internet_exposure?.type;
        const label = expType === 'public_bucket' ? 'Public'
          : expType === 'function_url' ? 'Fn URL'
          : expType === 'public_api' ? 'API'
          : 'Exposed';
        return (
          <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full"
            style={{ backgroundColor: '#ef444420', color: '#ef4444' }}>
            {label}
          </span>
        );
      },
    },
    {
      accessorKey: 'findings',
      header: 'Findings',
      size: 90,
      cell: (info) => {
        const f = info.getValue();
        if (!f || (!f.critical && !f.high && !f.medium && !f.low)) {
          return (
            <span className="flex items-center gap-1.5 text-xs whitespace-nowrap" style={{ color: 'var(--accent-success)' }}>
              <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: 'var(--accent-success)' }} />
              Clean
            </span>
          );
        }
        return (
          <div className="flex gap-1 flex-wrap">
            {f.critical > 0 && <SeverityBadge severity="critical" count={f.critical} />}
            {f.high > 0 && <SeverityBadge severity="high" count={f.high} />}
            {f.medium > 0 && <SeverityBadge severity="medium" count={f.medium} />}
            {f.low > 0 && <SeverityBadge severity="low" count={f.low} />}
          </div>
        );
      },
    },
    {
      accessorKey: 'last_scanned',
      header: 'Last Seen',
      size: 95,
      cell: (info) => {
        const val = info.getValue();
        if (!val) return <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>—</span>;
        const date = new Date(val);
        const hoursAgo = Math.floor((Date.now() - date) / (1000 * 60 * 60));
        const daysAgo = Math.floor(hoursAgo / 24);
        let label;
        if (hoursAgo < 1) label = 'Just now';
        else if (hoursAgo < 24) label = `${hoursAgo}h ago`;
        else if (daysAgo < 30) label = `${daysAgo}d ago`;
        else label = date.toLocaleDateString();
        return (
          <span className="text-xs whitespace-nowrap" style={{ color: daysAgo > 30 ? 'var(--accent-warning)' : 'var(--text-tertiary)' }}>
            {label}
          </span>
        );
      },
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
            <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>Failed to load inventory data</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</p>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Cloud Asset Inventory
          </h1>
          <p className="mt-1" style={{ color: 'var(--text-tertiary)' }}>
            Discover and manage assets across your multi-cloud environment
          </p>
          {filterSummary && (
            <p className="text-xs mt-0.5 mb-2" style={{ color: 'var(--text-tertiary)' }}>
              <span style={{ color: 'var(--accent-primary)' }}>Filtered to:</span>{' '}
              <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{filterSummary}</span>
            </p>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => router.push('/inventory/architecture')}
            className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors"
            style={{
              backgroundColor: 'var(--accent-primary)',
              color: 'white',
            }}
          >
            <Network className="w-4 h-4" />
            Architecture View
          </button>
          <button
            onClick={() => router.push('/inventory/graph')}
            className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
            }}
          >
            <Network className="w-4 h-4" />
            Graph (v1)
          </button>
          <button
            className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
            }}
          >
            <Download className="w-4 h-4" />
            Export
          </button>
          <button
            className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              color: 'var(--text-secondary)',
            }}
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Asset Discovery Strip */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'New Resources', value: `+${newThisWeek}`, sub: 'Discovered this week', color: '#22c55e', icon: <TrendingUp className="w-4 h-4" /> },
          { label: 'Removed',       value: `${summary?.removed_assets ?? 0}`,  sub: 'Terminated this week',  color: '#ef4444', icon: <TrendingDown className="w-4 h-4" /> },
          { label: 'Drifted',       value: `${summary?.total_drift ?? 0}`,  sub: 'Config changed vs baseline', color: '#f97316', icon: <AlertTriangle className="w-4 h-4" /> },
        ].map(s => (
          <div key={s.label} className="flex items-center gap-3 rounded-xl p-4 border transition-colors duration-200"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: s.color + '60' }}>
            <div className="p-2 rounded-lg" style={{ backgroundColor: s.color + '20' }}>
              <span style={{ color: s.color }}>{s.icon}</span>
            </div>
            <div>
              <p className="text-xl font-bold" style={{ color: s.color }}>{s.value}</p>
              <p className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>{s.label}</p>
              <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{s.sub}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Stale Assets Banner */}
      {(() => {
        const staleCount = scopeFiltered.filter(a => {
          const lastSeen = new Date(a.last_scanned);
          return (Date.now() - lastSeen) > 30 * 24 * 60 * 60 * 1000;
        }).length;
        return staleCount > 0 ? (
          <div className="flex items-center gap-3 rounded-xl p-4 border" style={{ backgroundColor: '#92400e18', borderColor: '#d97706' }}>
            <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#f59e0b' }} />
            <div className="flex-1">
              <span className="text-sm font-semibold" style={{ color: '#fbbf24' }}>{staleCount} resources last seen &gt;30 days ago — may be orphaned. </span>
              <span className="text-xs" style={{ color: '#fcd34d' }}>Review in the asset table below to identify candidates for decommission.</span>
            </div>
          </div>
        ) : null;
      })()}

      {/* KPI MetricStrip */}
      <MetricStrip groups={[
        {
          label: '🔴 EXPOSURE RISK',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'EXPOSED ASSETS', value: exposedCount, valueColor: 'var(--severity-critical)', delta: +8, deltaGoodDown: true, context: 'internet-facing' },
            { label: 'CRITICAL FINDINGS', value: criticalCount, valueColor: 'var(--severity-critical)', delta: -23, deltaGoodDown: true, context: 'vs last 7d' },
            { label: 'DRIFT EVENTS', value: driftCount, valueColor: 'var(--severity-high)', context: 'config changes' },
          ],
        },
        {
          label: '🔵 COVERAGE',
          color: 'var(--accent-primary)',
          cells: [
            { label: 'TOTAL RESOURCES', value: scopeFiltered.length },
            { label: 'UNMANAGED', value: unmanagedCount, valueColor: 'var(--severity-high)', context: 'no tags/owner' },
            { label: 'PROVIDERS', value: `${uniqueProviders}/6`, noTrend: true, context: 'cloud providers' },
          ],
        },
      ]} />

      {/* Resource Domain Summary Cards */}
      <div>
        <h2 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
          Resource Domains
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
          {domainBreakdown.map((domain) => {
            const Icon = DOMAIN_ICON_MAP[domain.iconName] || Server;
            return (
              <div
                key={domain.key}
                className="rounded-lg p-3 border cursor-pointer transition-all duration-150"
                style={{
                  backgroundColor: 'var(--bg-card)',
                  borderColor: 'var(--border-primary)',
                  borderLeftWidth: 3,
                  borderLeftColor: domain.color,
                }}
                onClick={() => setFilters({ ...filters, service: '' })}
                onMouseEnter={(e) => { e.currentTarget.style.borderColor = domain.color; }}
                onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border-primary)'; e.currentTarget.style.borderLeftColor = domain.color; }}
              >
                <div className="flex items-center gap-2 mb-2">
                  <div className="p-1.5 rounded" style={{ backgroundColor: domain.color + '18' }}>
                    <Icon className="w-4 h-4" style={{ color: domain.color }} />
                  </div>
                  <span className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>{domain.count}</span>
                </div>
                <p className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>{domain.label}</p>
                {(domain.findings.critical > 0 || domain.findings.high > 0) && (
                  <div className="flex gap-1 mt-1.5">
                    {domain.findings.critical > 0 && (
                      <span className="text-[10px] font-medium px-1.5 py-0.5 rounded" style={{ backgroundColor: '#ef444420', color: '#ef4444' }}>
                        {domain.findings.critical}C
                      </span>
                    )}
                    {domain.findings.high > 0 && (
                      <span className="text-[10px] font-medium px-1.5 py-0.5 rounded" style={{ backgroundColor: '#f9731620', color: '#f97316' }}>
                        {domain.findings.high}H
                      </span>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Asset Lifecycle Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div
          className="lg:col-span-2 rounded-lg p-6 border"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
            Asset Status Distribution
          </h3>
          <div className="space-y-3">
            {(() => {
              const total = scopeFiltered.length || 1;
              const statusCounts = scopeFiltered.reduce((acc, a) => {
                const s = (a.status || 'active').toLowerCase();
                acc[s] = (acc[s] || 0) + 1;
                return acc;
              }, {});
              const statusColors = { active: 'var(--accent-success)', running: 'var(--accent-success)', stopped: 'var(--accent-warning)', terminated: 'var(--accent-danger)', deprecated: 'var(--accent-danger)', 'pending deletion': '#6b7280', unknown: '#9ca3af' };
              return Object.entries(statusCounts)
                .sort(([,a],[,b]) => b - a)
                .map(([label, count]) => ({
                  label: label.charAt(0).toUpperCase() + label.slice(1),
                  value: Math.round((count / total) * 100),
                  color: statusColors[label] || '#9ca3af',
                }));
            })().map((item) => (
              <div key={item.label}>
                <div className="flex items-center justify-between mb-2">
                  <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                  <span style={{ color: 'var(--text-primary)' }} className="font-semibold">
                    {item.value}%
                  </span>
                </div>
                <div
                  className="w-full h-2 rounded-full overflow-hidden"
                  style={{ backgroundColor: 'var(--bg-tertiary)' }}
                >
                  <div
                    className="h-full"
                    style={{ width: `${item.value}%`, backgroundColor: item.color }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Provider Distribution */}
        <div
          className="rounded-lg p-6 border"
          style={{
            backgroundColor: 'var(--bg-card)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
            Multi-Cloud Distribution
          </h3>
          <div className="space-y-3">
            {[
              { label: 'AWS', count: awsAssets, icon: '🟠' },
              { label: 'Azure', count: azureAssets, icon: '🔵' },
              { label: 'GCP', count: gcpAssets, icon: '🔴' },
            ].map((provider) => (
              <div key={provider.label}>
                <div className="flex items-center justify-between mb-1">
                  <span style={{ color: 'var(--text-secondary)' }}>
                    {provider.icon} {provider.label}
                  </span>
                  <span
                    style={{ color: 'var(--text-primary)' }}
                    className="font-semibold"
                  >
                    {provider.count}
                  </span>
                </div>
                <div
                  className="w-full h-2 rounded-full overflow-hidden"
                  style={{ backgroundColor: 'var(--bg-tertiary)' }}
                >
                  <div
                    className="h-full"
                    style={{
                      width: `${(provider.count / totalAssets) * 100}%`,
                      backgroundColor:
                        provider.label === 'AWS'
                          ? '#ff9900'
                          : provider.label === 'Azure'
                            ? '#0078d4'
                            : '#4285f4',
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Shadow IT / Unmanaged Assets */}
      <div
        className="rounded-lg p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Shadow IT & Unmanaged Assets
          </h3>
          <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">
            {unmanagedAssets} resources
          </span>
        </div>
        {unmanagedAssets > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr style={{ borderBottomColor: 'var(--border-primary)' }} className="border-b">
                  <th
                    className="text-left py-2 px-4 font-semibold"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Resource
                  </th>
                  <th
                    className="text-left py-2 px-4 font-semibold"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Type
                  </th>
                  <th
                    className="text-left py-2 px-4 font-semibold"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Provider
                  </th>
                  <th
                    className="text-left py-2 px-4 font-semibold"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Risk
                  </th>
                </tr>
              </thead>
              <tbody>
                {assets
                  .filter((a) => !a.tags || Object.keys(a.tags).length === 0)
                  .slice(0, 5)
                  .map((asset) => (
                    <tr
                      key={asset.resource_id}
                      style={{ borderBottomColor: 'var(--border-primary)' }}
                      className="border-b hover:bg-opacity-50"
                      style={{ backgroundColor: 'transparent' }}
                    >
                      <td
                        className="py-3 px-4"
                        style={{ color: 'var(--text-secondary)' }}
                      >
                        {asset.resource_name}
                      </td>
                      <td
                        className="py-3 px-4"
                        style={{ color: 'var(--text-tertiary)' }}
                      >
                        {asset.resource_type}
                      </td>
                      <td
                        className="py-3 px-4"
                        style={{ color: 'var(--text-secondary)' }}
                      >
                        {(asset.provider || '').toUpperCase()}
                      </td>
                      <td
                        className="py-3 px-4 font-semibold"
                        style={{
                          color:
                            asset.risk_score >= 70
                              ? 'var(--accent-danger)'
                              : asset.risk_score >= 50
                                ? 'var(--accent-warning)'
                                : 'var(--accent-success)',
                        }}
                      >
                        {asset.risk_score}%
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div
            className="text-center py-8"
            style={{ color: 'var(--text-tertiary)' }}
          >
            No unmanaged assets detected
          </div>
        )}
      </div>

      {/* Search and Filters */}
      <div className="flex gap-4">
        <div
          className="flex-1 flex items-center gap-2 px-4 py-2 rounded-lg border"
          style={{
            backgroundColor: 'var(--bg-tertiary)',
            borderColor: 'var(--border-primary)',
          }}
        >
          <Search className="w-4 h-4" style={{ color: 'var(--text-tertiary)' }} />
          <input
            type="text"
            placeholder="Search assets by name, ID, or owner..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="flex-1 bg-transparent border-0 outline-none"
            style={{ color: 'var(--text-primary)' }}
          />
        </div>
      </div>

      {/* Filter Bar */}
      <FilterBar
        filters={[
          { key: 'service', label: 'Service', options: services },
          { key: 'environment', label: 'Environment', options: environments.map((e) => ({ value: e, label: e })) },
          {
            key: 'risk_level',
            label: 'Risk Level',
            options: [
              { value: 'critical', label: 'Critical' },
              { value: 'high', label: 'High' },
              { value: 'medium', label: 'Medium' },
              { value: 'low', label: 'Low' },
            ],
          },
        ]}
        onFilterChange={(key, value) => {
          setFilters({ ...filters, [key]: value });
        }}
        activeFilters={filters}
      />

      {/* Assets Table */}
      <div
        className="rounded-lg p-6 border"
        style={{
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border-primary)',
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Assets
          </h2>
          <span style={{ color: 'var(--text-tertiary)' }} className="text-sm">
            {filteredAssets.length} of {assets.length} assets
          </span>
        </div>
        <DataTable
          data={filteredAssets}
          columns={columns}
          pageSize={20}
          onRowClick={(asset) => router.push(`/inventory/${encodeURIComponent(asset.resource_uid || asset.resource_id)}`)}
          loading={loading}
          emptyMessage="No assets found matching your filters"
        />
      </div>
    </div>
  );
}
