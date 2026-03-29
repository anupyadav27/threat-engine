'use client';

import { useState, useEffect, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  Server,
  Database,
  Lock,
  Download,
  RefreshCw,
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
import { classifyResourceDomain } from '@/lib/inventory-taxonomy';
import PageLayout from '@/components/shared/PageLayout';
import InsightRow from '@/components/shared/InsightRow';
import SeverityBadge from '@/components/shared/SeverityBadge';

const DOMAIN_ICON_MAP = {
  KeyRound, Network, Shield, Server, Box, Zap, HardDrive, Database,
  Lock, Globe, MessageSquare, Activity, ClipboardCheck, Brain,
};

/** Helper: risk level from numeric score */
const getRiskLevel = (score) => {
  if (score >= 70) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
};

export default function InventoryPage() {
  const router = useRouter();
  const { provider, account, region } = useGlobalFilter();
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [summary, setSummary] = useState(null);

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

  // ── Derived metrics ──
  const scopeFiltered = assets;

  const newThisWeek = scopeFiltered.filter(
    (a) => new Date(a.created_at) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
  ).length;
  const unmanagedCount = scopeFiltered.filter((a) => !a.tags || Object.keys(a.tags).length === 0).length;
  const exposedCount = scopeFiltered.filter((a) => a.internet_exposed === true || a.public === true || a.risk_score > 70).length;
  const criticalCount = scopeFiltered.filter((a) => a.severity === 'critical' || a.risk_level === 'critical' || (a.findings && a.findings.critical > 0)).length;
  const driftCount = summary?.total_drift ?? 0;
  const removedCount = summary?.removed_assets ?? 0;
  const uniqueProviders = new Set(scopeFiltered.map((r) => r.provider)).size;
  const staleCount = scopeFiltered.filter(a => {
    const lastSeen = new Date(a.last_scanned);
    return (Date.now() - lastSeen) > 30 * 24 * 60 * 60 * 1000;
  }).length;

  const totalAssets = scopeFiltered.length || 1;
  const awsAssets = scopeFiltered.filter((a) => a.provider === 'aws').length;
  const azureAssets = scopeFiltered.filter((a) => a.provider === 'azure').length;
  const gcpAssets = scopeFiltered.filter((a) => a.provider === 'gcp').length;

  // ── Asset Status Distribution data ──
  const statusBars = useMemo(() => {
    const total = scopeFiltered.length || 1;
    const statusCounts = scopeFiltered.reduce((acc, a) => {
      const s = (a.status || 'active').toLowerCase();
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, {});
    const statusColors = {
      active: 'var(--accent-success)', running: 'var(--accent-success)',
      stopped: 'var(--accent-warning)', terminated: 'var(--accent-danger)',
      deprecated: 'var(--accent-danger)', 'pending deletion': '#6b7280', unknown: '#9ca3af',
    };
    return Object.entries(statusCounts)
      .sort(([, a], [, b]) => b - a)
      .map(([label, count]) => ({
        label: label.charAt(0).toUpperCase() + label.slice(1),
        value: Math.round((count / total) * 100),
        color: statusColors[label] || '#9ca3af',
      }));
  }, [scopeFiltered]);

  // ── Tab-filtered data sets ──
  const exposedAssets = useMemo(() => scopeFiltered.filter(a => a.internet_exposed === true || a.public === true || a.risk_score > 70), [scopeFiltered]);
  const unmanagedAssets = useMemo(() => scopeFiltered.filter(a => !a.tags || Object.keys(a.tags).length === 0), [scopeFiltered]);
  const criticalAssets = useMemo(() => scopeFiltered.filter(a => a.severity === 'critical' || a.risk_level === 'critical' || (a.findings && a.findings.critical > 0)), [scopeFiltered]);

  // ── Unique values for dynamic filter options ──
  const uniqueVals = (key) => [...new Set(scopeFiltered.map(r => r[key]).filter(Boolean))].sort();

  const filterDefs = useMemo(() => {
    const f = [];
    const services = uniqueVals('service');
    if (services.length > 0) f.push({ key: 'service', label: 'Service', options: services.map(s => ({ value: s, label: s.toUpperCase() })) });
    const providers = uniqueVals('provider');
    if (providers.length > 0) f.push({ key: 'provider', label: 'Provider', options: providers.map(p => ({ value: p, label: p.toUpperCase() })) });
    const accounts = uniqueVals('account_id');
    if (accounts.length > 0) f.push({ key: 'account_id', label: 'Account', options: accounts });
    const regions = uniqueVals('region');
    if (regions.length > 0) f.push({ key: 'region', label: 'Region', options: regions });
    f.push({
      key: 'risk_level',
      label: 'Risk Level',
      options: [
        { value: 'critical', label: 'Critical' },
        { value: 'high', label: 'High' },
        { value: 'medium', label: 'Medium' },
        { value: 'low', label: 'Low' },
      ],
    });
    return f;
  }, [scopeFiltered]);

  const groupByOpts = useMemo(() => [
    { key: 'provider', label: 'Provider' },
    { key: 'account_id', label: 'Account' },
    { key: 'region', label: 'Region' },
    { key: 'service', label: 'Service' },
    { key: 'resource_type', label: 'Resource Type' },
    { key: 'status', label: 'Status' },
  ], []);

  // ── Table columns ──
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

  // ── Shared tab config ──
  const sharedTabProps = { columns, filters: filterDefs, groupByOptions: groupByOpts };

  // ── PageLayout props ──
  const pageContext = {
    title: 'Cloud Asset Inventory',
    brief: 'Discover and manage assets across your multi-cloud environment',
    details: [
      'Use the "Unmanaged" tab to find resources missing tags or ownership.',
      'The "Internet Exposed" tab highlights publicly reachable resources.',
      'Group by Provider or Region to understand distribution at a glance.',
    ],
    tabs: [
      { id: 'all', label: 'All Assets', count: scopeFiltered.length },
      { id: 'exposed', label: 'Internet Exposed', count: exposedCount },
      { id: 'unmanaged', label: 'Unmanaged', count: unmanagedCount },
      { id: 'critical', label: 'Critical Findings', count: criticalCount },
    ],
  };

  const kpiGroups = [
    {
      title: 'Exposure Risk',
      items: [
        { label: 'New This Week', value: newThisWeek, suffix: 'resources' },
        { label: 'Removed', value: removedCount },
        { label: 'Drifted', value: driftCount },
        { label: 'Stale (>30d)', value: staleCount },
      ],
    },
    {
      title: 'Coverage',
      items: [
        { label: 'Total Resources', value: scopeFiltered.length },
        { label: 'Exposed', value: exposedCount },
        { label: 'Critical', value: criticalCount },
        { label: 'Providers', value: `${uniqueProviders}/6` },
      ],
    },
  ];

  const tabData = {
    all: { data: scopeFiltered, ...sharedTabProps },
    exposed: { data: exposedAssets, ...sharedTabProps },
    unmanaged: { data: unmanagedAssets, ...sharedTabProps },
    critical: { data: criticalAssets, ...sharedTabProps },
  };

  // ── Insight Row: Asset Status Distribution (left) + Multi-Cloud Distribution (right) ──
  const insightRowNode = (
    <InsightRow
      left={
        <div>
          <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Asset Status Distribution</h3>
          <div className="space-y-2.5">
            {statusBars.map((item) => (
              <div key={item.label}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>{item.value}%</span>
                </div>
                <div className="w-full h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                  <div className="h-full rounded-full" style={{ width: `${item.value}%`, backgroundColor: item.color }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      }
      right={
        <div>
          <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Multi-Cloud Distribution</h3>
          <div className="space-y-2.5">
            {[
              { label: 'AWS', count: awsAssets, icon: '🟠', color: '#ff9900' },
              { label: 'Azure', count: azureAssets, icon: '🔵', color: '#0078d4' },
              { label: 'GCP', count: gcpAssets, icon: '🔴', color: '#4285f4' },
            ].map((p) => (
              <div key={p.label}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{p.icon} {p.label}</span>
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>{p.count}</span>
                </div>
                <div className="w-full h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                  <div className="h-full rounded-full" style={{ width: `${(p.count / totalAssets) * 100}%`, backgroundColor: p.color }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      }
    />
  );

  return (
    <div className="space-y-5">
      {/* Navigation buttons above PageLayout */}
      <div className="flex gap-2 justify-end">
        <button
          onClick={() => router.push('/inventory/architecture')}
          className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors text-sm"
          style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
        >
          <Network className="w-4 h-4" />
          Architecture View
        </button>
        <button
          onClick={() => router.push('/inventory/graph')}
          className="flex items-center gap-2 px-3 py-2 rounded-lg transition-colors text-sm"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
        >
          <Network className="w-4 h-4" />
          Graph (v1)
        </button>
        <button
          className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors text-sm"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
        >
          <Download className="w-4 h-4" />
          Export
        </button>
        <button
          className="flex items-center gap-2 px-4 py-2 rounded-lg transition-colors text-sm"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      <PageLayout
        icon={Server}
        pageContext={pageContext}
        kpiGroups={kpiGroups}
        insightRow={insightRowNode}
        tabData={tabData}
        loading={loading}
        error={error}
        onRowClick={(asset) => router.push(`/inventory/${encodeURIComponent(asset.resource_uid || asset.resource_id)}`)}
      />
    </div>
  );
}
