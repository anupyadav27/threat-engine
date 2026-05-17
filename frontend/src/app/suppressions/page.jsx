'use client';

import { useEffect, useState, useMemo } from 'react';
import {
  EyeOff,
  Shield,
  Clock,
  AlertTriangle,
  Building2,
  Server,
  RefreshCw,
  Trash2,
  ChevronDown,
  ShieldOff,
  FileSearch,
} from 'lucide-react';
import { fetchView, deleteFromEngine } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';
import KpiCard from '@/components/shared/KpiCard';
import DataTable from '@/components/shared/DataTable';

const SCOPE_TYPE_LABELS = {
  rule:       'Rule',
  service:    'Service',
  technology: 'Technology',
  provider:   'Provider',
};

const SCOPE_TYPE_COLORS = {
  rule:       { bg: 'rgba(59,130,246,0.12)',  color: '#3b82f6' },
  service:    { bg: 'rgba(16,185,129,0.12)',  color: '#10b981' },
  technology: { bg: 'rgba(168,85,247,0.12)', color: '#a855f7' },
  provider:   { bg: 'rgba(249,115,22,0.12)', color: '#f97316' },
};

function AccessDenied() {
  return (
    <div className="flex-1 flex items-center justify-center py-24">
      <div className="text-center space-y-4 max-w-sm">
        <div className="w-16 h-16 rounded-full flex items-center justify-center mx-auto" style={{ backgroundColor: 'rgba(239,68,68,0.1)' }}>
          <ShieldOff className="w-8 h-8" style={{ color: '#ef4444' }} />
        </div>
        <p className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>Access Denied</p>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          The Suppressions page requires Analyst role or higher. Contact your administrator to request access.
        </p>
      </div>
    </div>
  );
}

export default function SuppressionsPage() {
  const { hasPermission, role } = useAuth();
  const [loading, setLoading]   = useState(true);
  const [data, setData]         = useState({});
  const [kpi, setKpi]           = useState({});
  const [activeTab, setActiveTab] = useState('rule_scope');
  const [liftingId, setLiftingId] = useState(null);
  const [error, setError]         = useState(null);

  // Viewer has no suppression permissions — block page
  const canView = hasPermission('rules:read');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchView('suppressions');
      if (res?.error) { setError(res.error); return; }
      setData(res);
      setKpi(res.kpi || {});
    } catch (err) {
      setError(err?.message || 'Failed to load suppressions');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { if (canView) load(); else setLoading(false); }, [canView]);

  if (!canView) return <AccessDenied />;

  const ruleSuppresions   = data.rule_suppressions    || [];
  const findingSuppressions = data.finding_suppressions || [];

  const handleLiftRule = async (row) => {
    setLiftingId(row.id);
    try {
      const res = await deleteFromEngine('rule', `/api/v1/rules/suppressions/${row.id}`);
      if (res?.error) {
        alert(`Failed to lift suppression: ${res.error}`);
      } else {
        setData(prev => ({
          ...prev,
          rule_suppressions: (prev.rule_suppressions || []).filter(s => s.id !== row.id),
          suppressions: (prev.suppressions || []).filter(s => s.id !== row.id),
        }));
      }
    } finally {
      setLiftingId(null);
    }
  };

  const handleLiftFinding = async (row) => {
    setLiftingId(row.id);
    try {
      const res = await deleteFromEngine('rule', `/api/v1/findings/suppressions/${row.id}`);
      if (res?.error) {
        alert(`Failed to lift suppression: ${res.error}`);
      } else {
        setData(prev => ({
          ...prev,
          finding_suppressions: (prev.finding_suppressions || []).filter(s => s.id !== row.id),
          suppressions: (prev.suppressions || []).filter(s => s.id !== row.id),
        }));
      }
    } finally {
      setLiftingId(null);
    }
  };

  // Analyst can lift their OWN suppressions; tenant_admin+ can lift any
  const canLiftAny = hasPermission('rules:write');

  const LiftButton = ({ row, onLift }) => {
    const isLifting = liftingId === row.id;
    const isOwn = row.suppressed_by && role; // simplified — server enforces ownership
    const showLift = canLiftAny || isOwn;
    if (!showLift) return null;
    return (
      <button
        onClick={() => onLift(row)}
        disabled={isLifting}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors"
        style={{
          backgroundColor: 'rgba(239,68,68,0.1)',
          color: '#ef4444',
          opacity: isLifting ? 0.6 : 1,
          cursor: isLifting ? 'not-allowed' : 'pointer',
        }}
      >
        {isLifting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
        {isLifting ? 'Lifting...' : 'Lift'}
      </button>
    );
  };

  const ruleColumns = [
    {
      accessorKey: 'scope_value',
      header: 'Suppressed Scope',
      cell: (info) => {
        const row = info.row.original;
        const colors = SCOPE_TYPE_COLORS[row.scope_type] || { bg: 'rgba(107,114,128,0.12)', color: '#6b7280' };
        return (
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs px-2 py-0.5 rounded font-semibold" style={{ backgroundColor: colors.bg, color: colors.color }}>
                {SCOPE_TYPE_LABELS[row.scope_type] || row.scope_type}
              </span>
              {row.provider && (
                <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                  {row.provider.toUpperCase()}
                </span>
              )}
            </div>
            <p className="text-sm font-mono" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</p>
          </div>
        );
      },
    },
    {
      accessorKey: 'scope_level',
      header: 'Level',
      cell: (info) => {
        const isTenant = info.getValue() === 'tenant';
        return (
          <div className="flex items-center gap-1.5">
            {isTenant
              ? <Building2 className="w-4 h-4" style={{ color: '#3b82f6' }} />
              : <Server    className="w-4 h-4" style={{ color: '#10b981' }} />
            }
            <span className="text-sm font-medium" style={{ color: isTenant ? '#3b82f6' : '#10b981' }}>
              {isTenant ? 'Tenant-wide' : 'Account'}
            </span>
          </div>
        );
      },
    },
    {
      accessorKey: 'account_id',
      header: 'Account',
      cell: (info) => {
        const val = info.getValue();
        return (
          <span className="text-sm font-mono" style={{ color: val ? 'var(--text-primary)' : 'var(--text-muted)' }}>
            {val || '— All —'}
          </span>
        );
      },
    },
    {
      accessorKey: 'reason',
      header: 'Reason',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue() || <em style={{ color: 'var(--text-muted)' }}>No reason given</em>}
        </span>
      ),
    },
    {
      accessorKey: 'suppressed_by',
      header: 'Suppressed By',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'expires_at',
      header: 'Expires',
      cell: ExpiresCell,
    },
    {
      id: 'actions',
      header: '',
      cell: (info) => <LiftButton row={info.row.original} onLift={handleLiftRule} />,
    },
  ];

  const findingColumns = [
    {
      accessorKey: 'rule_id',
      header: 'Rule',
      cell: (info) => (
        <p className="text-sm font-mono" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</p>
      ),
    },
    {
      accessorKey: 'resource_uid',
      header: 'Resource',
      cell: (info) => {
        const val = info.getValue();
        return (
          <span className="text-sm font-mono break-all" style={{ color: val ? 'var(--text-primary)' : 'var(--text-muted)' }}>
            {val || <em style={{ color: 'var(--text-muted)' }}>All resources in account</em>}
          </span>
        );
      },
    },
    {
      accessorKey: 'account_id',
      header: 'Account',
      cell: (info) => (
        <span className="text-sm font-mono" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'reason',
      header: 'Reason',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue() || <em style={{ color: 'var(--text-muted)' }}>No reason given</em>}
        </span>
      ),
    },
    {
      accessorKey: 'suppressed_by',
      header: 'Suppressed By',
      cell: (info) => (
        <div>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</p>
          {info.row.original.suppressed_by_role && (
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{info.row.original.suppressed_by_role}</p>
          )}
        </div>
      ),
    },
    {
      accessorKey: 'expires_at',
      header: 'Expires',
      cell: ExpiresCell,
    },
    {
      id: 'actions',
      header: '',
      cell: (info) => <LiftButton row={info.row.original} onLift={handleLiftFinding} />,
    },
  ];

  const tabs = [
    { id: 'rule_scope', label: 'Rule Scope', count: ruleSuppresions.length,   icon: Shield },
    { id: 'findings',   label: 'Findings',   count: findingSuppressions.length, icon: FileSearch },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>Suppressions</h1>
          <p className="mt-1" style={{ color: 'var(--text-secondary)' }}>
            Manage rule-scope and finding-level suppressions
          </p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors"
          style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--accent-danger)' }}>
          <p className="text-sm font-medium" style={{ color: 'var(--accent-danger)' }}>Error: {error}</p>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Suppressions" value={kpi.total ?? 0} subtitle="Active" icon={<EyeOff className="w-5 h-5" />} color="blue" />
        <KpiCard title="Rule Scope" value={kpi.rule_scope_total ?? 0} subtitle="Rule/service/tech" icon={<Shield className="w-5 h-5" />} color="purple" />
        <KpiCard title="Finding Level" value={kpi.finding_total ?? 0} subtitle="Resource-specific" icon={<FileSearch className="w-5 h-5" />} color="green" />
        <KpiCard title="Expiring Soon" value={kpi.expiring_soon ?? 0} subtitle="Within 30 days" icon={<Clock className="w-5 h-5" />} color="orange" />
      </div>

      {/* Tabs */}
      <div className="border-b" style={{ borderColor: 'var(--border-primary)' }}>
        <div className="flex gap-1">
          {tabs.map(({ id, label, count, icon: Icon }) => {
            const active = activeTab === id;
            return (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className="flex items-center gap-2 px-4 py-3 text-sm font-semibold border-b-2 transition-colors"
                style={{
                  borderBottomColor: active ? 'var(--accent-primary)' : 'transparent',
                  color: active ? 'var(--accent-primary)' : 'var(--text-secondary)',
                }}
              >
                <Icon className="w-4 h-4" />
                {label}
                <span
                  className="text-xs px-1.5 py-0.5 rounded-full font-medium"
                  style={{
                    backgroundColor: active ? 'rgba(99,102,241,0.15)' : 'var(--bg-tertiary)',
                    color: active ? 'var(--accent-primary)' : 'var(--text-muted)',
                  }}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Rule Scope Tab */}
      {activeTab === 'rule_scope' && (
        <RuleScopeTab
          suppressions={ruleSuppresions}
          columns={ruleColumns}
          kpi={kpi}
          loading={loading}
        />
      )}

      {/* Findings Tab */}
      {activeTab === 'findings' && (
        <FindingsTab
          suppressions={findingSuppressions}
          columns={findingColumns}
          loading={loading}
        />
      )}

      {/* Info box */}
      <div className="rounded-xl p-5 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" style={{ color: 'var(--accent-warning)' }} />
          <div className="space-y-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
            <p className="font-semibold" style={{ color: 'var(--text-primary)' }}>How suppressions work</p>
            <p><strong>Rule scope</strong> suppressions skip a rule, service, or technology for all or specific accounts. Requires Tenant Admin role.</p>
            <p><strong>Finding level</strong> suppressions suppress a specific resource+rule combination in an account. Requires Analyst role.</p>
            <p>Suppressions take effect on the <strong>next scan</strong> — existing findings are not removed retroactively.</p>
          </div>
        </div>
      </div>
    </div>
  );
}

function RuleScopeTab({ suppressions, columns, kpi, loading }) {
  const [filterLevel, setFilterLevel]       = useState('');
  const [filterType, setFilterType]         = useState('');
  const [filterProvider, setFilterProvider] = useState('');

  const filtered = useMemo(() => {
    let rows = [...suppressions];
    if (filterLevel)    rows = rows.filter(r => r.scope_level === filterLevel);
    if (filterType)     rows = rows.filter(r => r.scope_type  === filterType);
    if (filterProvider) rows = rows.filter(r => r.provider    === filterProvider);
    return rows;
  }, [suppressions, filterLevel, filterType, filterProvider]);

  const uniqueProviders = [...new Set(suppressions.map(s => s.provider).filter(Boolean))].sort();

  // Scope type breakdown
  const byType = kpi.by_scope_type || {};

  return (
    <div className="space-y-4">
      {Object.keys(byType).length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Object.entries(byType).map(([type, count]) => {
            const colors = SCOPE_TYPE_COLORS[type] || { bg: 'rgba(107,114,128,0.12)', color: '#6b7280' };
            return (
              <div key={type} className="rounded-xl p-4 border flex items-center gap-3" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ backgroundColor: colors.bg }}>
                  <Shield className="w-4 h-4" style={{ color: colors.color }} />
                </div>
                <div>
                  <p className="text-lg font-bold" style={{ color: colors.color }}>{count}</p>
                  <p className="text-xs capitalize" style={{ color: 'var(--text-secondary)' }}>{SCOPE_TYPE_LABELS[type]}</p>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="flex items-center justify-between flex-wrap gap-3">
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {filtered.length} of {suppressions.length} rule-scope suppressions
        </p>
        <div className="flex items-center gap-2 flex-wrap">
          <FilterDropdown label="Level" value={filterLevel} onChange={setFilterLevel} options={[
            { value: '', label: 'All Levels' }, { value: 'tenant', label: 'Tenant-wide' }, { value: 'account', label: 'Account' },
          ]} />
          <FilterDropdown label="Scope Type" value={filterType} onChange={setFilterType} options={[
            { value: '', label: 'All Types' }, { value: 'rule', label: 'Rule' }, { value: 'service', label: 'Service' },
            { value: 'technology', label: 'Technology' }, { value: 'provider', label: 'Provider' },
          ]} />
          {uniqueProviders.length > 0 && (
            <FilterDropdown label="Provider" value={filterProvider} onChange={setFilterProvider} options={[
              { value: '', label: 'All Providers' },
              ...uniqueProviders.map(p => ({ value: p, label: p.toUpperCase() })),
            ]} />
          )}
        </div>
      </div>

      {!loading && suppressions.length === 0 ? (
        <EmptyState
          icon={<Shield className="w-8 h-8" style={{ color: '#22c55e' }} />}
          title="No rule-scope suppressions"
          description="Suppress rules, services, or technologies from the Rule Library page."
        />
      ) : (
        <DataTable data={filtered} columns={columns} pageSize={15} loading={loading} emptyMessage="No suppressions match the selected filters" />
      )}
    </div>
  );
}

function FindingsTab({ suppressions, columns, loading }) {
  const [filterRule, setFilterRule] = useState('');

  const filtered = useMemo(() => {
    if (!filterRule.trim()) return suppressions;
    const q = filterRule.toLowerCase();
    return suppressions.filter(r =>
      r.rule_id?.toLowerCase().includes(q) ||
      r.resource_uid?.toLowerCase().includes(q) ||
      r.account_id?.toLowerCase().includes(q)
    );
  }, [suppressions, filterRule]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
          {filtered.length} of {suppressions.length} finding-level suppressions
        </p>
        <input
          type="text"
          placeholder="Search rule, resource, account..."
          value={filterRule}
          onChange={e => setFilterRule(e.target.value)}
          className="px-3 py-1.5 rounded-lg border text-sm w-64"
          style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
        />
      </div>

      {!loading && suppressions.length === 0 ? (
        <EmptyState
          icon={<FileSearch className="w-8 h-8" style={{ color: '#3b82f6' }} />}
          title="No finding-level suppressions"
          description="Suppress specific resource findings from the Misconfigurations page."
        />
      ) : (
        <DataTable data={filtered} columns={columns} pageSize={15} loading={loading} emptyMessage="No findings match the search" />
      )}
    </div>
  );
}

function EmptyState({ icon, title, description }) {
  return (
    <div className="rounded-xl p-12 border flex flex-col items-center gap-4 text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
      <div className="w-16 h-16 rounded-full flex items-center justify-center" style={{ backgroundColor: 'rgba(34,197,94,0.1)' }}>
        {icon}
      </div>
      <div>
        <p className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>{title}</p>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>{description}</p>
      </div>
    </div>
  );
}

function ExpiresCell(info) {
  const val = info.getValue();
  if (!val) return <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'rgba(107,114,128,0.12)', color: '#6b7280' }}>Permanent</span>;
  const date = new Date(val);
  const soon = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  const color = date < soon ? '#f97316' : 'var(--text-secondary)';
  return (
    <div className="flex items-center gap-1">
      {date < soon && <Clock className="w-3.5 h-3.5" style={{ color: '#f97316' }} />}
      <span className="text-sm" style={{ color }}>{date.toLocaleDateString()}</span>
    </div>
  );
}

function FilterDropdown({ label, value, onChange, options }) {
  return (
    <div className="relative">
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="appearance-none pl-3 pr-8 py-1.5 rounded-lg text-sm border cursor-pointer"
        style={{
          backgroundColor: 'var(--bg-secondary)',
          borderColor: value ? 'var(--accent-primary)' : 'var(--border-primary)',
          color: 'var(--text-primary)',
        }}
      >
        {options.map(opt => <option key={opt.value} value={opt.value}>{opt.label}</option>)}
      </select>
      <ChevronDown className="w-3.5 h-3.5 absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--text-muted)' }} />
    </div>
  );
}
