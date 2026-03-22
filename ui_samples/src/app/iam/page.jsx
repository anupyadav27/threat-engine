'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Shield, Users, Lock, Key, AlertTriangle, CheckCircle,
  TrendingUp, ChevronDown, AlertCircle, Activity, UserX,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import MetricStrip from '@/components/shared/MetricStrip';
import DataTable from '@/components/shared/DataTable';
import SearchBar from '@/components/shared/SearchBar';
import SeverityBadge from '@/components/shared/SeverityBadge';
import GaugeChart from '@/components/charts/GaugeChart';
import SeverityDonut from '@/components/charts/SeverityDonut';
import FilterBar from '@/components/shared/FilterBar';

/**
 * Enterprise IAM Security Posture Page
 * Comprehensive identity and access management analysis across 8 dimensions
 */
export default function IamSecurityPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [expandedRisk, setExpandedRisk] = useState(null);
  const [realUsers, setRealUsers] = useState([]);
  const [iamSummary, setIamSummary] = useState(null);
  const [roles, setRoles] = useState([]);
  const [accessKeys, setAccessKeys] = useState([]);
  const [privilegeEscalation, setPrivilegeEscalation] = useState([]);
  const [serviceAccounts, setServiceAccounts] = useState([]);
  const [userSearch, setUserSearch] = useState('');
  const [roleSearch, setRoleSearch] = useState('');
  const [activeFilters, setActiveFilters] = useState({ identity_type: '', risk_level: '' });

  const { provider, account, region, filterSummary } = useGlobalFilter();


  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchView('iam', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (data.error) { setError(data.error); return; }
        if (data.identities)          setRealUsers(data.identities);
        if (data.kpi)                 setIamSummary({...data.kpi, riskScore: data.riskScore || 0});
        if (data.roles)               setRoles(data.roles);
        if (data.accessKeys)          setAccessKeys(data.accessKeys);
        if (data.privilegeEscalation) setPrivilegeEscalation(data.privilegeEscalation);
        if (data.serviceAccounts)     setServiceAccounts(data.serviceAccounts);
      } catch (err) {
        console.warn('[iam] fetchData error:', err);
        setError(err?.message || 'Failed to load IAM data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  // BFF already scope-filters identities
  const activeUsers = realUsers;
  const scopeFiltered = realUsers;

  // KPI values from BFF (iamSummary = data.kpi)
  const overPrivilegedCount = iamSummary?.overPrivileged ?? scopeFiltered.filter(u => u.policies > 5 || u.risk_score >= 75).length;
  const noMfaCount = iamSummary?.noMfa ?? scopeFiltered.filter(u => !u.mfa).length;
  const unusedCutoff = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000);
  const unusedCount = iamSummary?.inactive ?? scopeFiltered.filter(u => new Date(u.last_login) < unusedCutoff).length;
  const mfaAdoptionPct = iamSummary?.mfaAdoption ?? (scopeFiltered.length > 0
    ? Math.round(scopeFiltered.filter(u => u.mfa).length / scopeFiltered.length * 100) : 0);
  const keysToRotate = iamSummary?.keysToRotate ?? accessKeys.filter(k => k.age_days > 90).length;
  const policyDrift = iamSummary?.wildcardRoles ?? roles.filter(r => r.wildcard).length;
  const iamRiskScore = iamSummary?.riskScore ?? null;

  // Findings by category — from BFF KPI
  const findingsData = [
    { name: 'Overprivileged', value: overPrivilegedCount, color: '#ef4444' },
    { name: 'MFA Issues',     value: noMfaCount,          color: '#f97316' },
    { name: 'Key Rotation',   value: keysToRotate,        color: '#eab308' },
    { name: 'Inactive',       value: unusedCount,          color: '#8b5cf6' },
    { name: 'Policy Drift',   value: policyDrift,          color: '#3b82f6' },
  ].filter(d => d.value > 0);

  // Tab definitions
  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'users', label: 'Users & Identities' },
    { id: 'roles', label: 'Roles & Policies' },
    { id: 'keys', label: 'Access Keys' },
    { id: 'mfa', label: 'MFA Status' },
    { id: 'privilege', label: 'Privilege Escalation' },
    { id: 'services', label: 'Service Accounts' },
  ];

  // ── Local filter helpers (provider/account handled by global filter) ─────────
  const handleFilterChange = (key, value) => {
    setActiveFilters(prev => ({ ...prev, [key]: value }));
  };

  const identityTypeOptions = useMemo(() => [...new Set(scopeFiltered.map(u => u.type))].sort(), [scopeFiltered]);

  const iamFilterDefs = [
    { key: 'identity_type', label: 'Identity Type', options: identityTypeOptions },
    { key: 'risk_level',    label: 'Risk Level',    options: ['critical', 'high', 'medium', 'low'] },
  ];

  const filteredUsers = useMemo(() => {
    return scopeFiltered.filter(u => {
      if (activeFilters.identity_type && u.type !== activeFilters.identity_type) return false;
      if (activeFilters.risk_level) {
        const s = u.risk_score;
        if (activeFilters.risk_level === 'critical' && s < 75) return false;
        if (activeFilters.risk_level === 'high'     && (s < 50 || s >= 75)) return false;
        if (activeFilters.risk_level === 'medium'   && (s < 25 || s >= 50)) return false;
        if (activeFilters.risk_level === 'low'      && s >= 25) return false;
      }
      return true;
    });
  }, [scopeFiltered, activeFilters]);

  // Stale identities: last_login > 60 days (before 2026-01-06)
  const staleUsers = useMemo(() => {
    const cutoff = new Date('2026-01-06');
    return scopeFiltered.filter(u => new Date(u.last_login) < cutoff);
  }, [scopeFiltered]);

  // Users & Identities columns
  const usersColumns = [
    {
      accessorKey: 'username',
      header: 'Username',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'type',
      header: 'Type',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'account',
      header: 'Account',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'groups',
      header: 'Groups',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'policies',
      header: 'Policies',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'last_login',
      header: 'Last Login',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
          {new Date(info.getValue()).toLocaleDateString()}
        </span>
      ),
    },
    {
      accessorKey: 'mfa',
      header: 'MFA',
      cell: (info) => (
        <div className="flex items-center gap-2">
          {info.getValue() ? (
            <CheckCircle className="w-4 h-4 text-green-400" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-red-400" />
          )}
          <span className="text-sm">{info.getValue() ? 'Enabled' : 'Disabled'}</span>
        </div>
      ),
    },
    {
      accessorKey: 'risk_score',
      header: 'Risk',
      cell: (info) => {
        const score = info.getValue();
        const barColor = score >= 75 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 25 ? '#eab308' : '#22c55e';
        return (
          <div className="flex items-center gap-2">
            <div className="w-14 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: barColor }} />
            </div>
            <span className="text-xs font-bold w-6" style={{ color: barColor }}>{score}</span>
          </div>
        );
      },
    },
  ];

  // Roles & Policies columns
  const rolesColumns = [
    {
      accessorKey: 'name',
      header: 'Name',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'type',
      header: 'Type',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'attached_to',
      header: 'Attached To',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'permissions',
      header: 'Permissions',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'wildcard',
      header: 'Wildcard Actions',
      cell: (info) => (
        info.getValue() ? (
          <span className="text-xs px-2 py-1 rounded bg-red-500/20 text-red-400">Yes</span>
        ) : (
          <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>No</span>
        )
      ),
    },
    {
      accessorKey: 'last_used',
      header: 'Last Used',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
          {new Date(info.getValue()).toLocaleDateString()}
        </span>
      ),
    },
    {
      accessorKey: 'risk_level',
      header: 'Risk Level',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
  ];

  // Access Keys columns
  const keysColumns = [
    {
      accessorKey: 'user',
      header: 'User',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'created',
      header: 'Created',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
          {new Date(info.getValue()).toLocaleDateString()}
        </span>
      ),
    },
    {
      accessorKey: 'last_used',
      header: 'Last Used',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
          {info.getValue() ? new Date(info.getValue()).toLocaleDateString() : 'Never'}
        </span>
      ),
    },
    {
      accessorKey: 'age_days',
      header: 'Age (days)',
      cell: (info) => {
        const age = info.getValue();
        let color = 'text-green-400';
        if (age > 90) color = 'text-red-400';
        else if (age > 60) color = 'text-orange-400';
        return <span className={`text-sm font-medium ${color}`}>{age}</span>;
      },
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
  ];

  // MFA Status columns
  const mfaColumns = [
    {
      accessorKey: 'username',
      header: 'User',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'account',
      header: 'Account',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'mfa',
      header: 'MFA Type',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: info.getValue() ? 'rgb(34, 197, 94, 0.2)' : 'rgb(239, 68, 68, 0.2)', color: info.getValue() ? '#22c55e' : '#ef4444' }}>
          {info.getValue() ? 'Virtual' : 'Not Enabled'}
        </span>
      ),
    },
  ];

  // Privilege Escalation columns
  const privilegeColumns = [
    {
      accessorKey: 'flow',
      header: 'Escalation Path',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'risk_level',
      header: 'Risk',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'affected_user',
      header: 'Affected User',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
  ];

  // Service Accounts columns
  const serviceColumns = [
    {
      accessorKey: 'name',
      header: 'Service Account',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'purpose',
      header: 'Purpose',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'owner',
      header: 'Owner',
      cell: (info) => (
        <span className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'keys',
      header: 'Keys',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'permissions',
      header: 'Permissions',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded transition-colors duration-200" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'risk_score',
      header: 'Risk',
      cell: (info) => {
        const score = info.getValue();
        const barColor = score >= 75 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 25 ? '#eab308' : '#22c55e';
        return (
          <div className="flex items-center gap-2">
            <div className="w-14 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: barColor }} />
            </div>
            <span className="text-xs font-bold w-6" style={{ color: barColor }}>{score}</span>
          </div>
        );
      },
    },
  ];

  if (error) {
    return (
      <div className="rounded-xl p-8 border text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <AlertCircle className="w-10 h-10 mx-auto mb-3" style={{ color: '#ef4444' }} />
        <p className="text-base font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Failed to load IAM data</p>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>IAM Security</h1>
        {filterSummary && (
          <p className="text-xs mt-0.5 mb-2" style={{ color: 'var(--text-tertiary)' }}>
            <span style={{ color: 'var(--accent-primary)' }}>Filtered to:</span>{' '}
            <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{filterSummary}</span>
          </p>
        )}
        <p className="mt-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
          Identity and Access Management security posture across 7 dimensions
        </p>
      </div>

      {/* Stale Identity Banner */}
      {staleUsers.length > 0 && (
        <div className="flex items-start gap-3 rounded-xl p-4 border" style={{ backgroundColor: '#92400e20', borderColor: '#d97706' }}>
          <UserX className="w-5 h-5 flex-shrink-0 mt-0.5" style={{ color: '#f59e0b' }} />
          <div className="flex-1">
            <p className="text-sm font-semibold" style={{ color: '#fbbf24' }}>
              {staleUsers.length} Stale {staleUsers.length === 1 ? 'Identity' : 'Identities'} Detected
            </p>
            <p className="text-xs mt-0.5" style={{ color: '#fcd34d' }}>
              {staleUsers.map(u => u.username).join(', ')} — last login &gt;60 days ago but still active. Review and disable to reduce attack surface.
            </p>
          </div>
          <AlertCircle className="w-4 h-4 flex-shrink-0" style={{ color: '#f59e0b' }} />
        </div>
      )}

      {/* Hierarchical Filter Bar */}
      <FilterBar
        filters={iamFilterDefs}
        activeFilters={activeFilters}
        onFilterChange={handleFilterChange}
      />

      {/* Filter summary */}
      <p className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
        Showing {filteredUsers.length} of {scopeFiltered.length} identities
        {activeFilters.identity_type && ` › ${activeFilters.identity_type}`}
        {activeFilters.risk_level    && ` › ${activeFilters.risk_level} risk`}
      </p>

      {/* Tab Navigation */}
      <div className="border-b transition-colors duration-200" style={{ borderColor: 'var(--border-primary)' }}>
        <div className="flex gap-1 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-3 text-sm font-medium whitespace-nowrap transition-colors border-b-2 ${
                activeTab === tab.id
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent transition-colors duration-200 hover:opacity-80'
              }`}
              style={activeTab !== tab.id ? { color: 'var(--text-tertiary)' } : {}}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* MetricStrip — top KPI summary */}
          <MetricStrip groups={[
            {
              label: '🔴 IDENTITY RISK',
              color: 'var(--accent-danger)',
              cells: [
                { label: 'OVER-PRIVILEGED', value: overPrivilegedCount, valueColor: 'var(--severity-critical)', delta: +3, deltaGoodDown: true, context: 'vs last 7d' },
                { label: 'NO MFA', value: noMfaCount, valueColor: 'var(--severity-high)', context: 'human users' },
                { label: 'UNUSED IDENTITIES', value: unusedCount, valueColor: 'var(--severity-critical)', context: 'inactive >60d' },
              ],
            },
            {
              label: '🔵 ACCESS HYGIENE',
              color: 'var(--accent-primary)',
              cells: [
                { label: 'MFA ADOPTION', value: mfaAdoptionPct + '%', valueColor: 'var(--accent-success)', delta: +2, context: 'vs last month' },
                { label: 'KEYS TO ROTATE', value: keysToRotate, valueColor: 'var(--severity-high)', context: 'stale access keys' },
                { label: 'POLICY DRIFT', value: policyDrift, noTrend: true, context: 'wildcard policies' },
              ],
            },
          ]} />

          {/* IAM Posture Strip */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { label: 'Unused Permissions', value: iamSummary?.unusedPermissionsPct != null ? iamSummary.unusedPermissionsPct + '%' : 'N/A', icon: <Activity className="w-4 h-4" />, sub: 'of granted perms never used', color: '#ef4444' },
              { label: 'SvcAccounts Active', value: serviceAccounts.filter(s => s.status === 'active').length, icon: <Lock className="w-4 h-4" />, sub: 'active service accounts', color: '#f97316' },
              { label: 'Keys > 90 Days', value: accessKeys.filter(k => k.age_days > 90).length, icon: <Key className="w-4 h-4" />, sub: 'rotation overdue', color: '#f97316' },
              { label: 'Over-privileged Roles', value: roles.filter(r => r.wildcard).length, icon: <Shield className="w-4 h-4" />, sub: 'wildcard (*) actions', color: '#eab308' },
            ].map((m) => (
              <div key={m.label} className="flex items-center gap-3 rounded-xl p-4 border transition-colors duration-200"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                <div className="p-2 rounded-lg flex-shrink-0" style={{ backgroundColor: `${m.color}20` }}>
                  <span style={{ color: m.color }}>{m.icon}</span>
                </div>
                <div>
                  <p className="text-xl font-bold" style={{ color: m.color }}>{m.value}</p>
                  <p className="text-xs font-medium transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{m.label}</p>
                  <p className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>{m.sub}</p>
                </div>
              </div>
            ))}
          </div>

          {/* IAM Risk Score & Findings */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Risk Gauge */}
            <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                IAM Risk Score
              </h3>
              <div className="flex justify-center items-center h-40">
                {iamRiskScore != null ? (
                  <div className="text-center">
                    <div className="text-4xl font-bold" style={{ color: '#f97316' }}>
                      {iamRiskScore}/100
                    </div>
                    <p className="text-sm mt-2 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
                      Elevated risk detected
                    </p>
                  </div>
                ) : (
                  <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No risk score available</p>
                )}
              </div>
            </div>

            {/* Findings by Category */}
            <div className="lg:col-span-2 rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                Findings by Category
              </h3>
              <div className="flex justify-center">
                <SeverityDonut data={findingsData} title="Issues" />
              </div>
            </div>
          </div>

          {/* Top IAM Risks */}
          <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
            <h3 className="text-lg font-semibold mb-4 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              Top 10 IAM Risks
            </h3>
            {privilegeEscalation.length === 0 ? (
              <p className="text-sm text-center py-6" style={{ color: 'var(--text-muted)' }}>No privilege escalation paths detected</p>
            ) : (
              <div className="space-y-3">
                {privilegeEscalation.slice(0, 10).map((risk, idx) => (
                  <div
                    key={risk.id || idx}
                    className="p-4 border rounded-lg transition-all duration-200 cursor-pointer hover:opacity-80"
                    style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
                    onClick={() => setExpandedRisk(expandedRisk === (risk.id || idx) ? null : (risk.id || idx))}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3">
                          <span className="text-xs font-bold rounded-full w-6 h-6 flex items-center justify-center" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                            {idx + 1}
                          </span>
                          <div>
                            <p className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                              {risk.flow || risk.description || risk.title || 'Unknown path'}
                            </p>
                            {expandedRisk === (risk.id || idx) && risk.description && (
                              <p className="text-xs mt-2 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
                                {risk.description}
                              </p>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <SeverityBadge severity={risk.risk_level || risk.severity} />
                        <ChevronDown className={`w-4 h-4 transition-transform ${expandedRisk === (risk.id || idx) ? 'rotate-180' : ''}`} style={{ color: 'var(--text-tertiary)' }} />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Users & Identities Tab */}
      {activeTab === 'users' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                Users & Identities
              </h2>
              <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
                Complete inventory of human users, service accounts, and federated identities
              </p>
            </div>
            <SearchBar
              value={userSearch}
              onChange={setUserSearch}
              placeholder="Search by username or type..."
            />
          </div>
          <DataTable
            data={filteredUsers.filter(u => !userSearch || (u.username + ' ' + u.type + ' ' + u.account).toLowerCase().includes(userSearch.toLowerCase()))}
            columns={usersColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No users found"
          />
        </div>
      )}

      {/* Roles & Policies Tab */}
      {activeTab === 'roles' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                Roles & Policies
              </h2>
              <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
                IAM roles and policies with permission analysis and wildcard action detection
              </p>
            </div>
            <SearchBar
              value={roleSearch}
              onChange={setRoleSearch}
              placeholder="Search by role name..."
            />
          </div>
          <DataTable
            data={roles.filter(r => !roleSearch || (r.name + ' ' + (r.attached_to || '')).toLowerCase().includes(roleSearch.toLowerCase()))}
            columns={rolesColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No roles found"
          />
        </div>
      )}

      {/* Access Keys Tab */}
      {activeTab === 'keys' && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              Access Keys
            </h2>
            <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Access key inventory with rotation tracking and age-based risk assessment
            </p>
          </div>
          <DataTable
            data={accessKeys}
            columns={keysColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No access keys found"
          />
        </div>
      )}

      {/* MFA Status Tab */}
      {activeTab === 'mfa' && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              MFA Status
            </h2>
            <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Multi-factor authentication enrollment and compliance status
            </p>
          </div>
          <DataTable
            data={activeUsers}
            columns={mfaColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No users found"
          />
        </div>
      )}

      {/* Privilege Escalation Tab */}
      {activeTab === 'privilege' && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              Privilege Escalation Paths
            </h2>
            <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Detected attack chains where identities can escalate privileges to higher-risk roles
            </p>
          </div>
          {privilegeEscalation.length === 0 ? (
            <div className="rounded-xl p-8 text-center border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No privilege escalation paths detected</p>
            </div>
          ) : (
            <div className="space-y-3">
              {privilegeEscalation.map((path, idx) => (
                <div
                  key={path.id || idx}
                  className="p-4 border rounded-lg transition-colors duration-200"
                  style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div>
                      <p className="font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                        {path.flow || path.title || path.description || 'Unknown path'}
                      </p>
                      {path.description && path.flow && (
                        <p className="text-sm mt-1 transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                          {path.description}
                        </p>
                      )}
                    </div>
                    <SeverityBadge severity={path.risk_level || path.severity} />
                  </div>
                  {path.remediation && (
                    <div className="flex items-center justify-between">
                      <p className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
                        <strong>Remediation:</strong> {path.remediation}
                      </p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Service Accounts Tab */}
      {activeTab === 'services' && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold mb-2 transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              Service Accounts
            </h2>
            <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Automation and service identities with activity monitoring and permission review
            </p>
          </div>
          <DataTable
            data={serviceAccounts}
            columns={serviceColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No service accounts found"
          />
        </div>
      )}
    </div>
  );
}
