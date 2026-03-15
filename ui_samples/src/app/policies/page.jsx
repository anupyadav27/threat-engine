'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  FileText,
  Plus,
  Check,
  Clock,
  Archive,
  TrendingUp,
  BarChart3,
  AlertTriangle,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import FilterBar from '@/components/shared/FilterBar';
import DataTable from '@/components/shared/DataTable';
import StatusIndicator from '@/components/shared/StatusIndicator';
import BarChartComponent from '@/components/charts/BarChartComponent';


/**
 * Enterprise Policy Management Page
 * Displays security policies with coverage, effectiveness, and compliance framework mapping
 */
export default function PoliciesPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  const [policies, setPolicies] = useState([]);
  const [error, setError] = useState(null);
  const [filteredPolicies, setFilteredPolicies] = useState([]);
  const [activeFilters, setActiveFilters] = useState({
    category: [],
    status: [],
    provider: [],
    severity: [],
    framework: [],
  });

  // Fetch policies on mount
  useEffect(() => {
    const fetchPolicies = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await getFromEngine('rule', '/api/v1/policies/list', {
          limit: 100,
        });

        if (res && !res.error && res.data) {
          setPolicies(res.data);
        } else {
          setError(res?.error || 'Failed to load policies');
        }
      } catch (err) {
        setError(err?.message || 'Failed to load policies');
      } finally {
        setLoading(false);
      }
    };

    fetchPolicies();
  }, []);

  // Apply filters
  useEffect(() => {
    let filtered = [...policies];

    if ((activeFilters.category || []).length > 0) {
      filtered = filtered.filter((p) => (activeFilters.category || []).includes(p.category));
    }

    if ((activeFilters.status || []).length > 0) {
      filtered = filtered.filter((p) => (activeFilters.status || []).includes(p.status));
    }

    if ((activeFilters.provider || []).length > 0) {
      filtered = filtered.filter((p) => (activeFilters.provider || []).includes(p.provider));
    }

    if ((activeFilters.severity || []).length > 0) {
      filtered = filtered.filter((p) => (activeFilters.severity || []).includes(p.severity));
    }

    setFilteredPolicies(filtered);
  }, [policies, activeFilters]);

  // Calculate policy statistics
  const policyStats = {
    total: policies.length,
    active: policies.filter((p) => p.status === 'active').length,
    draft: policies.filter((p) => p.status === 'draft').length,
    total_violations: policies.reduce((sum, p) => sum + p.violations, 0),
    auto_remediate_enabled: policies.filter((p) => p.auto_remediate).length,
    avg_pass_rate: policies.length > 0 ? (policies.reduce((sum, p) => sum + p.pass_rate, 0) / policies.length).toFixed(1) : '0.0',
  };

  // Policy categories summary — computed from real policies
  const policyCategorySummary = (() => {
    const cats = {};
    policies.forEach(p => {
      const cat = p.category || 'Uncategorized';
      if (!cats[cat]) cats[cat] = { category: cat, policies: 0, violations: 0 };
      cats[cat].policies++;
      cats[cat].violations += p.violations || 0;
    });
    return Object.values(cats).sort((a, b) => b.violations - a.violations);
  })();

  // Top 10 most violated policies for effectiveness chart
  const topViolatedPolicies = [...policies]
    .sort((a, b) => b.violations - a.violations)
    .slice(0, 10)
    .map(p => ({
      name: p.name.substring(0, 35) + (p.name.length > 35 ? '...' : ''),
      value: p.violations,
    }));

  // Active exceptions/exemptions — derived from policies with exemptions
  const activeExceptions = policies
    .filter(p => p.exceptions && p.exceptions.length > 0)
    .flatMap(p => (p.exceptions || []).map(ex => ({
      policy: p.name,
      resource: ex.resource || '—',
      justification: ex.justification || ex.reason || '—',
      approved_by: ex.approved_by || '—',
      expiry: ex.expiry || '—',
      status: ex.status || 'active',
    })));

  // Recent policy changes — derived from policies with version info
  const policyVersionHistory = policies
    .filter(p => p.version_history && p.version_history.length > 0)
    .flatMap(p => (p.version_history || []).map(v => ({
      policy: p.name,
      version: v.version || '—',
      change: v.change || v.description || '—',
      changed_by: v.changed_by || v.author || '—',
      date: v.date || v.updated_at || '—',
    })))
    .sort((a, b) => (b.date || '').localeCompare(a.date || ''))
    .slice(0, 10);

  // Get unique categories and providers
  const uniqueCategories = [...new Set(policies.map((p) => p.category).filter(Boolean))];
  const uniqueProviders = [...new Set(policies.map((p) => p.provider).filter(Boolean))];
  const uniqueSeverities = [...new Set(policies.map((p) => p.severity).filter(Boolean))];

  // Table columns
  const columns = [
    {
      accessorKey: 'name',
      header: 'Policy Name',
      cell: (info) => (
        <span className="text-sm font-medium max-w-sm" style={{ color: 'var(--text-primary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'category',
      header: 'Category',
      cell: (info) => {
        const category = info.getValue();
        const categoryColors = {
          IAM: '#3b82f6',
          Network: '#10b981',
          Storage: '#f97316',
          Database: '#8b5cf6',
          Logging: '#06b6d4',
          Compute: '#ec4899',
          Encryption: '#06b6d4',
          'Container Security': '#f59e0b',
        };
        const color = categoryColors[category] || '#6b7280';
        return (
          <span
            className="text-xs px-2 py-1 rounded font-semibold"
            style={{ backgroundColor: color + '20', color }}
          >
            {category}
          </span>
        );
      },
    },
    {
      accessorKey: 'severity',
      header: 'Severity',
      cell: (info) => {
        const severity = info.getValue();
        const colors = {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
        };
        return (
          <span
            className="text-xs px-2 py-1 rounded font-semibold"
            style={{ backgroundColor: (colors[severity] || '#3b82f6') + '20', color: colors[severity] || '#3b82f6' }}
          >
            {severity.charAt(0).toUpperCase() + severity.slice(1)}
          </span>
        );
      },
    },
    {
      accessorKey: 'provider',
      header: 'Provider',
      cell: (info) => (
        <span className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
          {(info.getValue() || '').toUpperCase()}
        </span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      cell: (info) => {
        const status = info.getValue();
        let color = '#10b981';
        if (status === 'draft') color = '#f59e0b';
        else if (status === 'archived') color = '#6b7280';
        return (
          <span className="text-xs px-2 py-1 rounded font-semibold" style={{ backgroundColor: color + '20', color }}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </span>
        );
      },
    },
    {
      accessorKey: 'evaluations',
      header: 'Evals',
      cell: (info) => (
        <span className="text-sm font-semibold" style={{ color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'violations',
      header: 'Violations',
      cell: (info) => (
        <span className="text-sm font-semibold" style={{ color: info.getValue() > 50 ? 'var(--accent-danger)' : 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    {
      accessorKey: 'pass_rate',
      header: 'Pass Rate',
      cell: (info) => {
        const rate = info.getValue();
        let color = '#10b981';
        if (rate < 90) color = '#ef4444';
        else if (rate < 95) color = '#f97316';
        return (
          <span className="text-sm font-semibold" style={{ color }}>
            {rate.toFixed(1)}%
          </span>
        );
      },
    },
    {
      accessorKey: 'auto_remediate',
      header: 'Auto-Remediate',
      cell: (info) => (
        <span className="text-xs px-2 py-1 rounded font-semibold" style={{
          backgroundColor: info.getValue() ? '#10b9812a' : '#6b72802a',
          color: info.getValue() ? '#10b981' : '#6b7280',
        }}>
          {info.getValue() ? 'Enabled' : 'Disabled'}
        </span>
      ),
    },
    {
      accessorKey: 'frameworks',
      header: 'Frameworks',
      cell: (info) => {
        const frameworks = info.getValue();
        return (
          <div className="flex flex-wrap gap-1">
            {frameworks.slice(0, 2).map((fw, idx) => (
              <span key={idx} className="text-xs px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
                {fw}
              </span>
            ))}
            {frameworks.length > 2 && (
              <span className="text-xs px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
                +{frameworks.length - 2}
              </span>
            )}
          </div>
        );
      },
    },
    {
      accessorKey: 'last_updated',
      header: 'Last Updated',
      cell: (info) => {
        const date = new Date(info.getValue());
        return (
          <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            {date.toLocaleDateString()}
          </span>
        );
      },
    },
  ];

  const handleRowClick = (policy) => {
    // Future: navigate to policy detail page
    console.log('Viewing policy:', policy.id);
  };

  const handleCreatePolicy = () => {
    router.push('/policies/add');
  };

  const filterOptions = [
    {
      name: 'category',
      label: 'Category',
      options: uniqueCategories,
    },
    {
      name: 'status',
      label: 'Status',
      options: ['active', 'draft', 'archived'],
    },
    {
      name: 'severity',
      label: 'Severity',
      options: uniqueSeverities,
    },
    {
      name: 'provider',
      label: 'Provider',
      options: uniqueProviders,
    },
  ];

  const handleFilterChange = (filterName, value) => {
    setActiveFilters((prev) => {
      const newFilters = { ...prev };
      if (newFilters[filterName].includes(value)) {
        newFilters[filterName] = newFilters[filterName].filter(
          (v) => v !== value
        );
      } else {
        newFilters[filterName] = [...newFilters[filterName], value];
      }
      return newFilters;
    });
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="rounded-xl p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--accent-danger)' }}>
          <p className="text-sm font-medium" style={{ color: 'var(--accent-danger)' }}>Error: {error}</p>
        </div>
      )}
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>
            Enterprise Policy Management
          </h1>
          <p className="mt-1" style={{ color: 'var(--text-tertiary)' }}>
            Security policy governance, compliance framework mapping, and effectiveness tracking
          </p>
        </div>
        <button
          onClick={handleCreatePolicy}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium transition-colors"
          style={{ backgroundColor: '#3b82f6' }}
        >
          <Plus className="w-4 h-4" />
          Create Policy
        </button>
      </div>

      {/* KPI Cards Grid - 6 cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <KpiCard
          title="Total Policies"
          value={policyStats.total}
          subtitle="Defined policies"
          icon={<FileText className="w-5 h-5" />}
          color="blue"
        />
        <KpiCard
          title="Active"
          value={policyStats.active}
          subtitle="In enforcement"
          icon={<Check className="w-5 h-5" />}
          color="green"
        />
        <KpiCard
          title="Draft"
          value={policyStats.draft}
          subtitle="Under development"
          icon={<Clock className="w-5 h-5" />}
          color="orange"
        />
        <KpiCard
          title="Total Violations"
          value={policyStats.total_violations}
          subtitle="Across all policies"
          icon={<AlertTriangle className="w-5 h-5" />}
          color="red"
        />
        <KpiCard
          title="Auto-Remediate Enabled"
          value={policyStats.auto_remediate_enabled}
          subtitle="Policies with auto-remediation"
          icon={<TrendingUp className="w-5 h-5" />}
          color="purple"
        />
        <KpiCard
          title="Avg Pass Rate"
          value={`${policyStats.avg_pass_rate}%`}
          subtitle="Overall policy compliance"
          icon={<BarChart3 className="w-5 h-5" />}
          color="green"
        />
      </div>

      {/* Policy Categories Summary Grid */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Policy Categories Summary
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Policies and violations by security domain
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {policyCategorySummary.map((cat, idx) => (
            <div key={idx} className="rounded-lg p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <h3 className="font-semibold text-sm mb-2" style={{ color: 'var(--text-primary)' }}>{cat.category}</h3>
              <div className="space-y-1">
                <div className="flex justify-between items-center">
                  <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>Policies</span>
                  <span className="font-bold text-sm" style={{ color: 'var(--text-primary)' }}>{cat.policies}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>Violations</span>
                  <span className="font-bold text-sm" style={{ color: cat.violations > 100 ? 'var(--accent-danger)' : 'var(--text-secondary)' }}>{cat.violations}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Policy Effectiveness Chart */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Most Violated Policies
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Top 10 policies by violation count
          </p>
        </div>
        <BarChartComponent
          data={topViolatedPolicies}
          dataKey="value"
          nameKey="name"
          title="Violations by Policy"
          colors={['#f97316']}
        />
      </div>

      {/* Policies DataTable */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            All Policies
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            {filteredPolicies.length} of {policies.length} policies
          </p>
        </div>

        {/* Filters */}
        <FilterBar
          filters={filterOptions}
          activeFilters={activeFilters}
          onFilterChange={handleFilterChange}
        />

        {/* Table */}
        <DataTable
          data={filteredPolicies}
          columns={columns}
          pageSize={15}
          onRowClick={handleRowClick}
          loading={loading}
          emptyMessage="No policies found matching your filters"
        />
      </div>

      {/* Active Exceptions */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Active Exception Management
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Approved exemptions with justification and expiry dates
          </p>
        </div>
        <div className="overflow-x-auto rounded-lg border" style={{ borderColor: 'var(--border-primary)' }}>
          <table className="w-full" style={{ backgroundColor: 'var(--bg-card)' }}>
            <thead style={{ backgroundColor: 'var(--bg-secondary)' }}>
              <tr>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Policy</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Resource</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Justification</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Approved By</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Expiry</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {activeExceptions.map((exc, idx) => (
                <tr key={idx} style={{ borderTop: `1px solid var(--border-primary)` }}>
                  <td className="px-4 py-3 text-sm font-medium max-w-xs" style={{ color: 'var(--text-primary)' }}>{exc.policy}</td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>
                    <code style={{ backgroundColor: 'var(--bg-tertiary)', padding: '2px 4px', borderRadius: '4px' }}>
                      {exc.resource}
                    </code>
                  </td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-tertiary)' }}>{exc.justification}</td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{exc.approved_by}</td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{exc.expiry}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs px-2 py-1 rounded font-semibold" style={{
                      backgroundColor: '#10b9812a',
                      color: '#10b981',
                    }}>
                      Active
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Policy Version History */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Recent Policy Changes
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Latest policy updates and version history
          </p>
        </div>
        <div className="space-y-3">
          {policyVersionHistory.map((entry, idx) => (
            <div key={idx} className="p-4 rounded-lg border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="flex items-start justify-between mb-2">
                <div className="flex-1">
                  <p className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>{entry.policy}</p>
                  <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>{entry.change}</p>
                </div>
                <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
                  v{entry.version}
                </span>
              </div>
              <div className="flex justify-between text-xs" style={{ color: 'var(--text-tertiary)' }}>
                <span>{entry.changed_by}</span>
                <span>{entry.date}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
