'use client';

import { useEffect, useState, useMemo } from 'react';
import {
  Activity,
  Shield,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import MetricStrip from '@/components/shared/MetricStrip';
import FilterBar from '@/components/shared/FilterBar';
import SeverityBadge from '@/components/shared/SeverityBadge';
import DataTable from '@/components/shared/DataTable';
import TrendLine from '@/components/charts/TrendLine';
import BarChartComponent from '@/components/charts/BarChartComponent';

/**
 * Risk Quantification & FAIR Model Analysis Dashboard
 * Displays financial risk metrics, trend analysis, and scenario breakdown
 */
export default function RiskPage() {
  const { provider, account, region, filterSummary } = useGlobalFilter();
  const [loading, setLoading] = useState(true);
  const [riskData, setRiskData] = useState(null);
  const [selectedScenario, setSelectedScenario] = useState(null);
  const [riskTrendData, setRiskTrendData] = useState([]);
  const [scenariosData, setScenariosData] = useState([]);
  const [activeFilters, setActiveFilters] = useState({});
  const [search, setSearch] = useState('');
  const [groupBy, setGroupBy] = useState('');
  const [expandedGroups, setExpandedGroups] = useState({});

  const [error, setError] = useState(null);

  const handleFilterChange = (key, value) => {
    setActiveFilters(prev => ({ ...prev, [key]: value }));
  };

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const data = await fetchView('risk', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (data.error) { setError(data.error); return; }
        setRiskData(data);
        if (data.trendData) setRiskTrendData(data.trendData);
        if (data.scenarios) {
          setScenariosData(data.scenarios);
          if (data.scenarios.length > 0) setSelectedScenario(data.scenarios[0]);
        }
      } catch (err) {
        console.warn('Error fetching risk data:', err);
        setError('Failed to load risk data. Please check that the Risk engine is running.');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [provider, account, region]);

  // BFF handles scope filtering — scopeFiltered is now just scenariosData
  const scopeFiltered = scenariosData;

  // Derived MetricStrip values
  const criticalRisks = riskData?.criticalRisks ?? scopeFiltered.filter(r => r.risk_rating === 'critical' || r.risk_level === 'critical').length;
  const acceptedRisksCount = riskData?.acceptedRisks ?? riskData?.accepted_risks ?? 0;

  // Format currency with proper formatting
  const formatCurrency = (value) => {
    const formatter = new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0,
    });
    return formatter.format(value);
  };

  // Get severity level for risk rating
  const getRiskSeverity = (rating) => {
    const ratingMap = {
      critical: 'critical',
      high: 'high',
      medium: 'medium',
      low: 'low',
    };
    return ratingMap[rating] || 'low';
  };

  // Prepare top scenarios data for bar chart
  const topScenariosForChart = scenariosData
    .sort((a, b) => b.expected_loss - a.expected_loss)
    .slice(0, 10)
    .map((s) => ({
      name: s.scenario_name.substring(0, 25) + (s.scenario_name.length > 25 ? '...' : ''),
      value: Math.round(s.expected_loss / 1000), // In thousands
    }));

  // ── Unique values for filter options ──
  const uniqueVals = (key) => [...new Set(scopeFiltered.map(r => r[key]).filter(Boolean))].sort();

  // Primary filters (always visible)
  const primaryFilters = useMemo(() => {
    const f = [
      { key: 'risk_rating', label: 'Risk Rating', options: ['critical', 'high', 'medium', 'low'] },
    ];
    const categories = uniqueVals('threat_category');
    if (categories.length > 1) f.push({ key: 'threat_category', label: 'Threat Category', options: categories });
    const accounts = uniqueVals('account');
    if (accounts.length > 0) f.push({ key: 'account', label: 'Account', options: accounts });
    return f;
  }, [scopeFiltered]);

  // Group-by options
  const groupByOptions = useMemo(() => [
    { key: 'risk_rating', label: 'Risk Rating' },
    { key: 'threat_category', label: 'Threat Category' },
    { key: 'account', label: 'Account' },
  ], []);

  // Apply search + filters
  const filtered = useMemo(() => {
    let result = scopeFiltered;
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(row =>
        Object.values(row).some(v => v && String(v).toLowerCase().includes(q))
      );
    }
    Object.entries(activeFilters).forEach(([key, value]) => {
      if (!value) return;
      result = result.filter(row => {
        const rowVal = row[key];
        if (!rowVal) return false;
        return String(rowVal).toLowerCase() === value.toLowerCase();
      });
    });
    return result;
  }, [scopeFiltered, search, activeFilters]);

  // Group data
  const grouped = useMemo(() => {
    if (!groupBy || !filtered.length) return null;
    const groups = {};
    filtered.forEach(row => {
      const key = String(row[groupBy] || 'Other');
      if (!groups[key]) groups[key] = [];
      groups[key].push(row);
    });
    return Object.entries(groups)
      .sort(([, a], [, b]) => b.length - a.length)
      .map(([key, items]) => ({ key, items, count: items.length }));
  }, [filtered, groupBy]);

  // Auto-expand all groups when groupBy changes
  useEffect(() => {
    if (grouped) {
      const expanded = {};
      grouped.forEach(g => { expanded[g.key] = true; });
      setExpandedGroups(expanded);
    }
  }, [groupBy]);

  const toggleGroup = (key) => {
    setExpandedGroups(prev => ({ ...prev, [key]: !prev[key] }));
  };

  // Table columns for scenarios
  const scenarioColumns = [
    {
      accessorKey: 'scenario_name',
      header: 'Risk Scenario',
      cell: (info) => (
        <span className="text-sm font-medium transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'threat_category',
      header: 'Threat Category',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'probability',
      header: 'Probability (%)',
      cell: (info) => (
        <span className="text-sm transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}%</span>
      ),
    },
    {
      accessorKey: 'expected_loss',
      header: 'Expected Loss',
      cell: (info) => (
        <span className="text-sm font-semibold text-green-400">
          {formatCurrency(info.getValue())}
        </span>
      ),
    },
    {
      accessorKey: 'worst_case_loss',
      header: 'Worst Case Loss',
      cell: (info) => (
        <span className="text-sm font-semibold text-orange-400">
          {formatCurrency(info.getValue())}
        </span>
      ),
    },
    {
      accessorKey: 'risk_rating',
      header: 'Risk Rating',
      cell: (info) => (
        <SeverityBadge severity={getRiskSeverity(info.getValue())} />
      ),
    },
  ];

  const riskRegister = riskData?.riskRegister ?? riskData?.risk_register ?? [];
  const mitigation_roadmap = riskData?.mitigationRoadmap ?? riskData?.mitigation_roadmap ?? [];

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
          Enterprise Risk Management & FAIR Analysis
        </h1>
        {filterSummary && (
          <p className="text-xs mt-0.5 mb-2" style={{ color: 'var(--text-tertiary)' }}>
            <span style={{ color: 'var(--accent-primary)' }}>Filtered to:</span>{' '}
            <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{filterSummary}</span>
          </p>
        )}
        <p className="mt-1 transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
          Financial risk quantification, scenario modeling, and mitigation roadmap using FAIR methodology
        </p>
      </div>

      {/* Error state */}
      {error && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: 'var(--accent-danger)' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      )}

      {/* MetricStrip */}
      <MetricStrip groups={[
        {
          label: '🔴 RISK EXPOSURE',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'RISK SCORE', value: (riskData?.riskScore ?? riskData?.risk_score ?? 0) + '/100', valueColor: 'var(--severity-critical)', delta: riskData?.risk_score_change ?? 0, deltaGoodDown: true, context: 'vs last month' },
            { label: 'CRITICAL RISKS', value: criticalRisks, valueColor: 'var(--severity-critical)', context: 'active scenarios' },
            { label: 'ALE', value: '$' + ((riskData?.averageLoss ?? riskData?.average_loss ?? 0) / 1e6).toFixed(1) + 'M', valueColor: 'var(--severity-high)', noTrend: true, context: 'annual loss exposure' },
          ],
        },
        {
          label: '🔵 MITIGATION',
          color: 'var(--accent-primary)',
          cells: [
            { label: 'ACCEPTED RISKS', value: acceptedRisksCount, noTrend: true, context: 'formally accepted' },
            { label: 'RISK REDUCTION', value: (riskData?.riskReduction || riskData?.risk_reduction) ? `${riskData.riskReduction || riskData.risk_reduction}%` : '—', valueColor: 'var(--accent-success)', noTrend: true, context: 'this month' },
            { label: 'COMPLIANCE INDEX', value: (riskData?.complianceIndex || riskData?.compliance_index) ? `${riskData.complianceIndex || riskData.compliance_index}%` : '—', noTrend: true, context: 'overall posture' },
          ],
        },
      ]} />

      {/* Risk Heat Map and Category Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Heat Map */}
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Risk Heat Map</h2>
            <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>Likelihood vs Impact matrix</p>
          </div>
          <div className="rounded-lg p-4 border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
            <div className="grid grid-cols-5 gap-1 text-xs">
              {/* Heat map grid visualization */}
              {Array.from({ length: 25 }).map((_, idx) => {
                const likelihood = Math.floor(idx / 5);
                const impact = idx % 5;
                const risk = likelihood + impact;
                let bgColor = '#10b981';
                if (risk >= 7) bgColor = '#ef4444';
                else if (risk >= 5) bgColor = '#f97316';
                else if (risk >= 3) bgColor = '#eab308';
                return (
                  <div
                    key={idx}
                    className="aspect-square rounded flex items-center justify-center font-bold text-white text-xs"
                    style={{ backgroundColor: bgColor }}
                  >
                    {risk}
                  </div>
                );
              })}
            </div>
            <div className="mt-3 text-xs space-y-1" style={{ color: 'var(--text-tertiary)' }}>
              <p className="font-semibold">Legend: Score ranges from 0 (low) to 8 (critical)</p>
              <p>Horizontal: Likelihood (Rare → Almost Certain)</p>
              <p>Vertical: Impact (Negligible → Catastrophic)</p>
            </div>
          </div>
        </div>

        {/* Risk Category Breakdown */}
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Risk Category Breakdown</h2>
            <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>Inherent vs Residual Risk Scores</p>
          </div>
          <BarChartComponent
            data={(() => {
              const categories = riskData?.riskCategories || riskData?.risk_categories || [];
              if (categories.length > 0) return categories;
              // Derive from risk register if available
              const regCategories = {};
              riskRegister.forEach(r => {
                if (!regCategories[r.category]) regCategories[r.category] = { name: r.category, inherent: 0, residual: 0, count: 0 };
                regCategories[r.category].inherent += r.inherent || 0;
                regCategories[r.category].residual += r.residual || 0;
                regCategories[r.category].count += 1;
              });
              const derived = Object.values(regCategories).map(c => ({
                name: c.name,
                inherent: Math.round(c.inherent / c.count),
                residual: Math.round(c.residual / c.count),
              }));
              return derived.length > 0 ? derived : [];
            })()}
            dataKey="value"
            nameKey="name"
            title="Risk by Category"
            colors={['#ef4444', '#10b981']}
          />
        </div>
      </div>

      {/* Risk Scenarios DataTable */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Risk Scenarios Inventory</h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Complete list of identified risk scenarios with financial impact estimates
          </p>
        </div>

        {/* Filter Bar (search + filters + group by) */}
        <FilterBar
          search={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search scenarios..."
          filters={primaryFilters}
          onFilterChange={handleFilterChange}
          activeFilters={activeFilters}
          groupByOptions={groupByOptions}
          groupBy={groupBy}
          onGroupByChange={setGroupBy}
        />

        {/* Grouped or flat table */}
        {grouped ? (
          <div className="space-y-3">
            {grouped.map(({ key, items, count }) => (
              <div key={key} className="rounded-lg border" style={{ borderColor: 'var(--border-primary)' }}>
                <button
                  onClick={() => toggleGroup(key)}
                  className="w-full flex items-center gap-2 px-4 py-2.5 text-sm font-medium"
                  style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)' }}
                >
                  {expandedGroups[key] ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                  <span>{key}</span>
                  <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{count}</span>
                </button>
                {expandedGroups[key] && (
                  <DataTable data={items} columns={scenarioColumns} pageSize={25} hideToolbar onRowClick={(scenario) => setSelectedScenario(scenario)} />
                )}
              </div>
            ))}
            <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>
              {grouped.length} groups, {filtered.length} total rows
            </div>
          </div>
        ) : (
          <DataTable
            data={filtered}
            columns={scenarioColumns}
            pageSize={10}
            loading={loading}
            emptyMessage="No risk scenarios available"
            onRowClick={(scenario) => setSelectedScenario(scenario)}
          />
        )}
      </div>

      {/* Financial Impact Analysis (FAIR Model) */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Top Risk Scenarios by Expected Loss
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Annual Loss Expectancy (ALE) estimates for critical risk scenarios
          </p>
        </div>
        <BarChartComponent
          data={topScenariosForChart}
          dataKey="value"
          nameKey="name"
          title="Expected Loss by Scenario (in thousands USD)"
          colors={['#f97316']}
        />
      </div>

      {/* Risk Register */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Risk Register
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Identified risks with inherent/residual scores and mitigation status
          </p>
        </div>
        <div className="overflow-x-auto rounded-lg border" style={{ borderColor: 'var(--border-primary)' }}>
          <table className="w-full" style={{ backgroundColor: 'var(--bg-card)' }}>
            <thead style={{ backgroundColor: 'var(--bg-secondary)' }}>
              <tr>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>ID</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Risk Title</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Category</th>
                <th className="px-4 py-3 text-center text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Inherent</th>
                <th className="px-4 py-3 text-center text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Residual</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Owner</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {riskRegister.length === 0 ? (
                <tr><td colSpan={7} className="px-4 py-6 text-center text-sm" style={{ color: 'var(--text-muted)' }}>No risk register data available</td></tr>
              ) : riskRegister.map((risk, idx) => (
                <tr key={idx} style={{ borderTop: `1px solid var(--border-primary)` }}>
                  <td className="px-4 py-3 text-sm font-mono" style={{ color: 'var(--text-secondary)' }}>{risk.id}</td>
                  <td className="px-4 py-3 text-sm max-w-xs" style={{ color: 'var(--text-primary)' }}>{risk.title}</td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-tertiary)' }}>{risk.category}</td>
                  <td className="px-4 py-3 text-center text-sm font-bold" style={{ color: risk.inherent > 75 ? 'var(--accent-danger)' : 'var(--text-secondary)' }}>
                    {risk.inherent}
                  </td>
                  <td className="px-4 py-3 text-center text-sm font-bold" style={{ color: risk.residual > 40 ? 'var(--accent-danger)' : 'var(--accent-success)' }}>
                    {risk.residual}
                  </td>
                  <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{risk.owner}</td>
                  <td className="px-4 py-3">
                    <span className="text-xs px-2 py-1 rounded font-semibold" style={{
                      backgroundColor: risk.status === 'Open' ? '#ef44442a' : risk.status === 'Mitigated' ? '#10b9812a' : '#8b5cf62a',
                      color: risk.status === 'Open' ? 'var(--accent-danger)' : risk.status === 'Mitigated' ? 'var(--accent-success)' : '#8b5cf6',
                    }}>
                      {risk.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Mitigation Roadmap */}
      <div className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
            Risk Mitigation Roadmap
          </h2>
          <p className="text-sm" style={{ color: 'var(--text-tertiary)' }}>
            Top 10 mitigation actions sorted by risk reduction potential
          </p>
        </div>
        <div className="overflow-x-auto rounded-lg border" style={{ borderColor: 'var(--border-primary)' }}>
          <table className="w-full" style={{ backgroundColor: 'var(--bg-card)' }}>
            <thead style={{ backgroundColor: 'var(--bg-secondary)' }}>
              <tr>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Action</th>
                <th className="px-4 py-3 text-center text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Current Risk</th>
                <th className="px-4 py-3 text-center text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Target Risk</th>
                <th className="px-4 py-3 text-center text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Reduction</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Cost</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Priority</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Owner</th>
                <th className="px-4 py-3 text-left text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Due Date</th>
              </tr>
            </thead>
            <tbody>
              {mitigation_roadmap.length === 0 ? (
                <tr><td colSpan={8} className="px-4 py-6 text-center text-sm" style={{ color: 'var(--text-muted)' }}>No mitigation roadmap data available</td></tr>
              ) : mitigation_roadmap.map((action, idx) => {
                const reduction = ((action.current_risk - action.target_risk) / action.current_risk * 100).toFixed(0);
                return (
                  <tr key={idx} style={{ borderTop: `1px solid var(--border-primary)` }}>
                    <td className="px-4 py-3 text-sm max-w-sm" style={{ color: 'var(--text-primary)' }}>{action.action}</td>
                    <td className="px-4 py-3 text-center text-sm font-bold" style={{ color: 'var(--accent-warning)' }}>{action.current_risk}</td>
                    <td className="px-4 py-3 text-center text-sm font-bold" style={{ color: 'var(--accent-success)' }}>{action.target_risk}</td>
                    <td className="px-4 py-3 text-center text-sm font-bold" style={{ color: '#10b981' }}>↓ {reduction}%</td>
                    <td className="px-4 py-3 text-sm font-mono" style={{ color: 'var(--text-secondary)' }}>{action.cost}</td>
                    <td className="px-4 py-3">
                      <span className="text-xs px-2 py-1 rounded font-semibold" style={{
                        backgroundColor: action.priority === 'Critical' ? '#ef44442a' : '#f59e0b2a',
                        color: action.priority === 'Critical' ? 'var(--accent-danger)' : 'var(--accent-warning)',
                      }}>
                        {action.priority}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{action.owner}</td>
                    <td className="px-4 py-3 text-sm" style={{ color: 'var(--text-secondary)' }}>{action.due_date}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* FAIR Model Breakdown Section */}
      {selectedScenario && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-semibold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
              FAIR Model Deep Dive: {selectedScenario.scenario_name}
            </h2>
            <p className="text-sm transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              Financial impact factors and annual loss expectancy calculation for selected scenario
            </p>
          </div>

          {/* FAIR Components Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Threat Event Frequency */}
            <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-lg bg-blue-500/20">
                    <Activity className="w-5 h-5 text-blue-400" />
                  </div>
                  <h3 className="text-sm font-semibold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>Threat Event Frequency</h3>
                </div>
              </div>
              <div className="space-y-3">
                <div>
                  <p className="text-3xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                    {(selectedScenario.threat_event_frequency * 100).toFixed(1)}%
                  </p>
                  <p className="text-xs mt-1 transition-colors duration-200" style={{ color: 'var(--text-muted)' }}>
                    {selectedScenario.threat_event_frequency === 0.25
                      ? 'Likely 1x per 4 years'
                      : selectedScenario.threat_event_frequency === 0.15
                        ? 'Likely 1x per 6-7 years'
                        : selectedScenario.threat_event_frequency === 0.30
                          ? 'Likely 1x per 3 years'
                          : selectedScenario.threat_event_frequency === 0.20
                            ? 'Likely 1x per 5 years'
                            : 'Based on threat analysis'}
                  </p>
                </div>
                <div className="pt-2 border-t transition-colors duration-200" style={{ borderColor: 'var(--border-primary)' }}>
                  <p className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>Estimated probability of threat occurring annually</p>
                </div>
              </div>
            </div>

            {/* Vulnerability Factor */}
            <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-lg bg-orange-500/20">
                    <Shield className="w-5 h-5 text-orange-400" />
                  </div>
                  <h3 className="text-sm font-semibold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>Vulnerability Factor</h3>
                </div>
              </div>
              <div className="space-y-3">
                <div>
                  <p className="text-3xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                    {(selectedScenario.vulnerability * 100).toFixed(0)}%
                  </p>
                  <p className="text-xs mt-1 transition-colors duration-200" style={{ color: 'var(--text-muted)' }}>
                    {selectedScenario.vulnerability > 0.7
                      ? 'High exposure'
                      : selectedScenario.vulnerability > 0.5
                        ? 'Moderate exposure'
                        : 'Lower exposure'}
                  </p>
                </div>
                <div className="pt-2 border-t transition-colors duration-200" style={{ borderColor: 'var(--border-primary)' }}>
                  <p className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>Probability that threat would succeed if attempted</p>
                </div>
              </div>
            </div>

            {/* Loss Magnitude */}
            <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-3 rounded-lg bg-red-500/20">
                    <Activity className="w-5 h-5 text-red-400" />
                  </div>
                  <h3 className="text-sm font-semibold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>Loss Magnitude</h3>
                </div>
              </div>
              <div className="space-y-3">
                <div>
                  <p className="text-2xl font-bold transition-colors duration-200" style={{ color: 'var(--text-primary)' }}>
                    {formatCurrency(selectedScenario.loss_magnitude)}
                  </p>
                  <p className="text-xs mt-1 transition-colors duration-200" style={{ color: 'var(--text-muted)' }}>Average loss amount</p>
                </div>
                <div className="pt-2 border-t transition-colors duration-200" style={{ borderColor: 'var(--border-primary)' }}>
                  <p className="text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>Financial impact per successful event</p>
                </div>
              </div>
            </div>
          </div>

          {/* FAIR Formula Explanation */}
          <div className="rounded-xl p-6 border transition-colors duration-200" style={{ backgroundColor: 'var(--bg-card)', opacity: 0.5, borderColor: 'var(--border-primary)' }}>
            <h4 className="text-sm font-semibold mb-3 transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>FAIR Model Calculation</h4>
            <div className="space-y-2 text-xs transition-colors duration-200" style={{ color: 'var(--text-tertiary)' }}>
              <p>
                <span className="font-semibold transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>Annual Loss Expectancy (ALE)</span>
                {' = TEF × Vulnerability × Loss Magnitude'}
              </p>
              <p>
                <span className="font-semibold transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                  {(selectedScenario.threat_event_frequency * 100).toFixed(1)}%
                </span>
                {' × '}
                <span className="font-semibold transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                  {(selectedScenario.vulnerability * 100).toFixed(0)}%
                </span>
                {' × '}
                <span className="font-semibold transition-colors duration-200" style={{ color: 'var(--text-secondary)' }}>
                  {formatCurrency(selectedScenario.loss_magnitude)}
                </span>
                {' = '}
                <span className="text-green-400 font-semibold">
                  {formatCurrency(selectedScenario.expected_loss)}
                </span>
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
