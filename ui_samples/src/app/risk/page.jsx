'use client';

import { useEffect, useState, useMemo } from 'react';
import { Activity } from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import InsightRow from '@/components/shared/InsightRow';
import SeverityBadge from '@/components/shared/SeverityBadge';
import BarChartComponent from '@/components/charts/BarChartComponent';

/** Format currency with USD locale */
const formatCurrency = (value) => {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 0,
    maximumFractionDigits: 0,
  }).format(value);
};

/** Map risk_rating string to SeverityBadge level */
const getRiskSeverity = (rating) => {
  const ratingMap = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
  return ratingMap[rating] || 'low';
};

export default function RiskPage() {
  const { provider, account, region } = useGlobalFilter();
  const [loading, setLoading] = useState(true);
  const [riskData, setRiskData] = useState(null);
  const [scenariosData, setScenariosData] = useState([]);
  const [error, setError] = useState(null);

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
        if (data.scenarios) setScenariosData(data.scenarios);
      } catch (err) {
        console.warn('Error fetching risk data:', err);
        setError('Failed to load risk data. Please check that the Risk engine is running.');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  const riskRegister = riskData?.riskRegister ?? riskData?.risk_register ?? [];
  const mitigationRoadmap = riskData?.mitigationRoadmap ?? riskData?.mitigation_roadmap ?? [];
  const criticalRisks = riskData?.criticalRisks ?? scenariosData.filter(r => r.risk_rating === 'critical' || r.risk_level === 'critical').length;
  const acceptedRisksCount = riskData?.acceptedRisks ?? riskData?.accepted_risks ?? 0;
  const riskScore = riskData?.riskScore ?? riskData?.risk_score ?? 0;
  const averageLoss = riskData?.averageLoss ?? riskData?.average_loss ?? 0;
  const riskReduction = riskData?.riskReduction || riskData?.risk_reduction || null;
  const complianceIndex = riskData?.complianceIndex || riskData?.compliance_index || null;

  // ── Risk Category data for bar chart ──
  const riskCategoryData = useMemo(() => {
    const categories = riskData?.riskCategories || riskData?.risk_categories || [];
    if (categories.length > 0) return categories;
    const regCategories = {};
    riskRegister.forEach(r => {
      if (!regCategories[r.category]) regCategories[r.category] = { name: r.category, inherent: 0, residual: 0, count: 0 };
      regCategories[r.category].inherent += r.inherent || 0;
      regCategories[r.category].residual += r.residual || 0;
      regCategories[r.category].count += 1;
    });
    return Object.values(regCategories).map(c => ({
      name: c.name,
      inherent: Math.round(c.inherent / c.count),
      residual: Math.round(c.residual / c.count),
    }));
  }, [riskData, riskRegister]);

  // ── Top scenarios bar chart data ──
  const topScenariosForChart = useMemo(() =>
    [...scenariosData]
      .sort((a, b) => b.expected_loss - a.expected_loss)
      .slice(0, 10)
      .map((s) => ({
        name: s.scenario_name.substring(0, 25) + (s.scenario_name.length > 25 ? '...' : ''),
        value: Math.round(s.expected_loss / 1000),
      })),
    [scenariosData]
  );

  // ── Scenario columns ──
  const scenarioColumns = [
    {
      accessorKey: 'scenario_name',
      header: 'Risk Scenario',
      cell: (info) => (
        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'threat_category',
      header: 'Threat Category',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'probability',
      header: 'Probability (%)',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}%</span>
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
      cell: (info) => <SeverityBadge severity={getRiskSeverity(info.getValue())} />,
    },
  ];

  // ── Risk Register columns ──
  const registerColumns = [
    {
      accessorKey: 'id',
      header: 'ID',
      size: 80,
      cell: (info) => (
        <span className="text-sm font-mono" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'title',
      header: 'Risk Title',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'category',
      header: 'Category',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'inherent',
      header: 'Inherent',
      size: 80,
      cell: (info) => {
        const val = info.getValue();
        return (
          <span className="text-sm font-bold text-center" style={{ color: val > 75 ? 'var(--accent-danger)' : 'var(--text-secondary)' }}>
            {val}
          </span>
        );
      },
    },
    {
      accessorKey: 'residual',
      header: 'Residual',
      size: 80,
      cell: (info) => {
        const val = info.getValue();
        return (
          <span className="text-sm font-bold text-center" style={{ color: val > 40 ? 'var(--accent-danger)' : 'var(--accent-success)' }}>
            {val}
          </span>
        );
      },
    },
    {
      accessorKey: 'owner',
      header: 'Owner',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'status',
      header: 'Status',
      size: 100,
      cell: (info) => {
        const status = info.getValue();
        const bg = status === 'Open' ? '#ef44442a' : status === 'Mitigated' ? '#10b9812a' : '#8b5cf62a';
        const color = status === 'Open' ? 'var(--accent-danger)' : status === 'Mitigated' ? 'var(--accent-success)' : '#8b5cf6';
        return (
          <span className="text-xs px-2 py-1 rounded font-semibold" style={{ backgroundColor: bg, color }}>
            {status}
          </span>
        );
      },
    },
  ];

  // ── Mitigation Roadmap columns ──
  const roadmapColumns = [
    {
      accessorKey: 'action',
      header: 'Action',
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'current_risk',
      header: 'Current Risk',
      size: 90,
      cell: (info) => (
        <span className="text-sm font-bold" style={{ color: 'var(--accent-warning)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'target_risk',
      header: 'Target Risk',
      size: 90,
      cell: (info) => (
        <span className="text-sm font-bold" style={{ color: 'var(--accent-success)' }}>{info.getValue()}</span>
      ),
    },
    {
      id: 'reduction',
      header: 'Reduction',
      size: 90,
      cell: ({ row }) => {
        const { current_risk, target_risk } = row.original;
        const reduction = current_risk ? ((current_risk - target_risk) / current_risk * 100).toFixed(0) : 0;
        return <span className="text-sm font-bold" style={{ color: '#10b981' }}>↓ {reduction}%</span>;
      },
    },
    {
      accessorKey: 'cost',
      header: 'Cost',
      size: 100,
      cell: (info) => (
        <span className="text-sm font-mono" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'priority',
      header: 'Priority',
      size: 90,
      cell: (info) => {
        const priority = info.getValue();
        const bg = priority === 'Critical' ? '#ef44442a' : '#f59e0b2a';
        const color = priority === 'Critical' ? 'var(--accent-danger)' : 'var(--accent-warning)';
        return (
          <span className="text-xs px-2 py-1 rounded font-semibold" style={{ backgroundColor: bg, color }}>
            {priority}
          </span>
        );
      },
    },
    {
      accessorKey: 'owner',
      header: 'Owner',
      size: 100,
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
    {
      accessorKey: 'due_date',
      header: 'Due Date',
      size: 100,
      cell: (info) => (
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      ),
    },
  ];

  // ── Filter defs per tab ──
  const scenarioFilterDefs = useMemo(() => {
    const f = [
      { key: 'risk_rating', label: 'Risk Rating', options: ['critical', 'high', 'medium', 'low'] },
    ];
    const categories = [...new Set(scenariosData.map(r => r.threat_category).filter(Boolean))].sort();
    if (categories.length > 1) f.push({ key: 'threat_category', label: 'Threat Category', options: categories });
    return f;
  }, [scenariosData]);

  const registerFilterDefs = useMemo(() => {
    const f = [];
    const categories = [...new Set(riskRegister.map(r => r.category).filter(Boolean))].sort();
    if (categories.length > 1) f.push({ key: 'category', label: 'Category', options: categories });
    f.push({ key: 'status', label: 'Status', options: [...new Set(riskRegister.map(r => r.status).filter(Boolean))].sort() });
    return f;
  }, [riskRegister]);

  const roadmapFilterDefs = useMemo(() => {
    const priorities = [...new Set(mitigationRoadmap.map(r => r.priority).filter(Boolean))].sort();
    return priorities.length > 0 ? [{ key: 'priority', label: 'Priority', options: priorities }] : [];
  }, [mitigationRoadmap]);

  const scenarioGroupByOpts = useMemo(() => [
    { key: 'risk_rating', label: 'Risk Rating' },
    { key: 'threat_category', label: 'Threat Category' },
  ], []);

  const registerGroupByOpts = useMemo(() => [
    { key: 'category', label: 'Category' },
    { key: 'status', label: 'Status' },
    { key: 'owner', label: 'Owner' },
  ], []);

  const roadmapGroupByOpts = useMemo(() => [
    { key: 'priority', label: 'Priority' },
    { key: 'owner', label: 'Owner' },
  ], []);

  // ── PageLayout props ──
  const pageContext = {
    title: 'Enterprise Risk Management',
    brief: 'Financial risk quantification, scenario modeling, and mitigation roadmap using FAIR methodology',
    details: [
      'Risk scenarios are scored using the FAIR (Factor Analysis of Information Risk) model.',
      'The heat map shows likelihood vs impact across all identified scenarios.',
      'Use the Risk Register tab to track risk ownership and mitigation status.',
    ],
    tabs: [
      { id: 'scenarios', label: 'Risk Scenarios', count: scenariosData.length },
      { id: 'register', label: 'Risk Register', count: riskRegister.length },
      { id: 'roadmap', label: 'Mitigation Roadmap', count: mitigationRoadmap.length },
    ],
  };

  const kpiGroups = [
    {
      title: 'Risk Exposure',
      items: [
        { label: 'Risk Score', value: `${riskScore}/100` },
        { label: 'Critical Risks', value: criticalRisks },
        { label: 'ALE', value: `$${(averageLoss / 1e6).toFixed(1)}M` },
      ],
    },
    {
      title: 'Mitigation',
      items: [
        { label: 'Accepted Risks', value: acceptedRisksCount },
        { label: 'Risk Reduction', value: riskReduction ? `${riskReduction}%` : '—' },
        { label: 'Compliance Index', value: complianceIndex ? `${complianceIndex}%` : '—' },
      ],
    },
  ];

  const tabData = {
    scenarios: {
      data: scenariosData,
      columns: scenarioColumns,
      filters: scenarioFilterDefs,
      groupByOptions: scenarioGroupByOpts,
    },
    register: {
      data: riskRegister,
      columns: registerColumns,
      filters: registerFilterDefs,
      groupByOptions: registerGroupByOpts,
    },
    roadmap: {
      data: mitigationRoadmap,
      columns: roadmapColumns,
      filters: roadmapFilterDefs,
      groupByOptions: roadmapGroupByOpts,
    },
  };

  // ── Insight Row: Heat Map (left) + Risk Category Bar Chart (right) ──
  const insightRowNode = (
    <InsightRow
      left={
        <div>
          <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Risk Heat Map</h3>
          <p className="text-xs mb-3" style={{ color: 'var(--text-tertiary)' }}>Likelihood vs Impact matrix</p>
          <div className="grid grid-cols-5 gap-1 text-xs">
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
          <div className="mt-2 text-[10px] space-y-0.5" style={{ color: 'var(--text-tertiary)' }}>
            <p className="font-semibold">Score: 0 (low) to 8 (critical)</p>
            <p>Horizontal: Likelihood | Vertical: Impact</p>
          </div>
        </div>
      }
      right={
        <div>
          <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Risk Category Breakdown</h3>
          <p className="text-xs mb-3" style={{ color: 'var(--text-tertiary)' }}>Inherent vs Residual Risk Scores</p>
          {riskCategoryData.length > 0 ? (
            <BarChartComponent
              data={riskCategoryData}
              dataKey="value"
              nameKey="name"
              title=""
              color="#ef4444"
            />
          ) : (
            <div className="flex items-center justify-center h-40">
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>No category data available</span>
            </div>
          )}
        </div>
      }
    />
  );

  return (
    <PageLayout
      icon={Activity}
      pageContext={pageContext}
      kpiGroups={kpiGroups}
      insightRow={insightRowNode}
      tabData={tabData}
      loading={loading}
      error={error}
    />
  );
}
