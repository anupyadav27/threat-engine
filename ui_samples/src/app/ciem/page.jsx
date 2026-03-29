'use client';

import { useState, useEffect, useMemo } from 'react';
import { Eye } from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';

export default function CiemPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState({});

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await fetchView('ciem', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (result.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load CIEM data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  // ── Extract data ──
  const totalFindings = data.totalFindings || 0;
  const rulesTriggered = data.rulesTriggered || 0;
  const uniqueActors = data.uniqueActors || 0;
  const l2Findings = data.l2Findings || 0;
  const l3Findings = data.l3Findings || 0;
  const severityBreakdown = data.severityBreakdown || [];
  const topCritical = data.topCritical || [];
  const identities = data.identities || [];
  const topRules = data.topRules || [];
  const logSources = data.logSources || [];

  // ── Severity counts ──
  const sevCounts = {};
  severityBreakdown.forEach(s => { sevCounts[s.severity] = s.count; });

  // ── Helper: unique values from an array ──
  const uniqueVals = (arr, key) => [...new Set(arr.map(r => r[key]).filter(Boolean))].sort();

  // ── Page context ──
  const pageContext = {
    title: 'CIEM \u2014 Log Analysis',
    brief: 'Cloud log collection, threat detection, and identity risk analysis',
    tabs: [
      { id: 'overview', label: 'Overview', count: topCritical.length },
      { id: 'identities', label: 'Identity Risk', count: identities.length },
      { id: 'detections', label: 'Detection Rules', count: topRules.length },
      { id: 'events', label: 'Log Sources', count: logSources.length },
    ],
  };

  // ── KPI Groups ──
  const kpiGroups = [
    {
      title: 'Threat Summary',
      items: [
        { label: 'Total Findings', value: totalFindings },
        { label: 'Critical + High', value: (sevCounts.critical || 0) + (sevCounts.high || 0) },
        { label: 'Rules Triggered', value: rulesTriggered },
      ],
    },
    {
      title: 'Identity & Correlation',
      items: [
        { label: 'Identities at Risk', value: uniqueActors },
        { label: 'L2 Correlations', value: l2Findings },
        { label: 'L3 Anomalies', value: l3Findings },
      ],
    },
  ];

  // ── Column definitions ──

  const criticalColumns = [
    { accessorKey: 'severity', header: 'Severity', cell: ({ getValue }) => <SeverityBadge severity={getValue()} /> },
    { accessorKey: 'title', header: 'Detection' },
    { accessorKey: 'rule_id', header: 'Rule', cell: ({ getValue }) => (
      <span style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{getValue()}</span>
    )},
    { accessorKey: 'actor_principal', header: 'Actor', cell: ({ getValue }) => (
      <span style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{(getValue() || '').split('/').pop() || '-'}</span>
    )},
    { accessorKey: 'resource_uid', header: 'Resource', cell: ({ getValue }) => (
      <span style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{(getValue() || '').split('/').pop() || '-'}</span>
    )},
    { accessorKey: 'event_time', header: 'Time', cell: ({ getValue }) => getValue() ? new Date(getValue()).toLocaleString() : '-' },
  ];

  const identityColumns = [
    { accessorKey: 'actor_principal', header: 'Identity', cell: ({ getValue }) => (
      <span style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{(getValue() || '').split('/').pop()}</span>
    )},
    { accessorKey: 'risk_score', header: 'Risk', cell: ({ getValue }) => {
      const v = getValue() || 0;
      const color = v >= 80 ? '#ef4444' : v >= 50 ? '#f97316' : v >= 20 ? '#eab308' : '#22c55e';
      return <span style={{ color, fontWeight: 700 }}>{v}</span>;
    }},
    { accessorKey: 'total_findings', header: 'Findings' },
    { accessorKey: 'critical', header: 'Critical', cell: ({ getValue }) => (
      <span style={{ color: getValue() > 0 ? '#ef4444' : 'var(--text-muted)', fontWeight: getValue() > 0 ? 700 : 400 }}>{getValue() || 0}</span>
    )},
    { accessorKey: 'high', header: 'High', cell: ({ getValue }) => (
      <span style={{ color: getValue() > 0 ? '#f97316' : 'var(--text-muted)', fontWeight: getValue() > 0 ? 700 : 400 }}>{getValue() || 0}</span>
    )},
    { accessorKey: 'rules_triggered', header: 'Rules' },
    { accessorKey: 'services_used', header: 'Services' },
    { accessorKey: 'resources_touched', header: 'Resources' },
  ];

  const detectionColumns = [
    { accessorKey: 'rule_id', header: 'Rule ID', cell: ({ getValue }) => (
      <span style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{getValue()}</span>
    )},
    { accessorKey: 'severity', header: 'Severity', cell: ({ getValue }) => <SeverityBadge severity={getValue()} /> },
    { accessorKey: 'title', header: 'Title' },
    { accessorKey: 'finding_count', header: 'Findings' },
    { accessorKey: 'rule_source', header: 'Level', cell: ({ getValue }) => {
      const v = getValue();
      const label = v === 'correlation' ? 'L2' : v === 'baseline' ? 'L3' : 'L1';
      return <span style={{ padding: '2px 8px', borderRadius: 4, fontSize: '0.75rem', background: 'var(--bg-tertiary)' }}>{label}</span>;
    }},
    { accessorKey: 'unique_actors', header: 'Actors' },
    { accessorKey: 'unique_resources', header: 'Resources' },
  ];

  const eventColumns = [
    { accessorKey: 'source_type', header: 'Log Source' },
    { accessorKey: 'source_bucket', header: 'Location' },
    { accessorKey: 'source_region', header: 'Region' },
    { accessorKey: 'event_count', header: 'Events' },
    { accessorKey: 'earliest', header: 'First Event', cell: ({ getValue }) => getValue() ? new Date(getValue()).toLocaleString() : '-' },
    { accessorKey: 'latest', header: 'Last Event', cell: ({ getValue }) => getValue() ? new Date(getValue()).toLocaleString() : '-' },
  ];

  // ── Build tabData ──
  const tabData = useMemo(() => {
    // Overview tab
    const overviewRuleIds = uniqueVals(topCritical, 'rule_id');
    const overviewActors = uniqueVals(topCritical, 'actor_principal');
    const overviewFilters = [
      { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
      ...(overviewRuleIds.length > 0 ? [{ key: 'rule_id', label: 'Rule', options: overviewRuleIds }] : []),
      ...(overviewActors.length > 0 ? [{ key: 'actor_principal', label: 'Actor', options: overviewActors }] : []),
    ];

    // Identities tab
    const identityFilters = [
      { key: 'risk_score_range', label: 'Risk Score', options: [
        { value: '80', label: 'Critical (>=80)' },
        { value: '50', label: 'High (>=50)' },
        { value: '20', label: 'Medium (>=20)' },
        { value: '0', label: 'Low (<20)' },
      ]},
      { key: 'has_critical', label: 'Critical Findings', options: [
        { value: 'yes', label: 'Has Critical' },
        { value: 'no', label: 'No Critical' },
      ]},
      { key: 'has_high', label: 'High Findings', options: [
        { value: 'yes', label: 'Has High' },
        { value: 'no', label: 'No High' },
      ]},
    ];

    // Detections tab
    const detectionSources = uniqueVals(topRules, 'rule_source');
    const detectionFilters = [
      { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
      ...(detectionSources.length > 0 ? [{ key: 'rule_source', label: 'Level', options: detectionSources }] : []),
    ];

    // Events tab
    const eventSourceTypes = uniqueVals(logSources, 'source_type');
    const eventRegions = uniqueVals(logSources, 'source_region');
    const eventFilters = [
      ...(eventSourceTypes.length > 0 ? [{ key: 'source_type', label: 'Source Type', options: eventSourceTypes }] : []),
      ...(eventRegions.length > 0 ? [{ key: 'source_region', label: 'Region', options: eventRegions }] : []),
    ];

    return {
      overview: {
        data: topCritical,
        columns: criticalColumns,
        filters: overviewFilters,
        extraFilters: [],
        groupByOptions: [
          { key: 'severity', label: 'Severity' },
          { key: 'rule_id', label: 'Rule' },
        ],
      },
      identities: {
        data: identities,
        columns: identityColumns,
        filters: identityFilters,
        extraFilters: [],
        groupByOptions: [
          { key: 'risk_range', label: 'Risk Range' },
          { key: 'rules_triggered', label: 'Rules Triggered' },
        ],
      },
      detections: {
        data: topRules,
        columns: detectionColumns,
        filters: detectionFilters,
        extraFilters: [],
        groupByOptions: [
          { key: 'severity', label: 'Severity' },
          { key: 'rule_source', label: 'Level' },
        ],
      },
      events: {
        data: logSources,
        columns: eventColumns,
        filters: eventFilters,
        extraFilters: [],
        groupByOptions: [
          { key: 'source_type', label: 'Source Type' },
          { key: 'source_region', label: 'Region' },
        ],
      },
    };
  }, [topCritical, identities, topRules, logSources]);

  return (
    <PageLayout
      icon={Eye}
      pageContext={pageContext}
      kpiGroups={kpiGroups}
      tabData={tabData}
      loading={loading}
      error={error}
      defaultTab="overview"
    />
  );
}
