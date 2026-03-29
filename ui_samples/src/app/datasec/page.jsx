'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Database,
  Lock,
  AlertTriangle,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import InsightRow from '@/components/shared/InsightRow';
import SeverityBadge from '@/components/shared/SeverityBadge';
import SeverityDonut from '@/components/charts/SeverityDonut';

/**
 * Enterprise Data Security and Classification Page
 * Uses PageLayout for standardized rendering.
 */
export default function DataSecurityPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [realCatalog, setRealCatalog] = useState([]);
  const [realClassification, setRealClassification] = useState([]);
  const [dlpViolations, setDlpViolations] = useState([]);
  const [encryptionData, setEncryptionData] = useState([]);
  const [dataResidency, setDataResidency] = useState([]);
  const [accessMonitoring, setAccessMonitoring] = useState([]);

  const { provider, account, region } = useGlobalFilter();

  // ── Data fetch ──────────────────────────────────────────────────────────────

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchView('datasec', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (data.error) { setError(data.error); return; }
        if (data.catalog)          setRealCatalog(data.catalog);
        if (data.classifications)  setRealClassification(data.classifications);
        if (data.dlp)              setDlpViolations(data.dlp);
        if (data.encryption)       setEncryptionData(data.encryption);
        if (data.residency)        setDataResidency(data.residency);
        if (data.accessMonitoring) setAccessMonitoring(data.accessMonitoring);
      } catch (err) {
        console.warn('Error fetching data security data:', err);
        setError(err?.message || 'Failed to load data security data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  // ── Derived KPIs ────────────────────────────────────────────────────────────

  const scopeFiltered = realCatalog;

  const sensitiveExposed = scopeFiltered.filter(d =>
    ['PII', 'PHI', 'Sensitive'].includes(d.classification) &&
    (d.public_access === true || d.encryption === 'None' || d.encryption === false)
  ).length;
  const unencryptedCount = scopeFiltered.filter(d =>
    d.encrypted === false || d.encryption === 'None' || d.encryption_status === 'unencrypted'
  ).length;
  const dlpViolationCount = dlpViolations.length;
  const classifiedPct = Math.round(
    scopeFiltered.filter(d => d.classification && d.classification !== 'Unknown').length /
    Math.max(scopeFiltered.length, 1) * 100
  );
  const encryptedPct = Math.round(
    scopeFiltered.filter(d =>
      d.encrypted === true || (d.encryption && d.encryption !== 'None' && d.encryption !== 'Unknown')
    ).length / Math.max(scopeFiltered.length, 1) * 100
  );

  const unencryptedStores = scopeFiltered.filter(d => !d.encryption || d.encryption === 'None' || d.encryption === 'Unknown').length;
  const publicAccessStores = scopeFiltered.filter(d => d.public_access).length;
  const dataRiskScore = Math.min(100, Math.round(
    (unencryptedStores + publicAccessStores * 2) / Math.max(scopeFiltered.length, 1) * 100
  )) || 0;

  // Classification donut data
  const classificationColorMap = { PII: '#ef4444', PHI: '#f97316', PCI: '#eab308', Confidential: '#8b5cf6', Secrets: '#ec4899', Internal: '#3b82f6', Public: '#6b7280' };
  const classificationData = Object.entries(
    realClassification.reduce((acc, c) => { acc[c.type] = (acc[c.type] || 0) + (c.count || 1); return acc; }, {})
  ).map(([name, value]) => ({ name, value, color: classificationColorMap[name] || '#6b7280' }));

  // ── Unique value helpers (per dataset) ──────────────────────────────────────

  const uniqueFrom = (arr, key) => [...new Set(arr.map(r => r[key]).filter(Boolean))].sort();

  // ── Filter definitions per tab ──────────────────────────────────────────────

  const catalogFilters = useMemo(() => {
    const f = [];
    const types = uniqueFrom(realCatalog, 'type');
    if (types.length > 0) f.push({ key: 'type', label: 'Type', options: types });
    const providers = uniqueFrom(realCatalog, 'provider');
    if (providers.length > 0) f.push({ key: 'provider', label: 'Provider', options: providers });
    const regions = uniqueFrom(realCatalog, 'region');
    if (regions.length > 0) f.push({ key: 'region', label: 'Region', options: regions });
    const classifications = uniqueFrom(realCatalog, 'classification');
    if (classifications.length > 0) f.push({ key: 'classification', label: 'Classification', options: classifications });
    const encryptions = uniqueFrom(realCatalog, 'encryption');
    if (encryptions.length > 0) f.push({ key: 'encryption', label: 'Encryption', options: encryptions });
    return f;
  }, [realCatalog]);

  const classificationFilters = useMemo(() => {
    const f = [];
    const types = uniqueFrom(realClassification, 'type');
    if (types.length > 0) f.push({ key: 'type', label: 'Type', options: types });
    f.push({ key: 'confidence', label: 'Confidence', options: [
      { value: '90', label: 'High (>=90%)' },
      { value: '70', label: 'Medium (>=70%)' },
      { value: '0', label: 'Low (<70%)' },
    ]});
    return f;
  }, [realClassification]);

  const encryptionFilters = useMemo(() => {
    const f = [];
    const types = uniqueFrom(encryptionData, 'type');
    if (types.length > 0) f.push({ key: 'type', label: 'Type', options: types });
    const statuses = uniqueFrom(encryptionData, 'status');
    if (statuses.length > 0) f.push({ key: 'status', label: 'Status', options: statuses });
    return f;
  }, [encryptionData]);

  const residencyFilters = useMemo(() => {
    const f = [];
    const statuses = uniqueFrom(dataResidency, 'status');
    if (statuses.length > 0) f.push({ key: 'status', label: 'Status', options: statuses });
    return f;
  }, [dataResidency]);

  const accessFilters = useMemo(() => {
    const f = [];
    const actions = uniqueFrom(accessMonitoring, 'action');
    if (actions.length > 0) f.push({ key: 'action', label: 'Action', options: actions });
    f.push({ key: 'anomaly', label: 'Anomaly', options: [
      { value: 'true', label: 'Detected' },
      { value: 'false', label: 'Normal' },
    ]});
    return f;
  }, [accessMonitoring]);

  const dlpFilters = useMemo(() => {
    const f = [];
    const types = uniqueFrom(dlpViolations, 'type');
    if (types.length > 0) f.push({ key: 'type', label: 'Type', options: types });
    const severities = uniqueFrom(dlpViolations, 'severity');
    if (severities.length > 0) f.push({ key: 'severity', label: 'Severity', options: severities });
    const actions = uniqueFrom(dlpViolations, 'action');
    if (actions.length > 0) f.push({ key: 'action', label: 'Action', options: actions });
    return f;
  }, [dlpViolations]);

  // ── Column definitions ──────────────────────────────────────────────────────

  const catalogColumns = [
    { accessorKey: 'name', header: 'Name', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'type', header: 'Type', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'provider', header: 'Provider', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span> },
    { accessorKey: 'region', header: 'Region', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'classification', header: 'Classification', cell: (info) => {
      const t = info.getValue();
      const colorMap = { PII:'bg-red-500/20 text-red-300', PHI:'bg-orange-500/20 text-orange-300', PCI:'bg-yellow-500/20 text-yellow-300', Confidential:'bg-purple-500/20 text-purple-300', Internal:'bg-blue-500/20 text-blue-300', Public:'bg-slate-500/20 text-slate-300' };
      return <span className={`text-xs px-2 py-1 rounded ${colorMap[t] || 'bg-slate-700 text-slate-300'}`}>{t}</span>;
    }},
    { accessorKey: 'encryption', header: 'Encryption', cell: (info) => (
      <div className="flex items-center gap-2">
        {info.getValue() !== 'None' ? <Lock className="w-4 h-4 text-green-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
        <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>
      </div>
    )},
    { accessorKey: 'owner', header: 'Owner', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span> },
  ];

  const classificationColumns = [
    { accessorKey: 'name', header: 'Pattern', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'type', header: 'Type', cell: (info) => {
      const typeMap = { PII:'bg-red-500/20 text-red-300', PHI:'bg-orange-500/20 text-orange-300', PCI:'bg-yellow-500/20 text-yellow-300', Secrets:'bg-pink-500/20 text-pink-300', Public:'bg-blue-500/20 text-blue-300' };
      return <span className={`text-xs px-2 py-1 rounded ${typeMap[info.getValue()]}`}>{info.getValue()}</span>;
    }},
    { accessorKey: 'count', header: 'Records Found', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue().toLocaleString()}</span> },
    { accessorKey: 'locations', header: 'Locations', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()} stores</span> },
    { accessorKey: 'confidence', header: 'Confidence', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}%</span> },
  ];

  const encryptionColumns = [
    { accessorKey: 'resource', header: 'Resource', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'type', header: 'Encryption Type', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'rotation', header: 'Key Rotation', cell: (info) => <span className="text-sm">{info.getValue()}</span> },
    { accessorKey: 'status', header: 'Status', cell: (info) => {
      const s = info.getValue();
      return s === 'encrypted'
        ? <span className="text-xs px-2 py-1 rounded bg-green-500/20 text-green-400">Encrypted</span>
        : <span className="text-xs px-2 py-1 rounded bg-red-500/20 text-red-400">Unencrypted</span>;
    }},
  ];

  const residencyColumns = [
    { accessorKey: 'region', header: 'Region', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'assets', header: 'Data Stores', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'compliance', header: 'Compliance Frameworks', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span> },
    { accessorKey: 'status', header: 'Status', cell: (info) => {
      const s = info.getValue();
      return s === 'compliant'
        ? <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-green-500" /><span className="text-sm text-green-400">Compliant</span></div>
        : <div className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-red-500" /><span className="text-sm text-red-400">Non-compliant</span></div>;
    }},
  ];

  const accessColumns = [
    { accessorKey: 'timestamp', header: 'Timestamp', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{new Date(info.getValue()).toLocaleString()}</span> },
    { accessorKey: 'resource', header: 'Resource', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'user', header: 'User/Service', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'action', header: 'Action', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'location', header: 'Location', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'anomaly', header: 'Anomaly', cell: (info) => (
      info.getValue()
        ? <span className="text-xs px-2 py-1 rounded bg-orange-500/20 text-orange-400">Detected</span>
        : <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>Normal</span>
    )},
  ];

  const dlpColumns = [
    { accessorKey: 'type', header: 'Violation Type', cell: (info) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</span> },
    { accessorKey: 'resource', header: 'Resource', cell: (info) => <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'data_type', header: 'Data Type', cell: (info) => <span className="text-xs px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{info.getValue()}</span> },
    { accessorKey: 'severity', header: 'Severity', cell: (info) => <SeverityBadge severity={info.getValue()} /> },
    { accessorKey: 'action', header: 'Action Taken', cell: (info) => <span className="text-sm">{info.getValue()}</span> },
    { accessorKey: 'timestamp', header: 'Timestamp', cell: (info) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{new Date(info.getValue()).toLocaleDateString()}</span> },
  ];

  // ── PageLayout props ────────────────────────────────────────────────────────

  const pageContext = {
    title: 'Data Security',
    brief: 'Data catalog, classification, encryption, residency, and access monitoring',
    tabs: [
      { id: 'catalog',        label: 'Data Catalog',      count: realCatalog.length },
      { id: 'classification', label: 'Classification',     count: realClassification.length },
      { id: 'encryption',     label: 'Encryption',         count: encryptionData.length },
      { id: 'residency',      label: 'Data Residency',     count: dataResidency.length },
      { id: 'access',         label: 'Access Monitoring',  count: accessMonitoring.length },
      { id: 'dlp',            label: 'DLP',                count: dlpViolations.length },
    ],
  };

  const kpiGroups = [
    {
      title: 'Data Risk',
      items: [
        { label: 'Sensitive Exposed', value: sensitiveExposed },
        { label: 'Unencrypted Stores', value: unencryptedCount },
        { label: 'DLP Violations', value: dlpViolationCount },
      ],
    },
    {
      title: 'Coverage',
      items: [
        { label: 'Stores Monitored', value: scopeFiltered.length },
        { label: 'Classified', value: classifiedPct + '%' },
        { label: 'Encrypted', value: encryptedPct + '%' },
      ],
    },
  ];

  const riskLabel = dataRiskScore >= 70 ? 'High risk' : dataRiskScore >= 30 ? 'Moderate risk' : 'Low risk';

  const insightRowEl = (
    <InsightRow
      ratio="1fr 2fr"
      left={
        <div className="flex flex-col items-center justify-center h-full">
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Data Risk Score</h3>
          <div className="text-4xl font-bold" style={{ color: '#f97316' }}>{dataRiskScore}/100</div>
          <p className="text-sm mt-2" style={{ color: 'var(--text-tertiary)' }}>{riskLabel}</p>
        </div>
      }
      right={
        <div>
          <h3 className="text-lg font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>Classification Distribution</h3>
          <div className="flex justify-center">
            {classificationData.length > 0 ? (
              <SeverityDonut data={classificationData} title="Records" />
            ) : (
              <p className="text-sm py-10" style={{ color: 'var(--text-muted)' }}>No classification data available</p>
            )}
          </div>
        </div>
      }
    />
  );

  const tabData = {
    catalog: {
      data: realCatalog,
      columns: catalogColumns,
      filters: catalogFilters,
      groupByOptions: [
        { key: 'type', label: 'Type' },
        { key: 'provider', label: 'Provider' },
        { key: 'region', label: 'Region' },
        { key: 'classification', label: 'Classification' },
        { key: 'encryption', label: 'Encryption' },
      ],
    },
    classification: {
      data: realClassification,
      columns: classificationColumns,
      filters: classificationFilters,
      groupByOptions: [
        { key: 'type', label: 'Type' },
      ],
    },
    encryption: {
      data: encryptionData,
      columns: encryptionColumns,
      filters: encryptionFilters,
      groupByOptions: [
        { key: 'type', label: 'Type' },
        { key: 'status', label: 'Status' },
      ],
    },
    residency: {
      data: dataResidency,
      columns: residencyColumns,
      filters: residencyFilters,
      groupByOptions: [
        { key: 'status', label: 'Status' },
      ],
    },
    access: {
      data: accessMonitoring,
      columns: accessColumns,
      filters: accessFilters,
      groupByOptions: [
        { key: 'action', label: 'Action' },
        { key: 'anomaly', label: 'Anomaly' },
      ],
    },
    dlp: {
      data: dlpViolations,
      columns: dlpColumns,
      filters: dlpFilters,
      groupByOptions: [
        { key: 'type', label: 'Type' },
        { key: 'severity', label: 'Severity' },
      ],
    },
  };

  return (
    <PageLayout
      icon={Database}
      pageContext={pageContext}
      kpiGroups={kpiGroups}
      insightRow={insightRowEl}
      tabData={tabData}
      loading={loading}
      error={error}
      defaultTab="catalog"
    />
  );
}
