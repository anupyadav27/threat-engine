'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Lock, Key, Shield, AlertTriangle,
  AlertCircle, CheckCircle,
} from 'lucide-react';
import { fetchView, getFromEngine } from '@/lib/api';
import { TENANT_ID } from '@/lib/constants';
import { useGlobalFilter } from '@/lib/global-filter-context';
import SeverityBadge from '@/components/shared/SeverityBadge';
import PageLayout from '@/components/shared/PageLayout';

export default function EncryptionPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState({});
  const [remediations, setRemediations] = useState([]);
  const [remFetched, setRemFetched] = useState(false);

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await fetchView('encryption', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (result.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load encryption data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  // Fetch remediations once (eagerly so the tab data is ready)
  useEffect(() => {
    if (remFetched) return;
    const fetchRemediations = async () => {
      try {
        const result = await getFromEngine('gateway', '/api/v1/encryption/remediations', {
          tenant_id: TENANT_ID,
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (!result.error) {
          const items = Array.isArray(result) ? result : (result.remediations || []);
          setRemediations(items.sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0)));
        }
      } catch (_) { /* handled by main error state */ }
      setRemFetched(true);
    };
    fetchRemediations();
  }, [provider, account, region, remFetched]);

  // ── Extract data arrays ──
  const overview = data.overview || [];
  const findings = data.findings || [];
  const keys = data.keys || [];
  const certificates = data.certificates || [];
  const secrets = data.secrets || [];

  // Ensure remediations tab exists in pageContext
  const pageContext = useMemo(() => {
    const ctx = data.pageContext || {};
    const serverTabs = ctx.tabs || [];
    const hasRemTab = serverTabs.some(t => t.id === 'remediations');
    return {
      ...ctx,
      tabs: hasRemTab ? serverTabs : [...serverTabs, { id: 'remediations', label: 'Remediations' }],
    };
  }, [data.pageContext]);

  // ── Column definitions ──

  const overviewColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    {
      accessorKey: 'resource_type', header: 'Type',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'account', header: 'Account' },
    {
      accessorKey: 'encryption_status', header: 'Encrypted',
      cell: (info) => {
        const v = info.getValue();
        const encrypted = v === 'encrypted' || v === 'enabled' || v === true;
        return encrypted
          ? <CheckCircle className="w-4 h-4 text-green-400" />
          : <AlertTriangle className="w-4 h-4 text-red-400" />;
      },
    },
    {
      accessorKey: 'severity', header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    { accessorKey: 'findings_count', header: 'Findings' },
    { accessorKey: 'region', header: 'Region' },
  ];

  const findingsColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    { accessorKey: 'rule_id', header: 'Rule' },
    {
      accessorKey: 'severity', header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'status', header: 'Status',
      cell: (info) => {
        const v = info.getValue();
        const isFail = v === 'FAIL';
        return (
          <span className={`text-xs px-2 py-0.5 rounded ${isFail ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>{v}</span>
        );
      },
    },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
    { accessorKey: 'resource_type', header: 'Type' },
  ];

  const keysColumns = [
    { accessorKey: 'key_id', header: 'Key ID' },
    { accessorKey: 'alias', header: 'Alias' },
    {
      accessorKey: 'key_type', header: 'Key Type',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'algorithm', header: 'Algorithm' },
    {
      accessorKey: 'status', header: 'Status',
      cell: (info) => {
        const v = info.getValue();
        const isEnabled = v === 'Enabled' || v === 'enabled' || v === 'ACTIVE';
        return (
          <span className={`text-xs px-2 py-0.5 rounded ${isEnabled ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}`}>{v}</span>
        );
      },
    },
    {
      accessorKey: 'rotation_enabled', header: 'Rotation',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  const certificatesColumns = [
    { accessorKey: 'domain', header: 'Domain' },
    { accessorKey: 'issuer', header: 'Issuer' },
    {
      accessorKey: 'status', header: 'Status',
      cell: (info) => {
        const v = info.getValue();
        const isValid = v === 'ISSUED' || v === 'valid' || v === 'ACTIVE';
        return (
          <span className={`text-xs px-2 py-0.5 rounded ${isValid ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>{v}</span>
        );
      },
    },
    { accessorKey: 'expires_at', header: 'Expires' },
    {
      accessorKey: 'days_until_expiry', header: 'Days Left',
      cell: (info) => {
        const days = info.getValue();
        const color = days <= 7 ? '#ef4444' : days <= 30 ? '#f97316' : days <= 90 ? '#eab308' : '#22c55e';
        return <span className="text-xs font-bold" style={{ color }}>{days}</span>;
      },
    },
    { accessorKey: 'key_algorithm', header: 'Algorithm' },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  const secretsColumns = [
    { accessorKey: 'name', header: 'Secret Name' },
    {
      accessorKey: 'type', header: 'Type',
      cell: (info) => info.getValue() ? (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ) : null,
    },
    {
      accessorKey: 'rotation_enabled', header: 'Rotation',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    },
    { accessorKey: 'last_rotated', header: 'Last Rotated' },
    {
      accessorKey: 'severity', header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  const remediationsColumns = [
    { accessorKey: 'title', header: 'Remediation' },
    {
      accessorKey: 'priority', header: 'Priority',
      cell: (info) => {
        const priority = info.getValue();
        const config = {
          'P1-URGENT': { bg: 'bg-red-500/20', text: 'text-red-400' },
          'P2-HIGH': { bg: 'bg-orange-500/20', text: 'text-orange-400' },
          'P3-MEDIUM': { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
          'P4-LOW': { bg: 'bg-slate-500/20', text: 'text-slate-400' },
        };
        const c = config[priority] || config['P4-LOW'];
        return (
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold ${c.bg} ${c.text}`}>
            {priority || 'P4-LOW'}
          </span>
        );
      },
    },
    {
      accessorKey: 'severity', header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    { accessorKey: 'resource_uid', header: 'Resource' },
    {
      accessorKey: 'resource_type', header: 'Type',
      cell: (info) => info.getValue() ? (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ) : null,
    },
    { accessorKey: 'priority_score', header: 'Score' },
  ];

  // ── Helper to build dynamic filter options from a dataset ──
  const uv = (arr, key) => [...new Set(arr.map(r => r[key]).filter(Boolean))].sort();

  // ── Build tabData ──
  const tabData = useMemo(() => {
    const buildFilters = (arr, tab) => {
      const f = [
        { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
      ];
      if (tab !== 'overview') {
        f.push({ key: 'status', label: 'Status', options: ['FAIL', 'PASS'] });
      }
      const encStatusVals = uv(arr, 'encryption_status');
      if (encStatusVals.length > 1) f.push({ key: 'encryption_status', label: 'Encryption Status', options: encStatusVals });
      const keyTypeVals = uv(arr, 'key_type');
      if (keyTypeVals.length > 1) f.push({ key: 'key_type', label: 'Key Type', options: keyTypeVals });
      const acctKey = tab === 'overview' ? 'account' : 'account_id';
      const accountVals = uv(arr, acctKey);
      if (accountVals.length > 0) f.push({ key: acctKey, label: 'Account', options: accountVals });
      const regionVals = uv(arr, 'region');
      if (regionVals.length > 0) f.push({ key: 'region', label: 'Region', options: regionVals });
      return f;
    };

    const buildExtras = (arr, tab) => {
      const extras = [];
      if (tab === 'findings') {
        const ruleVals = uv(arr, 'rule_id');
        if (ruleVals.length > 0) extras.push({ key: 'rule_id', label: 'Rule', options: ruleVals });
      }
      if (tab === 'keys') {
        const algorithmVals = uv(arr, 'algorithm');
        if (algorithmVals.length > 0) extras.push({ key: 'algorithm', label: 'Algorithm', options: algorithmVals });
      }
      if (tab === 'certificates') {
        const issuerVals = uv(arr, 'issuer');
        if (issuerVals.length > 0) extras.push({ key: 'issuer', label: 'Issuer', options: issuerVals });
      }
      return extras;
    };

    const buildGroupBy = (tab) => {
      if (tab === 'overview') {
        return [
          { key: 'resource_type', label: 'Resource Type' },
          { key: 'severity', label: 'Severity' },
          { key: 'account', label: 'Account' },
        ];
      }
      if (tab === 'keys') {
        return [
          { key: 'key_type', label: 'Key Type' },
          { key: 'algorithm', label: 'Algorithm' },
          { key: 'account_id', label: 'Account' },
          { key: 'region', label: 'Region' },
        ];
      }
      if (tab === 'certificates') {
        return [
          { key: 'issuer', label: 'Issuer' },
          { key: 'status', label: 'Status' },
          { key: 'account_id', label: 'Account' },
          { key: 'region', label: 'Region' },
        ];
      }
      return [
        { key: 'severity', label: 'Severity' },
        { key: 'status', label: 'Status' },
        { key: 'account_id', label: 'Account' },
        { key: 'region', label: 'Region' },
        { key: 'rule_id', label: 'Rule' },
      ];
    };

    return {
      overview: {
        data: overview,
        columns: overviewColumns,
        filters: buildFilters(overview, 'overview'),
        extraFilters: buildExtras(overview, 'overview'),
        groupByOptions: buildGroupBy('overview'),
      },
      findings: {
        data: findings,
        columns: findingsColumns,
        filters: buildFilters(findings, 'findings'),
        extraFilters: buildExtras(findings, 'findings'),
        groupByOptions: buildGroupBy('findings'),
      },
      keys: {
        data: keys,
        columns: keysColumns,
        filters: buildFilters(keys, 'keys'),
        extraFilters: buildExtras(keys, 'keys'),
        groupByOptions: buildGroupBy('keys'),
      },
      certificates: {
        data: certificates,
        columns: certificatesColumns,
        filters: buildFilters(certificates, 'certificates'),
        extraFilters: buildExtras(certificates, 'certificates'),
        groupByOptions: buildGroupBy('certificates'),
      },
      secrets: {
        data: secrets,
        columns: secretsColumns,
        filters: buildFilters(secrets, 'secrets'),
        extraFilters: buildExtras(secrets, 'secrets'),
        groupByOptions: buildGroupBy('secrets'),
      },
      remediations: {
        data: remediations,
        columns: remediationsColumns,
        filters: buildFilters(remediations, 'remediations'),
        extraFilters: [],
        groupByOptions: [
          { key: 'priority', label: 'Priority' },
          { key: 'severity', label: 'Severity' },
          { key: 'resource_type', label: 'Resource Type' },
        ],
      },
    };
  }, [overview, findings, keys, certificates, secrets, remediations]);

  return (
    <PageLayout
      icon={Lock}
      pageContext={pageContext}
      kpiGroups={data.kpiGroups || []}
      insightRow={null}
      tabData={tabData}
      loading={loading}
      error={error}
    />
  );
}
