'use client';

import { useState, useEffect, useMemo } from 'react';
import { Shield, CheckCircle, AlertTriangle } from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';

export default function IamSecurityPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState({});

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await fetchView('iam', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (result.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load IAM data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  const identities = data.identities || [];
  const roles = data.roles || [];
  const accessKeys = data.accessKeys || [];
  const privilegeEscalation = data.privilegeEscalation || [];

  // ── Column definitions ──

  const overviewColumns = [
    { accessorKey: 'username', header: 'Identity' },
    {
      accessorKey: 'type', header: 'Type',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'account', header: 'Account' },
    { accessorKey: 'policies', header: 'Findings' },
    {
      accessorKey: 'severity', header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    {
      accessorKey: 'risk_score', header: 'Risk',
      cell: (info) => {
        const score = info.getValue();
        const color = score >= 75 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 25 ? '#eab308' : '#22c55e';
        return (
          <div className="flex items-center gap-2">
            <div className="w-14 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: color }} />
            </div>
            <span className="text-xs font-bold" style={{ color }}>{score}</span>
          </div>
        );
      },
    },
    {
      accessorKey: 'mfa', header: 'MFA',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-red-400" />,
    },
  ];

  const findingsColumns = [
    { accessorKey: 'name', header: 'Name' },
    {
      accessorKey: 'type', header: 'Type',
      cell: (info) => info.getValue() ? (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ) : null,
    },
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
  ];

  const accessKeyColumns = [
    { accessorKey: 'user', header: 'Name' },
    {
      accessorKey: 'type', header: 'Type',
      cell: (info) => info.getValue() ? (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ) : null,
    },
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
  ];

  // ── Helper: unique values from an array ──
  const uniqueVals = (arr, key) => [...new Set(arr.map(r => r[key]).filter(Boolean))].sort();

  // ── Build tabData ──
  const tabData = useMemo(() => {
    const overviewTypes = uniqueVals(identities, 'type');
    const overviewAccounts = uniqueVals(identities, 'account');
    const overviewRegions = uniqueVals(identities, 'region');

    const buildFindingsFilters = (arr) => {
      const f = [
        { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
        { key: 'status', label: 'Status', options: ['FAIL', 'PASS'] },
      ];
      const types = uniqueVals(arr, 'type');
      if (types.length > 1) f.push({ key: 'type', label: 'Type', options: types });
      const accounts = uniqueVals(arr, 'account_id');
      if (accounts.length > 0) f.push({ key: 'account_id', label: 'Account', options: accounts });
      const regions = uniqueVals(arr, 'region');
      if (regions.length > 0) f.push({ key: 'region', label: 'Region', options: regions });
      return f;
    };

    const buildFindingsExtraFilters = (arr) => {
      const extras = [];
      const ruleVals = uniqueVals(arr, 'rule_id');
      if (ruleVals.length > 0) extras.push({ key: 'rule_id', label: 'Rule', options: ruleVals });
      return extras;
    };

    const findingsGroupByOptions = [
      { key: 'severity', label: 'Severity' },
      { key: 'type', label: 'Type' },
      { key: 'status', label: 'Status' },
      { key: 'account_id', label: 'Account' },
      { key: 'region', label: 'Region' },
      { key: 'rule_id', label: 'Rule' },
    ];

    return {
      overview: {
        data: identities,
        columns: overviewColumns,
        filters: [
          { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
          ...(overviewTypes.length > 1 ? [{ key: 'type', label: 'Type', options: overviewTypes }] : []),
          ...(overviewAccounts.length > 0 ? [{ key: 'account', label: 'Account', options: overviewAccounts }] : []),
          ...(overviewRegions.length > 0 ? [{ key: 'region', label: 'Region', options: overviewRegions }] : []),
          { key: 'risk_score_range', label: 'Risk Score', options: [
            { value: '75', label: 'Critical (>75)' },
            { value: '50', label: 'High (>50)' },
            { value: '25', label: 'Medium (>25)' },
            { value: '0', label: 'Low (<25)' },
          ]},
        ],
        extraFilters: [],
        groupByOptions: [
          { key: 'type', label: 'Identity Type' },
          { key: 'severity', label: 'Severity' },
          { key: 'account', label: 'Account' },
        ],
      },
      roles: {
        data: roles,
        columns: findingsColumns,
        filters: buildFindingsFilters(roles),
        extraFilters: buildFindingsExtraFilters(roles),
        groupByOptions: findingsGroupByOptions,
      },
      access_keys: {
        data: accessKeys,
        columns: accessKeyColumns,
        filters: buildFindingsFilters(accessKeys),
        extraFilters: buildFindingsExtraFilters(accessKeys),
        groupByOptions: findingsGroupByOptions,
      },
      privilege_escalation: {
        data: privilegeEscalation,
        columns: findingsColumns,
        filters: buildFindingsFilters(privilegeEscalation),
        extraFilters: buildFindingsExtraFilters(privilegeEscalation),
        groupByOptions: findingsGroupByOptions,
      },
    };
  }, [identities, roles, accessKeys, privilegeEscalation]);

  return (
    <PageLayout
      icon={Shield}
      pageContext={data.pageContext}
      kpiGroups={data.kpiGroups}
      tabData={tabData}
      loading={loading}
      error={error}
      defaultTab="overview"
    />
  );
}
