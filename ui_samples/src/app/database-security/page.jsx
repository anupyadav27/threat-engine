'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Database, Shield, AlertTriangle, AlertCircle, CheckCircle, Lock, KeyRound, FileText,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';

const DOMAIN_META = {
  access_control:   { label: 'Access Control',   icon: KeyRound,      color: '#8b5cf6' },
  encryption:       { label: 'Encryption',        icon: Lock,          color: '#3b82f6' },
  audit_logging:    { label: 'Audit Logging',     icon: FileText,      color: '#06b6d4' },
  backup_recovery:  { label: 'Backup & Recovery', icon: Shield,        color: '#22c55e' },
  network_security: { label: 'Network Security',  icon: Shield,        color: '#f97316' },
  configuration:    { label: 'Configuration',      icon: AlertTriangle, color: '#eab308' },
};

export default function DatabaseSecurityPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState({});

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await fetchView('database-security', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (result.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load database security data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  const pageContext = data.pageContext || {};
  const kpiGroups = data.kpiGroups || [];
  const databases = (data.data || {}).databases || [];
  const findings = (data.data || {}).findings || [];
  const domainScores = (data.data || {}).domain_scores || {};

  // ── Helper: unique values from an array ──
  const uniqueVals = (arr, key) => [...new Set(arr.map(r => r[key]).filter(Boolean))].sort();

  // ── Column definitions ──

  const inventoryColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    {
      accessorKey: 'db_service', header: 'DB Service',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'db_engine', header: 'DB Engine' },
    {
      accessorKey: 'posture_score', header: 'Posture Score',
      cell: (info) => {
        const score = info.getValue();
        const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';
        return <span className="text-xs font-bold" style={{ color }}>{score ?? '-'}</span>;
      },
    },
    {
      accessorKey: 'publicly_accessible', header: 'Public',
      cell: (info) => {
        const v = info.getValue();
        const isPublic = v === true || v === 'true' || v === 'True' || v === 'yes';
        return isPublic
          ? <AlertTriangle className="w-4 h-4 text-red-400" />
          : <CheckCircle className="w-4 h-4 text-green-400" />;
      },
    },
    {
      accessorKey: 'encryption', header: 'Encryption',
      cell: (info) => {
        const v = info.getValue();
        const encrypted = v === 'encrypted' || v === 'enabled' || v === true;
        return encrypted
          ? <CheckCircle className="w-4 h-4 text-green-400" />
          : <AlertTriangle className="w-4 h-4 text-red-400" />;
      },
    },
    {
      accessorKey: 'iam_auth', header: 'IAM Auth',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    },
    {
      accessorKey: 'backup', header: 'Backup',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    },
    {
      accessorKey: 'multi_az', header: 'Multi-AZ',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <span className="text-xs" style={{ color: 'var(--text-muted)' }}>-</span>,
    },
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
    {
      accessorKey: 'security_domain', header: 'Domain',
      cell: (info) => {
        const v = info.getValue();
        const meta = DOMAIN_META[v];
        return (
          <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: meta?.color || 'var(--text-secondary)' }}>
            {meta?.label || v}
          </span>
        );
      },
    },
    { accessorKey: 'db_service', header: 'DB Service' },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  // ── Domain score cards as insightRow (only when overview data is available) ──
  const insightRow = useMemo(() => {
    if (Object.keys(domainScores).length === 0) return null;
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {Object.entries(DOMAIN_META).map(([key, meta]) => {
          const score = domainScores[key] ?? 0;
          const Icon = meta.icon;
          const scoreColor = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444';
          return (
            <div key={key} className="rounded-lg p-4" style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
              <div className="flex items-center gap-2 mb-2">
                <span style={{ color: meta.color }}><Icon className="w-4 h-4" /></span>
                <span className="text-[10px] uppercase tracking-wide font-medium" style={{ color: 'var(--text-muted)' }}>{meta.label}</span>
              </div>
              <div className="text-2xl font-bold tabular-nums" style={{ color: scoreColor }}>
                {score}<span className="text-xs font-normal ml-0.5" style={{ color: 'var(--text-tertiary)' }}>/100</span>
              </div>
            </div>
          );
        })}
      </div>
    );
  }, [domainScores]);

  // ── Build tabData ──
  const tabData = useMemo(() => {
    const accessControlFindings = findings.filter(f => f.security_domain === 'access_control');
    const encryptionFindings = findings.filter(f => f.security_domain === 'encryption');
    const auditFindings = findings.filter(f => f.security_domain === 'audit_logging');

    const buildInventoryFilters = (arr) => {
      const f = [];
      const dbServiceVals = uniqueVals(arr, 'db_service');
      if (dbServiceVals.length > 1) f.push({ key: 'db_service', label: 'DB Service', options: dbServiceVals });
      const dbEngineVals = uniqueVals(arr, 'db_engine');
      if (dbEngineVals.length > 1) f.push({ key: 'db_engine', label: 'DB Engine', options: dbEngineVals });
      const accountVals = uniqueVals(arr, 'account_id');
      if (accountVals.length > 0) f.push({ key: 'account_id', label: 'Account', options: accountVals });
      const regionVals = uniqueVals(arr, 'region');
      if (regionVals.length > 0) f.push({ key: 'region', label: 'Region', options: regionVals });
      return f;
    };

    const buildFindingsFilters = (arr) => {
      const f = [
        { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
        { key: 'status', label: 'Status', options: ['FAIL', 'PASS'] },
      ];
      const domainVals = uniqueVals(arr, 'security_domain');
      if (domainVals.length > 1) f.push({ key: 'security_domain', label: 'Security Domain', options: domainVals });
      const dbServiceVals = uniqueVals(arr, 'db_service');
      if (dbServiceVals.length > 1) f.push({ key: 'db_service', label: 'DB Service', options: dbServiceVals });
      const dbEngineVals = uniqueVals(arr, 'db_engine');
      if (dbEngineVals.length > 1) f.push({ key: 'db_engine', label: 'DB Engine', options: dbEngineVals });
      const accountVals = uniqueVals(arr, 'account_id');
      if (accountVals.length > 0) f.push({ key: 'account_id', label: 'Account', options: accountVals });
      const regionVals = uniqueVals(arr, 'region');
      if (regionVals.length > 0) f.push({ key: 'region', label: 'Region', options: regionVals });
      return f;
    };

    const buildFindingsExtraFilters = (arr) => {
      const extras = [];
      const ruleVals = uniqueVals(arr, 'rule_id');
      if (ruleVals.length > 0) extras.push({ key: 'rule_id', label: 'Rule', options: ruleVals });
      return extras;
    };

    const inventoryGroupBy = [
      { key: 'db_service', label: 'DB Service' },
      { key: 'db_engine', label: 'DB Engine' },
      { key: 'account_id', label: 'Account' },
      { key: 'region', label: 'Region' },
    ];

    const findingsGroupBy = [
      { key: 'severity', label: 'Severity' },
      { key: 'status', label: 'Status' },
      { key: 'security_domain', label: 'Security Domain' },
      { key: 'db_service', label: 'DB Service' },
      { key: 'account_id', label: 'Account' },
      { key: 'region', label: 'Region' },
    ];

    return {
      overview: {
        data: databases,
        columns: inventoryColumns,
        filters: buildInventoryFilters(databases),
        extraFilters: [],
        groupByOptions: inventoryGroupBy,
      },
      inventory: {
        data: databases,
        columns: inventoryColumns,
        filters: buildInventoryFilters(databases),
        extraFilters: [],
        groupByOptions: inventoryGroupBy,
      },
      findings: {
        data: findings,
        columns: findingsColumns,
        filters: buildFindingsFilters(findings),
        extraFilters: buildFindingsExtraFilters(findings),
        groupByOptions: findingsGroupBy,
      },
      access_control: {
        data: accessControlFindings,
        columns: findingsColumns,
        filters: buildFindingsFilters(accessControlFindings),
        extraFilters: buildFindingsExtraFilters(accessControlFindings),
        groupByOptions: findingsGroupBy,
      },
      encryption: {
        data: encryptionFindings,
        columns: findingsColumns,
        filters: buildFindingsFilters(encryptionFindings),
        extraFilters: buildFindingsExtraFilters(encryptionFindings),
        groupByOptions: findingsGroupBy,
      },
      audit_logging: {
        data: auditFindings,
        columns: findingsColumns,
        filters: buildFindingsFilters(auditFindings),
        extraFilters: buildFindingsExtraFilters(auditFindings),
        groupByOptions: findingsGroupBy,
      },
    };
  }, [databases, findings]);

  return (
    <PageLayout
      icon={Database}
      pageContext={pageContext}
      kpiGroups={kpiGroups}
      insightRow={insightRow}
      tabData={tabData}
      loading={loading}
      error={error}
      defaultTab="overview"
    />
  );
}
