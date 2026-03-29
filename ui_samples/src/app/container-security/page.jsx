'use client';

import { useState, useEffect, useMemo } from 'react';
import {
  Container, Shield, AlertTriangle,
  CheckCircle, Box, Lock, KeyRound,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import SeverityBadge from '@/components/shared/SeverityBadge';
import PageLayout from '@/components/shared/PageLayout';

const DOMAIN_META = {
  cluster_security:  { label: 'Cluster Security',  icon: Shield,        color: '#8b5cf6' },
  workload_security: { label: 'Workload Security', icon: Box,           color: '#3b82f6' },
  image_security:    { label: 'Image Security',    icon: Container,     color: '#06b6d4' },
  network_exposure:  { label: 'Network Exposure',  icon: AlertTriangle, color: '#f97316' },
  rbac_access:       { label: 'RBAC Access',       icon: KeyRound,      color: '#22c55e' },
  runtime_audit:     { label: 'Runtime Audit',     icon: Lock,          color: '#eab308' },
};

export default function ContainerSecurityPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState({});

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await fetchView('container-security', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (result.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load container security data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  const pageContext = data.pageContext || {};
  const clusters = (data.data || {}).clusters || [];
  const findings = (data.data || {}).findings || [];
  const domainScores = (data.data || {}).domain_scores || {};

  // ── Column definitions ──

  const inventoryColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    {
      accessorKey: 'container_service', header: 'Service',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'cluster_name', header: 'Cluster' },
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
      accessorKey: 'logging_enabled', header: 'Logging',
      cell: (info) => {
        const v = info.getValue();
        return v
          ? <CheckCircle className="w-4 h-4 text-green-400" />
          : <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      },
    },
    {
      accessorKey: 'private_endpoint', header: 'Private Endpoint',
      cell: (info) => {
        const v = info.getValue();
        return v
          ? <CheckCircle className="w-4 h-4 text-green-400" />
          : <span className="text-xs" style={{ color: 'var(--text-muted)' }}>-</span>;
      },
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
    { accessorKey: 'container_service', header: 'Service' },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  // ── Domain score cards as insightRow ──
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

  // ── Helper ──
  const uv = (arr, key) => [...new Set(arr.map(r => r[key]).filter(Boolean))].sort();

  // ── Build tabData ──
  const tabData = useMemo(() => {
    const clusterSecFindings = findings.filter(f => f.security_domain === 'cluster_security');
    const imageSecFindings = findings.filter(f => f.security_domain === 'image_security');
    const rbacFindings = findings.filter(f => f.security_domain === 'rbac_access');

    const buildInventoryFilters = (arr) => {
      const f = [
        { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
      ];
      const serviceVals = uv(arr, 'container_service');
      if (serviceVals.length > 1) f.push({ key: 'container_service', label: 'Container Service', options: serviceVals });
      const clusterVals = uv(arr, 'cluster_name');
      if (clusterVals.length > 1) f.push({ key: 'cluster_name', label: 'Cluster', options: clusterVals });
      const accountVals = uv(arr, 'account_id');
      if (accountVals.length > 0) f.push({ key: 'account_id', label: 'Account', options: accountVals });
      const regionVals = uv(arr, 'region');
      if (regionVals.length > 0) f.push({ key: 'region', label: 'Region', options: regionVals });
      return f;
    };

    const buildFindingsFilters = (arr) => {
      const f = [
        { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
        { key: 'status', label: 'Status', options: ['FAIL', 'PASS'] },
      ];
      const domainVals = uv(arr, 'security_domain');
      if (domainVals.length > 1) f.push({ key: 'security_domain', label: 'Security Domain', options: domainVals });
      const serviceVals = uv(arr, 'container_service');
      if (serviceVals.length > 1) f.push({ key: 'container_service', label: 'Container Service', options: serviceVals });
      const clusterVals = uv(arr, 'cluster_name');
      if (clusterVals.length > 1) f.push({ key: 'cluster_name', label: 'Cluster', options: clusterVals });
      const accountVals = uv(arr, 'account_id');
      if (accountVals.length > 0) f.push({ key: 'account_id', label: 'Account', options: accountVals });
      const regionVals = uv(arr, 'region');
      if (regionVals.length > 0) f.push({ key: 'region', label: 'Region', options: regionVals });
      return f;
    };

    const buildFindingsExtras = (arr) => {
      const extras = [];
      const ruleVals = uv(arr, 'rule_id');
      if (ruleVals.length > 0) extras.push({ key: 'rule_id', label: 'Rule', options: ruleVals });
      return extras;
    };

    const inventoryGroupBy = [
      { key: 'container_service', label: 'Container Service' },
      { key: 'cluster_name', label: 'Cluster' },
      { key: 'account_id', label: 'Account' },
      { key: 'region', label: 'Region' },
    ];

    const findingsGroupBy = [
      { key: 'severity', label: 'Severity' },
      { key: 'status', label: 'Status' },
      { key: 'security_domain', label: 'Security Domain' },
      { key: 'container_service', label: 'Container Service' },
      { key: 'account_id', label: 'Account' },
      { key: 'region', label: 'Region' },
    ];

    return {
      overview: {
        data: clusters,
        columns: inventoryColumns,
        filters: buildInventoryFilters(clusters),
        extraFilters: [],
        groupByOptions: inventoryGroupBy,
      },
      inventory: {
        data: clusters,
        columns: inventoryColumns,
        filters: buildInventoryFilters(clusters),
        extraFilters: [],
        groupByOptions: inventoryGroupBy,
      },
      findings: {
        data: findings,
        columns: findingsColumns,
        filters: buildFindingsFilters(findings),
        extraFilters: buildFindingsExtras(findings),
        groupByOptions: findingsGroupBy,
      },
      cluster_security: {
        data: clusterSecFindings,
        columns: findingsColumns,
        filters: buildFindingsFilters(clusterSecFindings),
        extraFilters: buildFindingsExtras(clusterSecFindings),
        groupByOptions: findingsGroupBy,
      },
      image_security: {
        data: imageSecFindings,
        columns: findingsColumns,
        filters: buildFindingsFilters(imageSecFindings),
        extraFilters: buildFindingsExtras(imageSecFindings),
        groupByOptions: findingsGroupBy,
      },
      rbac: {
        data: rbacFindings,
        columns: findingsColumns,
        filters: buildFindingsFilters(rbacFindings),
        extraFilters: buildFindingsExtras(rbacFindings),
        groupByOptions: findingsGroupBy,
      },
    };
  }, [clusters, findings]);

  return (
    <PageLayout
      icon={Container}
      pageContext={pageContext}
      kpiGroups={data.kpiGroups || []}
      insightRow={insightRow}
      tabData={tabData}
      loading={loading}
      error={error}
    />
  );
}
