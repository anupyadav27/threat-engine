'use client';

import { useState, useEffect, useMemo } from 'react';
import { Network, AlertTriangle, CheckCircle } from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import PageLayout from '@/components/shared/PageLayout';
import SeverityBadge from '@/components/shared/SeverityBadge';

export default function NetworkSecurityPage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState({});

  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await fetchView('network-security', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (result.error) { setError(result.error); return; }
        setData(result);
      } catch (err) {
        setError(err?.message || 'Failed to load network security data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);

  const findings = (data.data || {}).findings || [];
  const securityGroups = (data.data || {}).security_groups || [];
  const internetExposure = (data.data || {}).internet_exposure || [];
  const topology = (data.data || {}).topology || [];
  const waf = (data.data || {}).waf || [];

  // ── Column definitions ──

  const findingsColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    { accessorKey: 'rule_id', header: 'Rule' },
    {
      accessorKey: 'module', header: 'Module',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
          {info.getValue()}
        </span>
      ),
    },
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

  const sgColumns = [
    { accessorKey: 'group_name', header: 'Security Group' },
    { accessorKey: 'group_id', header: 'Group ID' },
    { accessorKey: 'vpc_id', header: 'VPC' },
    {
      accessorKey: 'open_to_internet', header: 'Open to Internet',
      cell: (info) => info.getValue()
        ? <AlertTriangle className="w-4 h-4 text-red-400" />
        : <CheckCircle className="w-4 h-4 text-green-400" />,
    },
    { accessorKey: 'inbound_rules', header: 'Inbound Rules' },
    { accessorKey: 'outbound_rules', header: 'Outbound Rules' },
    {
      accessorKey: 'severity', header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  const exposureColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    { accessorKey: 'resource_type', header: 'Type' },
    {
      accessorKey: 'exposure_type', header: 'Exposure',
      cell: (info) => (
        <span className="text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-400">
          {info.getValue()}
        </span>
      ),
    },
    { accessorKey: 'ports', header: 'Ports' },
    { accessorKey: 'protocols', header: 'Protocols' },
    {
      accessorKey: 'severity', header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  const topologyColumns = [
    { accessorKey: 'vpc_id', header: 'VPC' },
    { accessorKey: 'cidr_block', header: 'CIDR' },
    { accessorKey: 'subnets', header: 'Subnets' },
    { accessorKey: 'peering_connections', header: 'Peering' },
    { accessorKey: 'transit_gateways', header: 'TGW' },
    { accessorKey: 'internet_gateways', header: 'IGW' },
    { accessorKey: 'nat_gateways', header: 'NAT' },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  const wafColumns = [
    { accessorKey: 'resource_name', header: 'Resource' },
    {
      accessorKey: 'waf_enabled', header: 'WAF',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-red-400" />,
    },
    {
      accessorKey: 'shield_enabled', header: 'Shield',
      cell: (info) => info.getValue()
        ? <CheckCircle className="w-4 h-4 text-green-400" />
        : <AlertTriangle className="w-4 h-4 text-yellow-400" />,
    },
    { accessorKey: 'web_acl_name', header: 'Web ACL' },
    { accessorKey: 'rule_count', header: 'Rules' },
    {
      accessorKey: 'severity', header: 'Severity',
      cell: (info) => <SeverityBadge severity={info.getValue()} />,
    },
    { accessorKey: 'account_id', header: 'Account' },
    { accessorKey: 'region', header: 'Region' },
  ];

  // ── Helper: unique values from an array ──
  const uniqueVals = (arr, key) => [...new Set(arr.map(r => r[key]).filter(Boolean))].sort();

  // ── Build tabData ──
  const tabData = useMemo(() => {
    const buildFilters = (arr) => {
      const f = [
        { key: 'severity', label: 'Severity', options: ['critical', 'high', 'medium', 'low'] },
      ];
      const moduleVals = uniqueVals(arr, 'module');
      if (moduleVals.length > 1) f.push({ key: 'module', label: 'Module', options: moduleVals });
      const rtVals = uniqueVals(arr, 'resource_type');
      if (rtVals.length > 1) f.push({ key: 'resource_type', label: 'Resource Type', options: rtVals });
      const accountVals = uniqueVals(arr, 'account_id');
      if (accountVals.length > 0) f.push({ key: 'account_id', label: 'Account', options: accountVals });
      const regionVals = uniqueVals(arr, 'region');
      if (regionVals.length > 0) f.push({ key: 'region', label: 'Region', options: regionVals });
      return f;
    };

    const defaultGroupByOptions = [
      { key: 'severity', label: 'Severity' },
      { key: 'module', label: 'Module' },
      { key: 'resource_type', label: 'Resource Type' },
      { key: 'account_id', label: 'Account' },
      { key: 'region', label: 'Region' },
    ];

    const findingsExtraFilters = (() => {
      const extras = [];
      const ruleVals = uniqueVals(findings, 'rule_id');
      if (ruleVals.length > 0) extras.push({ key: 'rule_id', label: 'Rule', options: ruleVals });
      extras.push({ key: 'status', label: 'Status', options: ['FAIL', 'PASS'] });
      return extras;
    })();

    return {
      overview: {
        data: findings,
        columns: findingsColumns,
        filters: buildFilters(findings),
        extraFilters: [],
        groupByOptions: defaultGroupByOptions,
      },
      findings: {
        data: findings,
        columns: findingsColumns,
        filters: buildFilters(findings),
        extraFilters: findingsExtraFilters,
        groupByOptions: defaultGroupByOptions,
      },
      security_groups: {
        data: securityGroups,
        columns: sgColumns,
        filters: buildFilters(securityGroups),
        extraFilters: [],
        groupByOptions: [
          { key: 'vpc_id', label: 'VPC' },
          { key: 'account_id', label: 'Account' },
          { key: 'region', label: 'Region' },
        ],
      },
      internet_exposure: {
        data: internetExposure,
        columns: exposureColumns,
        filters: buildFilters(internetExposure),
        extraFilters: [],
        groupByOptions: [
          { key: 'resource_type', label: 'Resource Type' },
          { key: 'exposure_type', label: 'Exposure Type' },
          { key: 'account_id', label: 'Account' },
        ],
      },
      topology: {
        data: topology,
        columns: topologyColumns,
        filters: buildFilters(topology),
        extraFilters: [],
        groupByOptions: [
          { key: 'account_id', label: 'Account' },
          { key: 'region', label: 'Region' },
        ],
      },
      waf: {
        data: waf,
        columns: wafColumns,
        filters: buildFilters(waf),
        extraFilters: [],
        groupByOptions: [
          { key: 'severity', label: 'Severity' },
          { key: 'account_id', label: 'Account' },
          { key: 'region', label: 'Region' },
        ],
      },
    };
  }, [findings, securityGroups, internetExposure, topology, waf]);

  return (
    <PageLayout
      icon={Network}
      pageContext={data.pageContext}
      kpiGroups={data.kpiGroups}
      tabData={tabData}
      loading={loading}
      error={error}
      defaultTab="overview"
    />
  );
}
