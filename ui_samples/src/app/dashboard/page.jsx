'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import {
  AlertCircle, ArrowRight, Flame, Loader2,
  LayoutDashboard, ShieldAlert, AlertTriangle, ClipboardCheck,
  KeyRound, Server, Lock, Network, Activity, Eye, Brain, Database, Container,
} from 'lucide-react';
import Link from 'next/link';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import DataTable from '@/components/shared/DataTable';
import PostureScoreHero from '@/components/shared/PostureScoreHero';
import AlertBanner from '@/components/shared/AlertBanner';
import MetricStrip from '@/components/shared/MetricStrip';
import InsightRow from '@/components/shared/InsightRow';
import CloudProviderBadge from '@/components/shared/CloudProviderBadge';
import TrendLine from '@/components/charts/TrendLine';
import SeverityDonut from '@/components/charts/SeverityDonut';
import BarChartComponent from '@/components/charts/BarChartComponent';

/* ═══════════════════════════════════════════════════════════════════════════
   SEVERITY BADGE — reusable inline badge for table cells
   ═══════════════════════════════════════════════════════════════════════════ */
function SeverityBadge({ severity }) {
  const colors = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280',
  };
  const c = colors[(severity || '').toLowerCase()] || '#6b7280';
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold"
      style={{ backgroundColor: `${c}18`, color: c, border: `1px solid ${c}30` }}>
      {(severity || 'N/A').toUpperCase()}
    </span>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   RISK SCORE BAR — inline horizontal bar with numeric label
   ═══════════════════════════════════════════════════════════════════════════ */
function RiskScoreBar({ score }) {
  const color = score > 80 ? '#ef4444' : score > 60 ? '#f97316' : '#eab308';
  return (
    <div className="flex items-center gap-2">
      <div className="w-12 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
        <div className="h-full rounded-full" style={{ width: `${Math.min(score, 100)}%`, backgroundColor: color }} />
      </div>
      <span className="text-sm font-bold" style={{ color }}>{score}</span>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   DOMAIN-SPECIFIC COLUMN DEFINITIONS
   ═══════════════════════════════════════════════════════════════════════════ */
const postureColumns = [
  { accessorKey: 'severity', header: 'Severity', cell: (i) => <SeverityBadge severity={i.getValue()} /> },
  { accessorKey: 'status', header: 'Status', cell: (i) => <span className="text-xs font-semibold" style={{ color: i.getValue() === 'FAIL' ? '#ef4444' : '#10b981' }}>{i.getValue()}</span> },
  { accessorKey: 'title', header: 'Title', cell: (i) => <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{i.getValue()}</span> },
  { accessorKey: 'service', header: 'Service', cell: (i) => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{i.getValue()}</span> },
  { accessorKey: 'account_id', header: 'Account', cell: (i) => <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>{i.getValue()}</span> },
  { accessorKey: 'region', header: 'Region', cell: (i) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{i.getValue()}</span> },
];

const threatColumns = [
  { accessorKey: 'severity', header: 'Severity', cell: (i) => <SeverityBadge severity={i.getValue()} /> },
  { accessorKey: 'title', header: 'Title', cell: (i) => <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{i.getValue() || '—'}</span> },
  { accessorKey: 'riskScore', header: 'Risk', cell: (i) => <RiskScoreBar score={i.getValue() || i.row.original.risk_score || 0} /> },
  { accessorKey: 'mitreTechnique', header: 'MITRE', cell: (i) => <span className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{i.getValue() || i.row.original.mitre_technique || '-'}</span> },
  { accessorKey: 'account', header: 'Account', cell: (i) => <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>{i.getValue() || i.row.original.account_id || '—'}</span> },
  { accessorKey: 'lastSeen', header: 'Last Seen', cell: (i) => { const v = i.getValue() || i.row.original.last_seen_at || i.row.original.detected_at; return <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{v ? new Date(v).toLocaleDateString() : '-'}</span>; } },
];

const complianceColumns = [
  { accessorKey: 'control_id', header: 'Control ID', cell: (i) => <span className="text-xs font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>{i.getValue()}</span> },
  { accessorKey: 'title', header: 'Title', cell: (i) => <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{i.getValue()}</span> },
  { accessorKey: 'framework', header: 'Framework', cell: (i) => <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{i.getValue()}</span> },
  { accessorKey: 'severity', header: 'Severity', cell: (i) => <SeverityBadge severity={i.getValue()} /> },
  { accessorKey: 'days_open', header: 'Days Open', cell: (i) => <span className="text-xs font-semibold" style={{ color: (i.getValue() || 0) > 30 ? '#ef4444' : 'var(--text-secondary)' }}>{i.getValue() || '-'}</span> },
];

const iamColumns = [
  { accessorKey: 'username', header: 'Identity', cell: (i) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{i.getValue() || i.row.original.identity || '—'}</span> },
  { accessorKey: 'type', header: 'Type', cell: (i) => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{i.getValue() || '—'}</span> },
  { accessorKey: 'severity', header: 'Severity', cell: (i) => <SeverityBadge severity={i.getValue()} /> },
  { accessorKey: 'risk_score', header: 'Risk Score', cell: (i) => <RiskScoreBar score={i.getValue() || 0} /> },
  { accessorKey: 'mfa', header: 'MFA', cell: (i) => <span className="text-xs font-semibold" style={{ color: i.getValue() ? '#10b981' : '#ef4444' }}>{i.getValue() ? 'Enabled' : 'Disabled'}</span> },
  { accessorKey: 'account', header: 'Account', cell: (i) => <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>{i.getValue() || i.row.original.account_id || '—'}</span> },
];

const inventoryColumns = [
  { accessorKey: 'resource_name', header: 'Resource', cell: (i) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{i.getValue() || i.row.original.name || '—'}</span> },
  { accessorKey: 'resource_type', header: 'Type', cell: (i) => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{i.getValue() || '—'}</span> },
  { accessorKey: 'provider', header: 'Provider', cell: (i) => <CloudProviderBadge provider={i.getValue()} size="sm" /> },
  { accessorKey: 'region', header: 'Region', cell: (i) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{i.getValue() || '—'}</span> },
  { accessorKey: 'findings', header: 'Findings', cell: (i) => { const f = i.getValue(); const total = typeof f === 'object' ? (f.critical||0)+(f.high||0)+(f.medium||0)+(f.low||0) : (f||0); return <span className="text-sm font-semibold" style={{ color: total > 0 ? '#ef4444' : 'var(--text-secondary)' }}>{total}</span>; } },
  { accessorKey: 'risk_score', header: 'Risk', cell: (i) => <RiskScoreBar score={i.getValue() || 0} /> },
];

const datasecColumns = [
  { accessorKey: 'name', header: 'Name', cell: (i) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{i.getValue()}</span> },
  { accessorKey: 'type', header: 'Type', cell: (i) => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{i.getValue()}</span> },
  { accessorKey: 'classification', header: 'Classification', cell: (i) => <span className="text-xs px-2 py-0.5 rounded font-semibold" style={{ backgroundColor: 'rgba(139,92,246,0.12)', color: '#8b5cf6' }}>{i.getValue() || '-'}</span> },
  { accessorKey: 'encryption', header: 'Encryption', cell: (i) => <span className="text-xs font-semibold" style={{ color: i.getValue() ? '#10b981' : '#ef4444' }}>{i.getValue() ? 'Encrypted' : 'Not Encrypted'}</span> },
  { accessorKey: 'public_access', header: 'Public Access', cell: (i) => <span className="text-xs font-semibold" style={{ color: i.getValue() ? '#ef4444' : '#10b981' }}>{i.getValue() ? 'Public' : 'Private'}</span> },
];

const networkColumns = [
  { accessorKey: 'severity', header: 'Severity', cell: (i) => <SeverityBadge severity={i.getValue()} /> },
  { accessorKey: 'title', header: 'Title', cell: (i) => <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{i.getValue()}</span> },
  { accessorKey: 'module', header: 'Module', cell: (i) => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{i.getValue()}</span> },
  { accessorKey: 'resource_type', header: 'Resource Type', cell: (i) => <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{i.getValue()}</span> },
  { accessorKey: 'account_id', header: 'Account', cell: (i) => <span className="text-xs font-mono" style={{ color: 'var(--text-tertiary)' }}>{i.getValue()}</span> },
];

const riskColumns = [
  { accessorKey: 'scenario_name', header: 'Scenario', cell: (i) => <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>{i.getValue() || i.row.original.scenario || '—'}</span> },
  { accessorKey: 'threat_category', header: 'Category', cell: (i) => <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{i.getValue() || i.row.original.category || '—'}</span> },
  { accessorKey: 'probability', header: 'Probability', cell: (i) => <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{i.getValue() != null ? `${(i.getValue() * 100).toFixed(0)}%` : '-'}</span> },
  { accessorKey: 'expected_loss', header: 'Expected Loss', cell: (i) => <span className="text-sm font-bold" style={{ color: '#ef4444' }}>{i.getValue() != null ? `$${Number(i.getValue()).toLocaleString()}` : '-'}</span> },
  { accessorKey: 'risk_rating', header: 'Rating', cell: (i) => { const r = (i.getValue() || i.row.original.rating || '').toLowerCase(); const c = r === 'critical' ? '#ef4444' : r === 'high' ? '#f97316' : r === 'medium' ? '#eab308' : '#3b82f6'; return <SeverityBadge severity={r} />; } },
];

const ciemColumns = [
  { accessorKey: 'severity', header: 'Severity', cell: (i) => <SeverityBadge severity={i.getValue()} /> },
  { accessorKey: 'title', header: 'Detection', cell: (i) => <span className="text-sm" style={{ color: 'var(--text-primary)' }}>{i.getValue() || i.row.original.detection || '—'}</span> },
  { accessorKey: 'rule_id', header: 'Rule ID', cell: (i) => <span className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{i.getValue() || '—'}</span> },
  { accessorKey: 'actor_principal', header: 'Actor', cell: (i) => { const v = i.getValue() || ''; return <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{v.split('/').pop() || v || '—'}</span>; } },
  { accessorKey: 'resource_uid', header: 'Resource', cell: (i) => { const v = i.getValue() || ''; return <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{v.split('/').pop() || v || '—'}</span>; } },
];

/* ═══════════════════════════════════════════════════════════════════════════
   DOMAIN VIEW CONFIGURATION
   Each entry maps a tab key to its BFF view name, chart rendering, KPI
   extraction, table columns, and link target.
   ═══════════════════════════════════════════════════════════════════════════ */
/* Helper: derive severity counts object from an array of objects with .severity field */
function _sevCounts(arr) {
  const c = { critical: 0, high: 0, medium: 0, low: 0 };
  (arr || []).forEach(r => { const s = (r.severity || '').toLowerCase(); if (c[s] !== undefined) c[s]++; });
  return c;
}

const DOMAIN_VIEWS = {
  posture: {
    label: 'Security Posture', Icon: ShieldAlert, href: '/misconfig', color: '#8b5cf6', bffView: 'misconfig',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      // Derive top rules from findings
      const ruleCounts = {};
      (d.findings || []).forEach(f => { const k = f.title || f.rule_id || 'Unknown'; ruleCounts[k] = (ruleCounts[k] || 0) + 1; });
      const topRules = Object.entries(ruleCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, value]) => ({ name, value }));
      // Derive service breakdown
      const bs = d.byService || {};
      const svcData = typeof bs === 'object' && !Array.isArray(bs)
        ? Object.entries(bs).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, value]) => ({ name: name.toUpperCase(), value }))
        : (Array.isArray(bs) ? bs.slice(0, 5).map(s => ({ name: (s.service || '').toUpperCase(), value: s.total || s.count || 0 })) : []);
      return {
        left: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Top Failing Rules</h3><BarChartComponent data={topRules} color="#8b5cf6" horizontal /></>),
        right: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Findings by Service</h3><BarChartComponent data={svcData} color="#a78bfa" horizontal /></>),
      };
    },
    getTable: (d) => ({ data: (d.findings || []).slice(0, 10), columns: postureColumns }),
    tableTitle: 'Top Misconfigurations',
  },
  threats: {
    label: 'Threats', Icon: AlertTriangle, href: '/threats', color: '#ef4444', bffView: 'threats',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      // mitreMatrix is a dict {tactic: [{id, name, count}]} — flatten it
      const mm = d.mitreMatrix || {};
      const mitreFlat = typeof mm === 'object' && !Array.isArray(mm)
        ? Object.values(mm).flat()
        : (Array.isArray(mm) ? mm : []);
      const mitreTop = mitreFlat.sort((a, b) => (b.count || 0) - (a.count || 0)).slice(0, 5)
        .map(t => ({ name: `${t.id || ''} ${t.name || ''}`.trim(), value: t.count || 0 }));
      return {
        left: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Threat Trend (30d)</h3><TrendLine data={d.trendData || []} dataKeys={['critical', 'high', 'medium']} colors={['#ef4444', '#f97316', '#eab308']} /></>),
        right: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Top MITRE Techniques</h3><BarChartComponent data={mitreTop} color="#ef4444" horizontal /></>),
      };
    },
    getTable: (d) => ({ data: (d.threats || []).slice(0, 10), columns: threatColumns }),
    tableTitle: 'Top Threat Findings',
  },
  compliance: {
    label: 'Compliance', Icon: ClipboardCheck, href: '/compliance', color: '#22c55e', bffView: 'compliance',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => ({
      left: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Framework Scores</h3>
        <div className="grid grid-cols-2 gap-3">
          {(d.frameworks || []).slice(0, 4).map((fw) => {
            const c = fw.score > 80 ? '#10b981' : fw.score > 60 ? '#eab308' : '#ef4444';
            return (<div key={fw.name || fw.id} className="rounded-lg p-3 border" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
              <h4 className="text-sm font-medium mb-2" style={{ color: 'var(--text-primary)' }}>{fw.name}</h4>
              <div className="w-full rounded-full h-2 mb-1" style={{ backgroundColor: 'var(--bg-tertiary)' }}><div className="h-2 rounded-full" style={{ width: `${fw.score}%`, backgroundColor: c }} /></div>
              <span className="text-sm font-bold" style={{ color: c }}>{fw.score}%</span>
            </div>);
          })}
        </div></>),
      right: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Compliance Trend</h3><TrendLine data={d.trendData || []} dataKeys={['score']} colors={['#22c55e']} /></>),
    }),
    getTable: (d) => ({ data: (d.failingControls || []).slice(0, 10), columns: complianceColumns }),
    tableTitle: 'Top Failing Controls',
  },
  iam: {
    label: 'IAM', Icon: KeyRound, href: '/iam', color: '#f59e0b', bffView: 'iam',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      // Derive from findingsByModule
      const fm = d.findingsByModule || {};
      const moduleData = Object.entries(fm).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, value]) => ({ name, value }));
      return {
        left: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Findings by Module</h3><BarChartComponent data={moduleData} color="#f59e0b" horizontal /></>),
        right: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Identity Severity Distribution</h3><SeverityDonut data={_sevCounts(d.identities)} title="Identities" /></>),
      };
    },
    getTable: (d) => ({ data: (d.identities || []).slice(0, 10), columns: iamColumns }),
    tableTitle: 'Top IAM Risks',
  },
  inventory: {
    label: 'Assets', Icon: Server, href: '/inventory', color: '#06b6d4', bffView: 'inventory',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      // Derive from summary
      const svc = (d.summary?.assets_by_service || []).slice(0, 5).map(s => ({ name: (s.service || '').toUpperCase(), value: s.count || 0 }));
      const prov = Object.entries(d.summary?.assets_by_provider || {}).map(([name, count]) => ({ name: name.toUpperCase(), value: count }));
      return {
        left: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Assets by Service</h3><BarChartComponent data={svc.length ? svc : [{ name: 'No data', value: 0 }]} color="#06b6d4" horizontal /></>),
        right: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Assets by Provider</h3><BarChartComponent data={prov.length ? prov : [{ name: 'No data', value: 0 }]} color="#0ea5e9" horizontal /></>),
      };
    },
    getTable: (d) => ({ data: (d.assets || []).slice(0, 10), columns: inventoryColumns }),
    tableTitle: 'Top Resources by Risk',
  },
  datasec: {
    label: 'Data', Icon: Lock, href: '/datasec', color: '#ec4899', bffView: 'datasec',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      const classData = (d.classifications || []).map(c => ({ name: c.name || c.type || 'Unknown', value: c.count || 0 }));
      return {
        left: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Data by Classification</h3><BarChartComponent data={classData.length ? classData : [{ name: 'No data', value: 0 }]} color="#ec4899" horizontal /></>),
        right: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Data Store Distribution</h3><SeverityDonut data={_sevCounts(d.catalog || d.findings)} title="Data Stores" /></>),
      };
    },
    getTable: (d) => ({ data: (d.catalog || []).slice(0, 10), columns: datasecColumns }),
    tableTitle: 'Top Data Stores',
  },
  network: {
    label: 'Network', Icon: Network, href: '/network-security', color: '#3b82f6', bffView: 'network-security',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      // Network data is nested under d.data
      const findings = d.data?.findings || d.findings || [];
      const moduleCounts = {};
      findings.forEach(f => { const m = f.module || f.network_modules || 'other'; moduleCounts[m] = (moduleCounts[m] || 0) + 1; });
      const moduleData = Object.entries(moduleCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, value]) => ({ name, value }));
      return {
        left: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Findings by Module</h3><BarChartComponent data={moduleData.length ? moduleData : [{ name: 'No data', value: 0 }]} color="#3b82f6" horizontal /></>),
        right: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Network Finding Severity</h3><SeverityDonut data={_sevCounts(findings)} title="Network" /></>),
      };
    },
    getTable: (d) => ({ data: (d.data?.findings || d.findings || []).slice(0, 10), columns: networkColumns }),
    tableTitle: 'Top Network Findings',
  },
  risk: {
    label: 'Risk', Icon: Activity, href: '/risk', color: '#f97316', bffView: 'risk',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      const catData = (d.riskCategories || []).map(c => ({ name: c.category || c.name || 'Unknown', value: c.score || c.count || 0 }));
      return {
        left: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Risk by Category</h3><BarChartComponent data={catData.length ? catData : [{ name: 'No data', value: 0 }]} color="#f97316" horizontal /></>),
        right: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Risk Trend</h3><TrendLine data={d.trendData || []} dataKeys={['score']} colors={['#f97316']} /></>),
      };
    },
    getTable: (d) => ({ data: (d.scenarios || []).slice(0, 10), columns: riskColumns }),
    tableTitle: 'Top Risk Scenarios',
  },
  ciem: {
    label: 'CIEM', Icon: Eye, href: '/ciem', color: '#a855f7', bffView: 'ciem',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      const ruleData = (d.topRules || []).slice(0, 5).map(r => ({ name: r.rule_id || r.title || 'Unknown', value: r.finding_count || r.count || 0 }));
      const sevData = {};
      (d.severityBreakdown || []).forEach(s => { sevData[s.severity] = s.count; });
      return {
        left: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>Top Detection Rules</h3><BarChartComponent data={ruleData.length ? ruleData : [{ name: 'No data', value: 0 }]} color="#a855f7" horizontal /></>),
        right: (<><h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>CIEM Severity Distribution</h3><SeverityDonut data={sevData} title="CIEM" /></>),
      };
    },
    getTable: (d) => ({ data: (d.topCritical || []).slice(0, 10), columns: ciemColumns }),
    tableTitle: 'Top CIEM Detections',
  },
};

/* ═══════════════════════════════════════════════════════════════════════════
   DOMAIN DASHBOARD — renders a single domain's executive summary
   ═══════════════════════════════════════════════════════════════════════════ */
function DomainDashboard({ view, data }) {
  const config = DOMAIN_VIEWS[view];
  if (!config) return null;

  // Loading spinner while data is being fetched
  if (!data) {
    return (
      <div className="flex flex-col items-center justify-center py-20 gap-3">
        <Loader2 className="w-8 h-8 animate-spin" style={{ color: config.color }} />
        <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>Loading {config.label} data...</span>
      </div>
    );
  }

  const kpis = config.getKpis(data);
  const charts = config.getCharts(data);
  const table = config.getTable(data);

  return (
    <div className="space-y-6">
      {/* KPIs */}
      {kpis.length > 0 && <MetricStrip groups={kpis} />}

      {/* Charts */}
      <InsightRow left={charts.left} right={charts.right} />

      {/* Top 10 Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>{config.tableTitle || 'Top Findings'}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
              Top 10 items requiring attention
            </p>
          </div>
          <Link href={config.href} className="text-xs flex items-center gap-1 font-semibold" style={{ color: 'var(--accent-primary)' }}>
            View All <ArrowRight className="w-3 h-3" />
          </Link>
        </div>
        <DataTable data={table.data} columns={table.columns} pageSize={10} emptyMessage={`No ${config.label.toLowerCase()} findings`} />
      </div>

      {/* Link to full page */}
      <div className="flex justify-end">
        <Link href={config.href}
          className="flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-lg transition-colors hover:opacity-80"
          style={{ color: config.color, backgroundColor: `${config.color}10` }}>
          View Full {config.label} Dashboard <ArrowRight className="w-4 h-4" />
        </Link>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   MAIN DASHBOARD PAGE
   ═══════════════════════════════════════════════════════════════════════════ */
export default function DashboardPage() {
  const [loading, setLoading] = useState(true);
  const [pageError, setPageError] = useState(null);
  const [activeView, setActiveView] = useState('overview');
  const [domainData, setDomainData] = useState({});

  // BFF data slices (overview)
  const [kpiData, setKpiData] = useState({});
  const [securityScoreTrendData, setSecurityScoreTrendData] = useState([]);
  const [realComplianceFrameworks, setRealComplianceFrameworks] = useState([]);
  const [mitreTopTechniques, setMitreTopTechniques] = useState([]);
  const [toxicCombos, setToxicCombos] = useState([]);
  const [remediationSLA, setRemediationSLA] = useState([]);
  const [riskyResources, setRiskyResources] = useState([]);
  const [criticalAlerts, setCriticalAlerts] = useState([]);
  const [cloudHealthData, setCloudHealthData] = useState([]);
  const [findingsByCategoryData, setFindingsByCategoryData] = useState([]);

  const { provider: filterProvider } = useGlobalFilter();

  // Derive severity totals for the donut from findingsByCategoryData
  const severityTotals = useMemo(() => {
    const totals = { critical: 0, high: 0, medium: 0, low: 0 };
    findingsByCategoryData.forEach((row) => {
      totals.critical += row.critical || 0;
      totals.high += row.high || 0;
      totals.medium += row.medium || 0;
      totals.low += row.low || 0;
    });
    return totals;
  }, [findingsByCategoryData]);

  // MITRE data formatted for BarChartComponent
  const mitreBarData = useMemo(
    () => mitreTopTechniques.slice(0, 5).map((t) => ({ name: `${t.id} ${t.name}`, value: t.count })),
    [mitreTopTechniques],
  );

  // ── Single BFF fetch for overview ──────────────────────────────────────
  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const data = await fetchView('dashboard', { provider: filterProvider || undefined });
        if (data.error) { setPageError(data.error); return; }

        if (data.kpi)                    setKpiData(data.kpi);
        if (data.securityScoreTrendData) setSecurityScoreTrendData(data.securityScoreTrendData);
        if (data.frameworks)             setRealComplianceFrameworks(data.frameworks);
        if (data.mitreTopTechniques)     setMitreTopTechniques(data.mitreTopTechniques);
        if (data.toxicCombinations)      setToxicCombos(data.toxicCombinations);
        if (data.remediationSLA)         setRemediationSLA(data.remediationSLA);
        if (data.riskyResources)         setRiskyResources(data.riskyResources);
        if (data.criticalAlerts)         setCriticalAlerts(data.criticalAlerts);
        if (data.cloudHealthData)        setCloudHealthData(data.cloudHealthData);
        if (data.findingsByCategoryData) setFindingsByCategoryData(data.findingsByCategoryData);
      } catch (err) {
        console.warn('Dashboard fetch error:', err);
        setPageError(err.message || 'Failed to load dashboard');
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [filterProvider]);

  // ── Lazy-load domain data on tab switch ────────────────────────────────
  useEffect(() => {
    if (activeView === 'overview') return;
    if (domainData[activeView]) return; // already cached

    const config = DOMAIN_VIEWS[activeView];
    if (!config) return;

    fetchView(config.bffView, { provider: filterProvider || undefined })
      .then((data) => {
        if (!data.error) {
          setDomainData((prev) => ({ ...prev, [activeView]: data }));
        }
      })
      .catch((err) => {
        console.warn(`Failed to load ${activeView} data:`, err);
      });
  }, [activeView, filterProvider, domainData]);

  // ── Derived KPI helpers ────────────────────────────────────────────────
  const fws = realComplianceFrameworks.length > 0 ? realComplianceFrameworks : [];
  const worstFw = fws.length > 0 ? [...fws].sort((a, b) => a.score - b.score)[0] : null;
  const worstFwColor = worstFw ? (worstFw.score < 70 ? '#ef4444' : worstFw.score < 80 ? '#eab308' : '#10b981') : undefined;
  const validAcc = cloudHealthData.filter((c) => c.credStatus === 'valid').length;
  const totalAcc = cloudHealthData.length;
  const allValid = validAcc === totalAcc;
  const hasCriticalAlerts = criticalAlerts.length > 0;

  // ── Risky Resources table columns ──────────────────────────────────────
  const riskyResourcesColumns = [
    {
      accessorKey: 'resource',
      header: 'Resource',
      cell: (info) => (
        <div>
          <div className="font-medium text-sm" style={{ color: 'var(--text-primary)' }}>{info.getValue()}</div>
          <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.row.original.type}</div>
        </div>
      ),
    },
    {
      accessorKey: 'provider',
      header: 'Provider / Region',
      cell: (info) => (
        <div className="flex flex-col gap-0.5">
          <CloudProviderBadge provider={info.getValue()} size="sm" />
          <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{info.row.original.region}</span>
        </div>
      ),
    },
    {
      accessorKey: 'findings',
      header: 'Findings',
      cell: (info) => <span className="text-sm font-semibold" style={{ color: '#ef4444' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'riskScore',
      header: 'Risk Score',
      cell: (info) => <RiskScoreBar score={info.getValue() || 0} />,
    },
    {
      accessorKey: 'owner',
      header: 'Owner',
      cell: (info) => <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{info.getValue()}</span>,
    },
    {
      accessorKey: 'age',
      header: 'Age',
      cell: (info) => <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>{info.getValue()}</span>,
    },
  ];

  // ── Compliance mini-gauge helper ───────────────────────────────────────
  const ComplianceMiniGauge = ({ fw }) => {
    const c = fw.score > 80 ? '#10b981' : fw.score > 60 ? '#eab308' : '#ef4444';
    return (
      <div className="rounded-lg p-3 border" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
        <h4 className="text-sm font-medium mb-2" style={{ color: 'var(--text-primary)' }}>{fw.name}</h4>
        <div className="w-full rounded-full h-2 mb-1" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
          <div className="h-2 rounded-full transition-all duration-300" style={{ width: `${fw.score}%`, backgroundColor: c }} />
        </div>
        <span className="text-sm font-bold" style={{ color: c }}>{fw.score}%</span>
      </div>
    );
  };

  // ── Toxic combo risk badge ─────────────────────────────────────────────
  const riskBadge = (score) => {
    const color = score >= 90 ? '#ef4444' : score >= 75 ? '#f97316' : '#eab308';
    return (
      <div className="flex items-center justify-center w-11 h-11 rounded-full border-2 flex-shrink-0"
        style={{ borderColor: color, backgroundColor: `${color}18` }}>
        <span className="text-sm font-bold" style={{ color }}>{score}</span>
      </div>
    );
  };

  // ── Tab definitions ────────────────────────────────────────────────────
  const scoreColor = (s) => s >= 80 ? '#22c55e' : s >= 60 ? '#eab308' : '#ef4444';

  const tabs = [
    { id: 'overview', label: 'Overview', Icon: LayoutDashboard, color: 'var(--accent-primary)' },
    { id: 'posture', label: 'Security Posture', Icon: ShieldAlert, color: '#8b5cf6', score: kpiData.criticalHighFindings ? Math.max(0, 100 - Math.round((kpiData.criticalHighFindings || 0) / 5)) : 78 },
    { id: 'threats', label: 'Threats', Icon: AlertTriangle, color: '#ef4444', score: kpiData.activeThreats ? Math.max(0, 100 - Math.round((kpiData.activeThreats || 0) / 10)) : 71 },
    { id: 'compliance', label: 'Compliance', Icon: ClipboardCheck, color: '#22c55e', score: kpiData.complianceScore || 78 },
    { id: 'iam', label: 'IAM', Icon: KeyRound, color: '#f59e0b', score: 62 },
    { id: 'inventory', label: 'Assets', Icon: Server, color: '#06b6d4', score: 85 },
    { id: 'datasec', label: 'Data', Icon: Lock, color: '#ec4899', score: 85 },
    { id: 'network', label: 'Network', Icon: Network, color: '#3b82f6', score: 80 },
    { id: 'risk', label: 'Risk', Icon: Activity, color: '#f97316', score: 67 },
    { id: 'ciem', label: 'CIEM', Icon: Eye, color: '#a855f7', score: 74 },
  ];

  // ═══════════════════════════════════════════════════════════════════════════
  return (
    <div className="space-y-6">

      {/* ── Error state ───────────────────────────────────────────────────── */}
      {pageError && (
        <div className="rounded-lg p-4 border flex items-center gap-3"
          style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: '#ef4444' }}>
          <AlertCircle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
          <div>
            <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>Failed to load dashboard data</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{pageError}</p>
          </div>
        </div>
      )}

      {/* [1] Alert Banner — conditional, only if critical issues exist ──── */}
      {hasCriticalAlerts && (
        <AlertBanner
          severity="critical"
          title={`${criticalAlerts.length} critical alert${criticalAlerts.length > 1 ? 's' : ''} require attention`}
          description={criticalAlerts[0]?.message}
          items={criticalAlerts.slice(0, 4).map((a) => ({
            label: a.resource || a.message,
            count: a.count,
            link: '/threats',
          }))}
          action={{ label: 'View Threats', onClick: () => (window.location.href = '/threats') }}
        />
      )}

      {/* [2] Posture Score Hero — gauge + domain scores ────────────────── */}
      <PostureScoreHero
        score={kpiData.complianceScore || 0}
        prevScore={(kpiData.complianceScore || 0) - (kpiData.complianceScoreChange || 0)}
        delta={kpiData.complianceScoreChange || 0}
        status={kpiData.complianceScore >= 75 ? 'Good' : kpiData.complianceScore >= 50 ? 'Fair' : 'Critical'}
        criticalActions={kpiData.criticalHighFindings || 0}
        domainScores={{
          compliance: kpiData.complianceScore || 0,
          threats: kpiData.activeThreats ? Math.max(0, 100 - Math.round(kpiData.activeThreats / 10)) : 0,
          iam: kpiData.openFindings ? Math.max(0, 100 - Math.round(kpiData.openFindings / 20)) : 0,
          misconfigs: kpiData.criticalHighFindings ? Math.max(0, 100 - Math.round(kpiData.criticalHighFindings / 5)) : 0,
          dataSec: kpiData.attackSurfaceScore ? Math.max(0, 100 - kpiData.attackSurfaceScore) : 50,
        }}
      />

      {/* [2b] Domain Context Switcher — tab bar ────────────────────────── */}
      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center overflow-x-auto">
          {tabs.map((tab) => {
            const isActive = activeView === tab.id;
            const isOverview = tab.id === 'overview';
            return (
              <button
                key={tab.id}
                onClick={() => setActiveView(tab.id)}
                className="flex items-center gap-2 px-4 py-3 border-r last:border-r-0 whitespace-nowrap transition-colors hover:opacity-80"
                style={{
                  borderColor: 'var(--border-primary)',
                  backgroundColor: isActive ? `${tab.color}10` : 'transparent',
                  borderBottom: isActive ? `2px solid ${tab.color}` : '2px solid transparent',
                  cursor: 'pointer',
                  minWidth: isOverview ? 110 : 90,
                }}>
                <tab.Icon className="w-4 h-4 flex-shrink-0" style={{ color: activeView === tab.id ? tab.color : 'var(--text-muted)' }} />
                <div>
                  <span className="text-xs font-semibold block" style={{ color: isActive ? tab.color : 'var(--text-secondary)' }}>{tab.label}</span>
                  {tab.score != null && (
                    <span className="text-sm font-bold" style={{ color: scoreColor(tab.score) }}>{tab.score}%</span>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Content: Overview or Domain-specific ──────────────────────── */}
      {activeView === 'overview' ? (
        <>
          {/* [3] MetricStrip — 2 groups: RISK POSTURE (red) + OPERATIONS (blue) */}
          <MetricStrip
            groups={[
              {
                label: 'RISK POSTURE',
                color: '#ef4444',
                cells: [
                  {
                    label: 'Critical + High',
                    value: kpiData.criticalHighFindings != null ? kpiData.criticalHighFindings.toLocaleString() : '--',
                    valueColor: '#ef4444',
                    delta: kpiData.criticalHighFindingsChange,
                    deltaGoodDown: true,
                    context: 'vs last 7d',
                    href: '/misconfig?severity=critical',
                  },
                  {
                    label: 'Internet Exposed',
                    value: kpiData.internetExposed != null ? kpiData.internetExposed.toLocaleString() : '--',
                    valueColor: '#f97316',
                    noTrend: true,
                    context: 'publicly reachable',
                    href: '/network-security',
                  },
                  {
                    label: worstFw ? `${worstFw.name} (worst)` : 'Worst Framework',
                    value: worstFw ? `${worstFw.score}%` : '--',
                    valueColor: worstFwColor,
                    delta: worstFw?.trend,
                    context: 'compliance score',
                    href: '/compliance',
                  },
                ],
              },
              {
                label: 'OPERATIONS',
                color: '#3b82f6',
                cells: [
                  {
                    label: 'Mean Time to Remediate',
                    value: kpiData.mttr != null ? `${kpiData.mttr}d` : '--',
                    delta: kpiData.mttrChange,
                    deltaGoodDown: true,
                    context: 'avg all severities',
                    href: '/scans',
                  },
                  {
                    label: 'Remediation SLA',
                    value: kpiData.slaCompliance != null ? `${kpiData.slaCompliance}%` : '--',
                    valueColor: kpiData.slaCompliance >= 90 ? '#10b981' : kpiData.slaCompliance >= 75 ? '#eab308' : '#ef4444',
                    delta: kpiData.slaComplianceChange,
                    context: 'fixed within target',
                    href: '/risk',
                  },
                  {
                    label: 'Monitored Accounts',
                    value: totalAcc > 0 ? `${validAcc} / ${totalAcc}` : '--',
                    valueColor: totalAcc > 0 ? (allValid ? '#10b981' : '#ef4444') : undefined,
                    noTrend: true,
                    context: allValid ? 'all credentials valid' : `${totalAcc - validAcc} credential issue`,
                    href: '/onboarding',
                  },
                ],
              },
            ]}
          />

          {/* [4] InsightRow: SecurityScoreTrend | SeverityDonut ────────── */}
          <InsightRow
            left={
              <>
                <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>
                  Security Score Trend (90d)
                </h3>
                <TrendLine data={securityScoreTrendData} dataKeys={['score']} colors={['#10b981']} />
              </>
            }
            right={
              <SeverityDonut data={severityTotals} title="Finding Distribution" />
            }
          />

          {/* [5] InsightRow: Framework mini-gauges | Top 5 MITRE techniques */}
          <InsightRow
            left={
              <>
                <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>
                  <Link href="/compliance" className="hover:opacity-80" style={{ color: 'inherit', textDecoration: 'none' }}>
                    Compliance Frameworks
                  </Link>
                </h3>
                {fws.length === 0 ? (
                  <p className="text-sm text-center py-4" style={{ color: 'var(--text-tertiary)' }}>No compliance data</p>
                ) : (
                  <div className="grid grid-cols-2 gap-3">
                    {fws.slice(0, 4).map((fw) => <ComplianceMiniGauge key={fw.name} fw={fw} />)}
                  </div>
                )}
              </>
            }
            right={
              <>
                <h3 className="text-sm font-semibold mb-3" style={{ color: 'var(--text-primary)' }}>
                  <Link href="/threats" className="hover:opacity-80" style={{ color: 'inherit', textDecoration: 'none' }}>
                    Top 5 MITRE ATT&CK Techniques
                  </Link>
                </h3>
                <BarChartComponent data={mitreBarData} color="#ef4444" horizontal />
              </>
            }
          />

          {/* [6] Riskiest Resources table (top 10) ────────────────────── */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>Top 10 Riskiest Resources</h2>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                  Highest risk scores requiring immediate attention
                </p>
              </div>
              <Link href="/risk" className="text-xs flex items-center gap-1 font-semibold" style={{ color: 'var(--accent-primary)' }}>
                View All <ArrowRight className="w-3 h-3" />
              </Link>
            </div>
            <DataTable data={riskyResources} columns={riskyResourcesColumns} pageSize={10} loading={loading} emptyMessage="No resources found" />
          </div>

          {/* [7] Two-column: Toxic Combos | Remediation SLA tracking ──── */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* Toxic Combos — top 3 */}
            <div className="rounded-xl border overflow-hidden"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-5 py-3 border-b flex items-center justify-between"
                style={{ borderColor: 'var(--border-primary)' }}>
                <h3 className="text-sm font-semibold flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
                  <Flame className="w-4 h-4" style={{ color: '#ef4444' }} />
                  Toxic Combinations
                </h3>
                <Link href="/threats/toxic-combinations" className="text-xs flex items-center gap-1 font-semibold"
                  style={{ color: 'var(--accent-primary)' }}>
                  View all <ArrowRight className="w-3 h-3" />
                </Link>
              </div>
              <div className="divide-y" style={{ borderColor: 'var(--border-primary)' }}>
                {toxicCombos.length === 0 ? (
                  <div className="px-5 py-8 text-center text-sm" style={{ color: 'var(--text-tertiary)' }}>
                    No toxic combinations detected
                  </div>
                ) : toxicCombos.slice(0, 3).map((combo) => (
                  <div key={combo.id} className="px-5 py-3 flex items-start gap-3">
                    {riskBadge(combo.riskScore)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{combo.title}</span>
                        <CloudProviderBadge provider={combo.provider} size="sm" />
                      </div>
                      <p className="text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>{combo.description}</p>
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                        {combo.affectedResources} resource{combo.affectedResources > 1 ? 's' : ''}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Remediation SLA tracking */}
            <div className="rounded-xl border overflow-hidden"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Remediation SLA Tracking</h3>
              </div>
              {remediationSLA.length === 0 ? (
                <div className="px-5 py-8 text-center text-sm" style={{ color: 'var(--text-tertiary)' }}>
                  No SLA data available
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b" style={{ borderColor: 'var(--border-primary)' }}>
                        {['Severity', 'SLA', 'Open', 'Within', 'Breached', '%'].map((h) => (
                          <th key={h} className="text-left py-2 px-3 font-semibold text-xs" style={{ color: 'var(--text-secondary)' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {remediationSLA.map((row) => {
                        const cc = row.compliant > 95 ? '#10b981' : row.compliant > 80 ? '#eab308' : '#ef4444';
                        return (
                          <tr key={row.severity} className="border-b" style={{ borderColor: 'var(--border-primary)' }}>
                            <td className="py-2 px-3 font-semibold text-xs" style={{ color: 'var(--text-primary)' }}>{row.severity}</td>
                            <td className="py-2 px-3 text-xs" style={{ color: 'var(--text-secondary)' }}>{row.slaTarget}</td>
                            <td className="py-2 px-3 text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>{row.openCount}</td>
                            <td className="py-2 px-3 text-xs font-semibold" style={{ color: '#10b981' }}>{row.withinSLA}</td>
                            <td className="py-2 px-3 text-xs font-semibold" style={{ color: '#ef4444' }}>{row.breached}</td>
                            <td className="py-2 px-3 text-xs font-bold" style={{ color: cc }}>{(row.compliant || 0).toFixed(1)}%</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </>
      ) : (
        /* ── Domain-specific view ─────────────────────────────────────── */
        <DomainDashboard view={activeView} data={domainData[activeView]} />
      )}

    </div>
  );
}
