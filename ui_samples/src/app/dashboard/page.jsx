'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import {
  AlertCircle, ArrowRight, ChevronDown, ChevronRight, Loader2, Zap, Shield,
  Code, TrendingUp, TrendingDown,
  LayoutDashboard, ShieldAlert, AlertTriangle, ClipboardCheck,
  KeyRound, Server, Lock, Network, Activity, Eye, Brain, Database, Container,
} from 'lucide-react';
import Link from 'next/link';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import {
  MOCK_DASHBOARD, MOCK_THREATS, MOCK_FRAMEWORKS, MOCK_POSTURE,
} from '@/lib/mock-data';
import DataTable from '@/components/shared/DataTable';
import AlertBanner from '@/components/shared/AlertBanner';
import MetricStrip from '@/components/shared/MetricStrip';
import InsightRow from '@/components/shared/InsightRow';
import CloudProviderBadge from '@/components/shared/CloudProviderBadge';
import TrendLine from '@/components/charts/TrendLine';
import SeverityDonut from '@/components/charts/SeverityDonut';
import BarChartComponent from '@/components/charts/BarChartComponent';
import {
  AreaChart, Area,
  BarChart, Bar,
  ScatterChart, Scatter, ZAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell, LabelList, ReferenceLine,
} from 'recharts';

/* ═══════════════════════════════════════════════════════════════════════════
   MULTI-TENANT DATA — each tenant has accounts + per-tenant aggregate domain
   scores + per-account domain scores. BFF: replace with /api/v1/tenants/{id}/posture
   ═══════════════════════════════════════════════════════════════════════════ */
const DS = (c,t,i,m,d,n,cs,r) => ({ compliance:c, threats:t, iam:i, misconfigs:m, dataSec:d, network:n, codeSec:cs, risk:r });
const DC = (i,t,m,d,cs,r,n,c) => ({ iam:i, threats:t, misconfigs:m, dataSec:d, codeSec:cs, risk:r, network:n, compliance:c });

const MOCK_TENANTS = [
  {
    id:'acme', name:'Acme Corp', criticals:23,
    domainScores: DS(76,58,42,71,63,69,55,48),
    domainCritical: DC(9,6,5,3,4,7,2,0),
    accounts:[
      { id:'aws-prod',  name:'AWS Production',  provider:'aws',   status:'healthy', regions:8, resources:9412,  criticals:12, score:82, lastScan:'2h ago',  nextScan:'~4h',  scanState:'ok',     credentialStatus:'valid',    credentialNote:'Expires in 87d', coverage:100,
        domainScores: DS(78,61,44,73,65,71,57,50), domainCritical: DC(4,3,2,1,2,3,1,0) },
      { id:'aws-stg',   name:'AWS Staging',     provider:'aws',   status:'healthy', regions:3, resources:1843,  criticals:4,  score:74, lastScan:'4h ago',  nextScan:'~2h',  scanState:'ok',     credentialStatus:'valid',    credentialNote:'Expires in 71d', coverage:98,
        domainScores: DS(74,55,38,70,60,67,52,45), domainCritical: DC(3,2,2,1,1,2,1,0) },
      { id:'azure-crp', name:'Azure Corp',      provider:'azure', status:'healthy', regions:4, resources:1247,  criticals:7,  score:71, lastScan:'1h ago',  nextScan:'~5h',  scanState:'ok',     credentialStatus:'expiring', credentialNote:'Expires in 12d', coverage:100,
        domainScores: DS(75,57,40,69,62,68,54,47), domainCritical: DC(2,1,1,1,1,2,0,0) },
      { id:'gcp-ana',   name:'GCP Analytics',   provider:'gcp',   status:'warning', regions:2, resources:345,   criticals:0,  score:0,  lastScan:'3d ago',  nextScan:'N/A',  scanState:'failed', credentialStatus:'expired',  credentialNote:'Re-auth required',  coverage:0,
        statusDetail:'Credential expired — re-auth needed',
        domainScores: DS(0,0,0,0,0,0,0,0), domainCritical: DC(0,0,0,0,0,0,0,0) },
    ],
  },
  {
    id:'techcorp', name:'TechCorp Inc', criticals:15,
    domainScores: DS(68,71,55,63,58,74,61,52),
    domainCritical: DC(5,4,3,2,1,0,0,0),
    accounts:[
      { id:'az-ent',  name:'Azure Enterprise', provider:'azure', status:'healthy', regions:6, resources:3240, criticals:9, score:68, lastScan:'3h ago', nextScan:'~3h', scanState:'ok',    credentialStatus:'valid',   credentialNote:'Expires in 55d', coverage:100,
        domainScores: DS(67,72,54,62,57,75,61,51), domainCritical: DC(3,2,2,1,1,0,0,0) },
      { id:'aws-dev', name:'AWS DevOps',        provider:'aws',   status:'healthy', regions:2, resources:890,  criticals:6, score:71, lastScan:'5h ago', nextScan:'~1h', scanState:'ok',    credentialStatus:'valid',   credentialNote:'Expires in 43d', coverage:97,
        domainScores: DS(69,70,56,64,59,73,61,53), domainCritical: DC(2,2,1,1,0,0,0,0) },
    ],
  },
  {
    id:'financeco', name:'Finance Co', criticals:8,
    domainScores: DS(82,74,71,79,76,80,68,73),
    domainCritical: DC(2,3,1,2,0,0,0,0),
    accounts:[
      { id:'gcp-prim', name:'GCP Primary',    provider:'gcp',   status:'healthy', regions:3, resources:1560, criticals:3, score:79, lastScan:'1h ago', nextScan:'~5h', scanState:'ok',    credentialStatus:'valid',   credentialNote:'Expires in 102d', coverage:100,
        domainScores: DS(83,75,72,80,77,81,69,74), domainCritical: DC(1,2,1,1,0,0,0,0) },
      { id:'aws-comp', name:'AWS Compliance', provider:'aws',   status:'healthy', regions:4, resources:2100, criticals:5, score:76, lastScan:'2h ago', nextScan:'~4h', scanState:'ok',    credentialStatus:'valid',   credentialNote:'Expires in 68d',  coverage:100,
        domainScores: DS(81,73,70,78,75,79,67,72), domainCritical: DC(1,1,0,1,0,0,0,0) },
      { id:'az-bkp',  name:'Azure Backup',   provider:'azure', status:'warning', regions:1, resources:340,  criticals:0, score:0,  lastScan:'7d ago', nextScan:'N/A', scanState:'stale', credentialStatus:'valid',   credentialNote:'Expires in 30d',  coverage:0,
        statusDetail:'Scan not running — check agent',
        domainScores: DS(0,0,0,0,0,0,0,0), domainCritical: DC(0,0,0,0,0,0,0,0) },
    ],
  },
];
const ALL_DOMAIN_SCORES   = DS(76,58,42,71,63,69,55,48);
const ALL_DOMAIN_CRITICAL = DC(9,6,5,3,4,7,2,0);

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
      const findings = d.findings || [];
      const SEV_ORDER = ['critical','high','medium','low'];
      const SEV_COLOR = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };

      // Top failing rules — ranked by count, colored by dominant severity
      const ruleMap = {};
      findings.forEach(f => {
        const k = f.title || f.rule_id || 'Unknown';
        if (!ruleMap[k]) ruleMap[k] = { count: 0, sevCounts: { critical:0, high:0, medium:0, low:0 }, svc: f.service || f.resource_type || '' };
        ruleMap[k].count++;
        const s = (f.severity || '').toLowerCase();
        if (ruleMap[k].sevCounts[s] !== undefined) ruleMap[k].sevCounts[s]++;
      });
      const topRules = Object.entries(ruleMap)
        .sort((a,b) => b[1].count - a[1].count).slice(0,7)
        .map(([name, info]) => {
          const domSev = SEV_ORDER.find(s => info.sevCounts[s] > 0) || 'low';
          return { name, value: info.count, color: SEV_COLOR[domSev], severity: domSev, svc: info.svc };
        });

      // Findings by service — severity stacked breakdown
      const svcMap = {};
      findings.forEach(f => {
        const svc = (f.service || 'other').toUpperCase();
        if (!svcMap[svc]) svcMap[svc] = { critical:0, high:0, medium:0, low:0, total:0 };
        const s = (f.severity || '').toLowerCase();
        if (svcMap[svc][s] !== undefined) svcMap[svc][s]++;
        svcMap[svc].total++;
      });
      // Fallback mock service data if no real findings
      const svcEntries = Object.entries(svcMap).sort((a,b)=>b[1].total-a[1].total).slice(0,6);
      const mockSvcEntries = [
        ['IAM',   {critical:12,high:28,medium:18,low:4,total:62}],
        ['S3',    {critical:6,high:14,medium:22,low:8,total:50}],
        ['EC2',   {critical:4,high:11,medium:19,low:6,total:40}],
        ['RDS',   {critical:3,high:8,medium:14,low:3,total:28}],
        ['VPC',   {critical:1,high:6,medium:12,low:5,total:24}],
        ['LAMBDA',{critical:2,high:5,medium:9,low:2,total:18}],
      ];
      const finalSvc = svcEntries.length >= 3 ? svcEntries : mockSvcEntries;
      const maxSvcTotal = Math.max(...finalSvc.map(([,v])=>v.total), 1);

      const mockRules = [
        {name:'S3 bucket public access not blocked',value:18,color:'#ef4444',severity:'critical',svc:'S3'},
        {name:'IAM root account MFA disabled',value:14,color:'#ef4444',severity:'critical',svc:'IAM'},
        {name:'Security group allows 0.0.0.0/0 ingress',value:12,color:'#f97316',severity:'high',svc:'EC2'},
        {name:'CloudTrail logging disabled in region',value:9,color:'#f97316',severity:'high',svc:'CloudTrail'},
        {name:'RDS snapshot publicly accessible',value:7,color:'#f59e0b',severity:'medium',svc:'RDS'},
        {name:'Lambda function no resource-based policy',value:6,color:'#f59e0b',severity:'medium',svc:'Lambda'},
        {name:'EBS volume not encrypted at rest',value:5,color:'#10b981',severity:'low',svc:'EBS'},
      ];
      const displayRules = topRules.length ? topRules : mockRules;

      return {
        left: (
          <>
            <h3 className="text-sm font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>Top Failing Rules</h3>
            <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>{displayRules.length} rules with active failures · sorted by impact</p>
            <div className="space-y-1.5">
              {displayRules.map((r,i) => (
                <div key={i} className="flex items-center gap-0 rounded-lg overflow-hidden"
                  style={{ backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-primary)' }}>
                  {/* Severity colour stripe */}
                  <div className="w-1 self-stretch flex-shrink-0" style={{ backgroundColor: r.color }} />
                  {/* Rank */}
                  <span className="text-xs font-bold w-7 text-center flex-shrink-0" style={{ color: 'var(--text-muted)' }}>#{i+1}</span>
                  {/* Rule name */}
                  <span className="flex-1 text-xs py-2.5 pr-2 truncate" style={{ color: 'var(--text-primary)' }}>{r.name}</span>
                  {/* Service chip */}
                  {r.svc && (
                    <span className="text-xs px-1.5 py-0.5 rounded mr-1.5 flex-shrink-0 font-mono"
                      style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)', fontSize: '10px' }}>
                      {r.svc}
                    </span>
                  )}
                  {/* Severity badge */}
                  {r.severity && (
                    <span className="text-xs font-bold px-1.5 py-0.5 rounded mr-2 flex-shrink-0"
                      style={{ backgroundColor: `${r.color}18`, color: r.color, border: `1px solid ${r.color}30`, fontSize: '9px', letterSpacing: '0.04em' }}>
                      {r.severity.toUpperCase()}
                    </span>
                  )}
                  {/* Fail count */}
                  <span className="text-xs font-bold w-10 text-center flex-shrink-0 py-2.5"
                    style={{ color: r.color }}>{r.value}<span className="font-normal text-xs" style={{ color: 'var(--text-muted)' }}> fail</span></span>
                </div>
              ))}
            </div>
          </>
        ),
        right: (
          <>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Risk by Service</h3>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Severity breakdown — critical + high = immediate action</p>
              </div>
              <div className="flex items-center gap-3">
                {SEV_ORDER.map(s => (
                  <div key={s} className="flex items-center gap-1">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: SEV_COLOR[s] }} />
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'capitalize' }}>{s}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="space-y-2">
              {finalSvc.map(([svc, counts]) => {
                const critHighPct = Math.round(((counts.critical + counts.high) / (counts.total || 1)) * 100);
                return (
                  <div key={svc}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold font-mono" style={{ color: 'var(--text-secondary)' }}>{svc}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs" style={{ color: critHighPct > 50 ? '#ef4444' : 'var(--text-muted)' }}>
                          {critHighPct}% critical+high
                        </span>
                        <span className="text-xs font-bold" style={{ color: 'var(--text-primary)' }}>{counts.total}</span>
                      </div>
                    </div>
                    <div className="flex h-4 rounded overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                      {SEV_ORDER.map(s => counts[s] > 0 && (
                        <div key={s}
                          title={`${s}: ${counts[s]}`}
                          style={{
                            width: `${(counts[s]/counts.total)*100}%`,
                            backgroundColor: SEV_COLOR[s],
                            minWidth: 3,
                            transition: 'width 0.3s ease'
                          }} />
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        ),
      };
    },
    getTable: () => null,   /* Top Failing Rules chart already covers this — no duplicate table */
    tableTitle: 'Top Misconfigurations',
  },
  threats: {
    label: 'Threats', Icon: AlertTriangle, href: '/threats', color: '#ef4444', bffView: 'threats',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      /* ── MITRE data ── */
      const mm = d.mitreMatrix || {};
      const mitreFlat = typeof mm === 'object' && !Array.isArray(mm)
        ? Object.values(mm).flat() : (Array.isArray(mm) ? mm : []);
      const mitreFromApi = mitreFlat.sort((a,b)=>(b.count||0)-(a.count||0)).slice(0,6)
        .map(t => ({ id: t.id||'', name: t.name||'', tactic: t.tactic||'', value: t.count||0 }));

      const mockMitre = [
        { id:'T1530', name:'Data from Cloud Storage',   tactic:'Collection',        value:28, severity:'critical' },
        { id:'T1078', name:'Valid Accounts',             tactic:'Defense Evasion',   value:21, severity:'critical' },
        { id:'T1190', name:'Exploit Public-Facing App', tactic:'Initial Access',    value:17, severity:'high'     },
        { id:'T1136', name:'Create Account',             tactic:'Persistence',       value:12, severity:'high'     },
        { id:'T1552', name:'Unsecured Credentials',      tactic:'Credential Access', value: 9, severity:'medium'   },
        { id:'T1071', name:'Application Layer Protocol', tactic:'Command & Control', value: 6, severity:'medium'   },
      ];
      const SEV_C = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
      const displayMitre = mitreFromApi.length
        ? mitreFromApi.map((t,i)=>({ ...t, severity: ['critical','critical','high','high','medium','medium'][i]||'medium' }))
        : mockMitre;

      /* ── Threat trend data — fallback mock if API empty ── */
      const mockTrend = (() => {
        const now = new Date('2026-03-29');
        return Array.from({ length: 30 }, (_,i) => {
          const t = i / 29;
          const wave = (ph,amp) => Math.sin(i*0.35+ph)*amp;
          return {
            date: (() => { const d2 = new Date(now); d2.setDate(d2.getDate()-(29-i)); return `${d2.getMonth()+1}/${d2.getDate()}`; })(),
            critical: Math.max(1, Math.round(3 + t*2  + wave(0,   1.5))),
            high:     Math.max(2, Math.round(7 + t*3  + wave(1,   2  ))),
            medium:   Math.max(3, Math.round(12+ t*1  + wave(2,   3  ))),
            low:      Math.max(1, Math.round(5 + t*0.5+ wave(0.5, 2  ))),
          };
        });
      })();
      const trendData = d.trendData?.length ? d.trendData : mockTrend;
      const totalToday = trendData.length ? (() => { const last = trendData[trendData.length-1]; return (last.critical||0)+(last.high||0)+(last.medium||0)+(last.low||0); })() : 0;

      return {
        /* ═══ LEFT — Stacked Area: threat volume by severity ═══ */
        left: (
          <>
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Threat Activity — 30 Days</h3>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                  Stacked finding volume by severity · today&apos;s total:{' '}
                  <span className="font-semibold" style={{ color: 'var(--text-secondary)' }}>{totalToday}</span>
                </p>
              </div>
              <div className="flex flex-col gap-0.5 items-end">
                {[['#ef4444','Critical'],['#f97316','High'],['#f59e0b','Medium'],['#10b981','Low']].map(([c,l]) => (
                  <div key={l} className="flex items-center gap-1.5">
                    <div className="w-2.5 h-1.5 rounded-full" style={{ backgroundColor: c, opacity: 0.7 }} />
                    <span style={{ fontSize:'10px', color:'var(--text-muted)' }}>{l}</span>
                  </div>
                ))}
              </div>
            </div>
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={trendData} margin={{ top:4, right:4, left:-22, bottom:0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" vertical={false} />
                <XAxis dataKey="date" tick={{ fill:'var(--text-tertiary)', fontSize:10 }} tickLine={false}
                  axisLine={{ stroke:'var(--border-primary)' }} interval={6} dy={4} />
                <YAxis tick={{ fill:'var(--text-tertiary)', fontSize:10 }} tickLine={false} axisLine={false} width={30} />
                <Tooltip
                  contentStyle={{ backgroundColor:'var(--bg-card)', borderColor:'var(--border-primary)', borderRadius:8, fontSize:12, padding:'8px 12px' }}
                  labelStyle={{ color:'var(--text-muted)', marginBottom:4, fontSize:11 }}
                  itemStyle={{ padding:'1px 0' }}
                />
                <Area type="monotone" dataKey="low"      stackId="1" stroke="#10b981" strokeWidth={0.5} fill="#10b981" fillOpacity={0.18} isAnimationActive={false} />
                <Area type="monotone" dataKey="medium"   stackId="1" stroke="#f59e0b" strokeWidth={0.5} fill="#f59e0b" fillOpacity={0.2}  isAnimationActive={false} />
                <Area type="monotone" dataKey="high"     stackId="1" stroke="#f97316" strokeWidth={1}   fill="#f97316" fillOpacity={0.25} isAnimationActive={false} />
                <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" strokeWidth={1.5} fill="#ef4444" fillOpacity={0.35} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </>
        ),

        /* ═══ RIGHT — Horizontal Bar: MITRE ATT&CK techniques ═══ */
        right: (
          <>
            <div className="flex items-start justify-between mb-1">
              <div>
                <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Top MITRE ATT&CK Techniques</h3>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Active techniques · bar = finding count · color = severity</p>
              </div>
              <div className="flex flex-col gap-0.5 items-end">
                {Object.entries(SEV_C).slice(0,3).map(([s,c]) => (
                  <div key={s} className="flex items-center gap-1">
                    <div className="w-2 h-2 rounded-sm" style={{ backgroundColor: c, opacity:0.75 }} />
                    <span style={{ fontSize:'9px', color:'var(--text-muted)', textTransform:'capitalize' }}>{s}</span>
                  </div>
                ))}
              </div>
            </div>
            <ResponsiveContainer width="100%" height={236}>
              <BarChart data={displayMitre} layout="vertical" margin={{ top:4, right:44, left:4, bottom:4 }} barCategoryGap="22%">
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" horizontal={false} />
                <XAxis type="number" tick={{ fill:'var(--text-tertiary)', fontSize:10 }} tickLine={false} axisLine={false} />
                <YAxis
                  type="category" dataKey="id" width={48}
                  tick={{ fill:'var(--text-tertiary)', fontSize:11, fontFamily:'monospace', fontWeight:600 }}
                  tickLine={false} axisLine={false}
                />
                <Tooltip
                  cursor={{ fill:'rgba(148,163,184,0.06)' }}
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null;
                    const it = payload[0].payload;
                    const sc = SEV_C[it.severity] || '#6b7280';
                    return (
                      <div style={{ backgroundColor:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:8, padding:'8px 12px', minWidth:200 }}>
                        <p style={{ color:sc, fontWeight:700, fontSize:12, marginBottom:4 }}>{it.id} — {it.name}</p>
                        <p style={{ color:'var(--text-muted)', fontSize:11 }}>Tactic: <span style={{ color:'var(--text-secondary)' }}>{it.tactic}</span></p>
                        <p style={{ color:'var(--text-muted)', fontSize:11 }}>Severity: <span style={{ color:sc, fontWeight:600 }}>{it.severity?.toUpperCase()}</span></p>
                        <p style={{ color:'var(--text-muted)', fontSize:11 }}>Findings: <span style={{ color:sc, fontWeight:700 }}>{it.value}</span></p>
                      </div>
                    );
                  }}
                />
                <Bar dataKey="value" radius={[0,4,4,0]} isAnimationActive={false} maxBarSize={22}>
                  <LabelList dataKey="value" position="right" style={{ fill:'var(--text-muted)', fontSize:10 }} />
                  {displayMitre.map((entry,idx) => (
                    <Cell key={idx} fill={SEV_C[entry.severity]||'#6b7280'} fillOpacity={0.65} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            {/* Technique name reference strip */}
            <div className="border-t pt-2 mt-1 grid grid-cols-2 gap-x-4 gap-y-0.5"
              style={{ borderColor:'var(--border-primary)' }}>
              {displayMitre.map((t,i) => (
                <div key={i} className="flex items-baseline gap-1.5 min-w-0">
                  <span className="text-xs font-bold font-mono flex-shrink-0"
                    style={{ color: SEV_C[t.severity]||'#6b7280', fontSize:'10px' }}>{t.id}</span>
                  <span className="text-xs truncate" style={{ color:'var(--text-muted)', fontSize:'10px' }}>{t.name}</span>
                  <span className="text-xs flex-shrink-0 ml-auto"
                    style={{ color:'var(--text-muted)', fontSize:'9px', opacity:0.7 }}>{t.tactic}</span>
                </div>
              ))}
            </div>
          </>
        ),

        /* ═══ BOTTOM LEFT — Risk Matrix scatter ═══ */
        bottomLeft: (() => {
          const SEV_C2 = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
          const riskMatrix = (d.riskMatrix || []).length ? d.riskMatrix : [
            { name:'Exposed IAM Keys',         likelihood:5, impact:5, count:14, severity:'critical' },
            { name:'Public S3 Buckets',         likelihood:5, impact:4, count:18, severity:'critical' },
            { name:'Open SG 0.0.0.0/0',         likelihood:4, impact:4, count:12, severity:'high'     },
            { name:'Unpatched EC2 Instances',    likelihood:4, impact:3, count: 9, severity:'high'     },
            { name:'No CloudTrail Logging',      likelihood:3, impact:4, count: 7, severity:'high'     },
            { name:'Weak IAM Password Policy',   likelihood:3, impact:3, count: 8, severity:'medium'   },
            { name:'Unencrypted EBS Volumes',    likelihood:2, impact:3, count:12, severity:'medium'   },
            { name:'No VPC Flow Logs',           likelihood:2, impact:2, count: 5, severity:'low'      },
          ];
          return (
            <>
              <div className="flex items-start justify-between mb-1">
                <div>
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Risk Matrix</h3>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    Likelihood × Impact · bubble size = finding count · hover for detail
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
                  {Object.entries(SEV_C2).map(([s,c]) => (
                    <div key={s} className="flex items-center gap-1">
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: c, opacity: 0.75 }} />
                      <span style={{ fontSize:'9px', color:'var(--text-muted)', textTransform:'capitalize' }}>{s}</span>
                    </div>
                  ))}
                </div>
              </div>
              <ResponsiveContainer width="100%" height={248}>
                <ScatterChart margin={{ top: 8, right: 12, left: -10, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" />
                  <XAxis
                    type="number" dataKey="likelihood" domain={[0.5, 5.5]} ticks={[1,2,3,4,5]}
                    tick={{ fill:'var(--text-tertiary)', fontSize:10 }} tickLine={false}
                    axisLine={{ stroke:'var(--border-primary)' }}
                    label={{ value:'Likelihood →', position:'insideBottom', offset:-12, fill:'var(--text-muted)', fontSize:10 }}
                  />
                  <YAxis
                    type="number" dataKey="impact" domain={[0.5, 5.5]} ticks={[1,2,3,4,5]}
                    tick={{ fill:'var(--text-tertiary)', fontSize:10 }} tickLine={false} axisLine={false} width={28}
                    label={{ value:'Impact', angle:-90, position:'insideLeft', offset:14, fill:'var(--text-muted)', fontSize:10 }}
                  />
                  <ZAxis type="number" dataKey="count" range={[300, 1800]} />
                  <ReferenceLine x={3} stroke="var(--border-primary)" strokeDasharray="4 4" strokeOpacity={0.6} />
                  <ReferenceLine y={3} stroke="var(--border-primary)" strokeDasharray="4 4" strokeOpacity={0.6} />
                  <Tooltip
                    cursor={{ strokeDasharray:'3 3' }}
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const it = payload[0].payload;
                      const sc = SEV_C2[it.severity] || '#6b7280';
                      return (
                        <div style={{ backgroundColor:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:8, padding:'8px 12px', minWidth:190 }}>
                          <p style={{ color:'var(--text-primary)', fontWeight:700, fontSize:12, marginBottom:4 }}>{it.name}</p>
                          <p style={{ color:'var(--text-muted)', fontSize:11 }}>Likelihood: <span style={{ color:'var(--text-secondary)', fontWeight:600 }}>{it.likelihood}/5</span></p>
                          <p style={{ color:'var(--text-muted)', fontSize:11 }}>Impact: <span style={{ color:'var(--text-secondary)', fontWeight:600 }}>{it.impact}/5</span></p>
                          <p style={{ color:'var(--text-muted)', fontSize:11 }}>Severity: <span style={{ color:sc, fontWeight:700 }}>{it.severity?.toUpperCase()}</span></p>
                          <p style={{ color:'var(--text-muted)', fontSize:11 }}>Findings: <span style={{ color:sc, fontWeight:700 }}>{it.count}</span></p>
                        </div>
                      );
                    }}
                  />
                  <Scatter
                    data={riskMatrix}
                    shape={(props) => {
                      const { cx, cy, payload } = props;
                      const c = SEV_C2[payload.severity] || '#6b7280';
                      const r = Math.sqrt(payload.count) * 2.8 + 5;
                      return (
                        <g>
                          <circle cx={cx} cy={cy} r={r} fill={c} fillOpacity={0.55} stroke={c} strokeWidth={1.5} strokeOpacity={0.85} />
                          {payload.count > 10 && (
                            <text x={cx} y={cy} textAnchor="middle" dominantBaseline="central" fontSize={9} fontWeight={700} fill={c}>{payload.count}</text>
                          )}
                        </g>
                      );
                    }}
                  />
                  {/* Quadrant labels */}
                  {[
                    { x:1.1, y:4.7, label:'MITIGATE',   opacity:0.25 },
                    { x:3.6, y:4.7, label:'ACT NOW',     opacity:0.35 },
                    { x:1.1, y:1.1, label:'ACCEPT',      opacity:0.18 },
                    { x:3.6, y:1.1, label:'MONITOR',     opacity:0.22 },
                  ].map(q => (
                    <ReferenceLine
                      key={q.label}
                      x={q.x} stroke="none"
                      label={{ value:q.label, position:'insideTopRight', fill:'var(--text-muted)', fontSize:9, fontWeight:700, opacity:q.opacity }}
                    />
                  ))}
                </ScatterChart>
              </ResponsiveContainer>
            </>
          );
        })(),

        /* ═══ BOTTOM RIGHT — Kill Chain stage bar ═══ */
        bottomRight: (() => {
          const stages = [
            { stage:'Recon',      short:'Recon',   count: 3, phase:0 },
            { stage:'Init Access',short:'Init Acc', count: 8, phase:1 },
            { stage:'Execution',  short:'Exec',     count:12, phase:2 },
            { stage:'Persistence',short:'Persist',  count: 9, phase:2 },
            { stage:'Priv Esc',   short:'Priv Esc', count: 6, phase:3 },
            { stage:'Def Evasion',short:'Def Ev',   count:14, phase:2 },
            { stage:'Cred Access',short:'Creds',    count:11, phase:3 },
            { stage:'Discovery',  short:'Discov',   count: 7, phase:1 },
            { stage:'Lateral Mov',short:'Lat Mov',  count: 4, phase:4 },
            { stage:'Collection', short:'Collect',  count: 8, phase:3 },
            { stage:'C2',         short:'C2',        count: 3, phase:4 },
            { stage:'Exfiltration',short:'Exfil',   count: 2, phase:4 },
          ];
          const phaseColor = [
            '#10b981', // phase 0 — early/recon
            '#f59e0b', // phase 1 — initial
            '#f97316', // phase 2 — mid
            '#ef4444', // phase 3 — late
            '#dc2626', // phase 4 — critical late
          ];
          const maxCount = Math.max(...stages.map(s => s.count), 1);
          const lateStageTotal = stages.filter(s => s.phase >= 3).reduce((sum,s) => sum + s.count, 0);
          return (
            <>
              <div className="flex items-start justify-between mb-1">
                <div>
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Attack Kill Chain Coverage</h3>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    Findings per MITRE tactic stage · late-stage detections signal active intrusion
                  </p>
                </div>
                {lateStageTotal > 0 && (
                  <span className="text-xs font-bold px-2 py-0.5 rounded flex-shrink-0"
                    style={{ backgroundColor:'#ef444420', color:'#ef4444', fontSize:'9px' }}>
                    {lateStageTotal} late-stage
                  </span>
                )}
              </div>
              {/* Phase legend */}
              <div className="flex items-center gap-3 mb-3 flex-wrap">
                {[['#10b981','Early'],['#f59e0b','Initial'],['#f97316','Mid'],['#ef4444','Late'],['#dc2626','Critical']].map(([c,l]) => (
                  <div key={l} className="flex items-center gap-1">
                    <div className="w-2.5 h-2 rounded-sm" style={{ backgroundColor: c, opacity:0.75 }} />
                    <span style={{ fontSize:'9px', color:'var(--text-muted)' }}>{l}</span>
                  </div>
                ))}
              </div>
              <ResponsiveContainer width="100%" height={224}>
                <BarChart data={stages} margin={{ top:4, right:8, left:-20, bottom:28 }} barCategoryGap="18%">
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" vertical={false} />
                  <XAxis
                    dataKey="short"
                    tick={{ fill:'var(--text-tertiary)', fontSize:9 }}
                    tickLine={false}
                    axisLine={{ stroke:'var(--border-primary)' }}
                    angle={-35} textAnchor="end" dy={4}
                  />
                  <YAxis tick={{ fill:'var(--text-tertiary)', fontSize:10 }} tickLine={false} axisLine={false} width={28} />
                  <Tooltip
                    cursor={{ fill:'rgba(148,163,184,0.06)' }}
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const it = payload[0].payload;
                      const c = phaseColor[it.phase];
                      return (
                        <div style={{ backgroundColor:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:8, padding:'8px 12px', minWidth:160 }}>
                          <p style={{ color:'var(--text-primary)', fontWeight:700, fontSize:12, marginBottom:4 }}>{it.stage}</p>
                          <p style={{ color:'var(--text-muted)', fontSize:11 }}>Findings: <span style={{ color:c, fontWeight:700 }}>{it.count}</span></p>
                          <p style={{ color:'var(--text-muted)', fontSize:11 }}>Share: <span style={{ color:c, fontWeight:600 }}>{Math.round((it.count/maxCount)*100)}% of peak</span></p>
                        </div>
                      );
                    }}
                  />
                  <Bar dataKey="count" radius={[3,3,0,0]} isAnimationActive={false} maxBarSize={32}>
                    <LabelList dataKey="count" position="top" style={{ fill:'var(--text-muted)', fontSize:9 }} />
                    {stages.map((s, idx) => (
                      <Cell key={idx} fill={phaseColor[s.phase]} fillOpacity={0.7} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </>
          );
        })(),

        /* ═══ FOOTER — Top Affected Accounts (by threat severity) ═══ */
        footer: (() => {
          const SEV_C3 = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
          /* Rank accounts by threat domain criticals + overall criticals as weight */
          const ranked = MOCK_TENANTS.flatMap(t =>
            t.accounts.map(acc => {
              const threatCrit  = acc.domainCritical?.threats  || 0;
              const threatScore = acc.domainScores?.threats    || 0;
              const highProxy   = Math.round(acc.criticals * 1.6);
              const medProxy    = Math.round(acc.criticals * 2.8);
              const weight      = threatCrit * 4 + acc.criticals * 3 + highProxy;
              return { ...acc, tenantName: t.name, tenantId: t.id, threatCrit, threatScore, highProxy, medProxy, weight };
            })
          ).sort((a, b) => b.weight - a.weight).slice(0, 6);

          const maxWeight = ranked[0]?.weight || 1;

          return (
            <>
              {/* Header */}
              <div className="px-5 py-3 border-b flex items-center justify-between"
                style={{ borderColor:'var(--border-primary)', backgroundColor:'var(--bg-secondary)' }}>
                <div>
                  <h3 className="text-sm font-semibold" style={{ color:'var(--text-primary)' }}>Top Affected Accounts</h3>
                  <p className="text-xs mt-0.5" style={{ color:'var(--text-muted)' }}>
                    Accounts ranked by active threat severity — prioritise for investigation
                  </p>
                </div>
                <Link href="/threats" className="flex items-center gap-1 text-xs font-semibold px-3 py-1.5 rounded-lg"
                  style={{ color:'#ef4444', backgroundColor:'#ef444410' }}>
                  All Threats <ArrowRight className="w-3 h-3" />
                </Link>
              </div>

              {/* Rows */}
              <div className="divide-y" style={{ borderColor:'var(--border-primary)' }}>
                {ranked.map((acc, i) => {
                  const isIssue   = acc.status === 'warning' || acc.scanState !== 'ok';
                  const sc        = acc.criticals > 5 ? '#ef4444' : acc.criticals > 2 ? '#f97316' : '#f59e0b';
                  const barPct    = Math.round((acc.weight / maxWeight) * 100);
                  const total     = acc.criticals + acc.highProxy + acc.medProxy;
                  const tScore    = acc.threatScore;
                  const tScoreC   = tScore >= 75 ? '#22c55e' : tScore >= 50 ? '#f97316' : tScore > 0 ? '#ef4444' : '#6b7280';

                  return (
                    <div key={acc.id} className="flex items-center gap-4 px-5 py-3 hover:bg-white/[0.02] transition-colors">

                      {/* Rank */}
                      <span className="text-xs font-bold w-5 flex-shrink-0 tabular-nums text-center"
                        style={{ color: i < 3 ? '#ef4444' : 'var(--text-muted)' }}>#{i+1}</span>

                      {/* Status dot */}
                      <div className="w-2 h-2 rounded-full flex-shrink-0"
                        style={{ backgroundColor: isIssue ? '#f59e0b' : '#22c55e' }} />

                      {/* Account + tenant */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <CloudProviderBadge provider={acc.provider} size="sm" />
                          <span className="text-xs font-semibold truncate" style={{ color:'var(--text-primary)' }}>
                            {acc.name}
                          </span>
                          {isIssue && (
                            <span className="text-xs font-bold px-1.5 py-0.5 rounded flex-shrink-0"
                              style={{ backgroundColor:'#f59e0b18', color:'#f59e0b', fontSize:'9px' }}>
                              ⚠ {acc.scanState !== 'ok' ? 'Scan issue' : 'Cred issue'}
                            </span>
                          )}
                        </div>
                        <span className="text-xs" style={{ color:'var(--text-muted)' }}>
                          {acc.tenantName} · {acc.regions} regions · {(acc.resources||0).toLocaleString()} resources
                        </span>
                      </div>

                      {/* Severity bar */}
                      <div className="w-36 flex-shrink-0">
                        <div className="flex h-2.5 rounded overflow-hidden mb-1" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                          {[
                            { val: acc.criticals, c:'#ef4444' },
                            { val: acc.highProxy,  c:'#f97316' },
                            { val: acc.medProxy,   c:'#f59e0b' },
                          ].filter(s => s.val > 0).map((s, si) => (
                            <div key={si} style={{ width:`${(s.val/Math.max(total,1))*100}%`, backgroundColor:s.c, minWidth:3 }} />
                          ))}
                        </div>
                        <div className="flex gap-3">
                          {[{l:'C',v:acc.criticals,c:'#ef4444'},{l:'H',v:acc.highProxy,c:'#f97316'},{l:'M',v:acc.medProxy,c:'#f59e0b'}].map(s => (
                            <span key={s.l} style={{ fontSize:'9px', color:'var(--text-muted)' }}>
                              <span style={{ color:s.c, fontWeight:700 }}>{s.l}</span>:{s.v}
                            </span>
                          ))}
                        </div>
                      </div>

                      {/* Threat score mini-arc */}
                      <div className="flex-shrink-0 flex flex-col items-center" style={{ width:48 }}>
                        {tScore > 0 ? (
                          <>
                            <span className="text-sm font-black tabular-nums" style={{ color: tScoreC }}>{tScore}</span>
                            <span style={{ fontSize:'9px', color:'var(--text-muted)' }}>threat</span>
                          </>
                        ) : (
                          <span style={{ fontSize:'10px', color:'#6b7280' }}>N/A</span>
                        )}
                      </div>

                      {/* Criticals badge */}
                      <div className="flex-shrink-0" style={{ width:60 }}>
                        {acc.criticals > 0 ? (
                          <span className="text-xs font-bold px-2 py-0.5 rounded"
                            style={{ backgroundColor:'#ef444418', color:'#ef4444', border:'1px solid #ef444430' }}>
                            ▲{acc.criticals}
                          </span>
                        ) : (
                          <span className="text-xs font-semibold" style={{ color:'#22c55e' }}>✓ Clean</span>
                        )}
                      </div>

                    </div>
                  );
                })}
              </div>

              {/* Footer totals */}
              <div className="px-5 py-2 border-t flex items-center gap-3 flex-wrap"
                style={{ borderColor:'var(--border-primary)', backgroundColor:'var(--bg-secondary)' }}>
                <span className="text-xs" style={{ color:'var(--text-muted)' }}>
                  <span className="font-semibold" style={{ color:'#ef4444' }}>
                    {MOCK_TENANTS.flatMap(t=>t.accounts).reduce((s,a)=>s+(a.criticals||0),0)}
                  </span> total criticals ·{' '}
                  <span className="font-semibold" style={{ color:'var(--text-secondary)' }}>
                    {MOCK_TENANTS.flatMap(t=>t.accounts).length}
                  </span> accounts monitored
                </span>
              </div>
            </>
          );
        })(),
      };
    },
    getTable: () => null,
    tableTitle: 'Top Threat Findings',
  },
  compliance: {
    label: 'Compliance', Icon: ClipboardCheck, href: '/compliance', color: '#22c55e', bffView: 'compliance',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      /* ── Shared data ── */
      const mockFrameworks = [
        { name:'CIS AWS v1.4', short:'CIS AWS',  score:78, passed:156, total:200, trend:+2, critical:4  },
        { name:'NIST 800-53',  short:'NIST',     score:71, passed:284, total:400, trend:-1, critical:8  },
        { name:'ISO 27001',    short:'ISO 27001',score:74, passed:111, total:150, trend:+1, critical:5  },
        { name:'PCI-DSS 4.0',  short:'PCI-DSS',  score:68, passed: 82, total:120, trend:-3, critical:11 },
        { name:'HIPAA',        short:'HIPAA',    score:82, passed: 82, total:100, trend:+3, critical:2  },
        { name:'SOC 2 Type II',short:'SOC 2',    score:76, passed:114, total:150, trend:0,  critical:6  },
      ];
      const apiFrameworks = (d.frameworks || []).filter(fw => (fw.score || 0) > 0);
      const frameworks = apiFrameworks.length >= 2 ? apiFrameworks : mockFrameworks;
      const fwC     = (s) => s >= 80 ? '#22c55e' : s >= 70 ? '#f59e0b' : '#ef4444';
      const fwLabel = (s) => s >= 80 ? 'Compliant' : s >= 70 ? 'At Risk' : 'Non-Compliant';

      return {

        /* ═══════════════════════════════════════════════════════════
           LEFT — "WHAT TYPE of controls are failing?"
           Control Category Breakdown — horizontal stacked bar
           ═══════════════════════════════════════════════════════════ */
        left: (() => {
          const categories = [
            { cat:'Access Control',      pass:82,  fail:34, critical:9  },
            { cat:'Logging & Monitoring',pass:61,  fail:22, critical:6  },
            { cat:'Encryption',          pass:74,  fail:18, critical:4  },
            { cat:'Network Security',    pass:88,  fail:14, critical:3  },
            { cat:'Data Protection',     pass:55,  fail:12, critical:5  },
            { cat:'Identity & MFA',      pass:49,  fail:19, critical:8  },
            { cat:'Config Management',   pass:107, fail:11, critical:2  },
          ];
          const maxTotal = Math.max(...categories.map(c => c.pass + c.fail), 1);
          const totalFailing = categories.reduce((s,c)=>s+c.fail, 0);
          return (
            <>
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3 className="text-sm font-semibold" style={{ color:'var(--text-primary)' }}>Control Category Breakdown</h3>
                  <p className="text-xs mt-0.5" style={{ color:'var(--text-muted)' }}>
                    <span className="font-semibold" style={{ color:'#ef4444' }}>{totalFailing}</span> failing controls across {categories.length} categories
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  {[['#22c55e','Passing'],['#ef4444','Failing']].map(([c,l]) => (
                    <div key={l} className="flex items-center gap-1">
                      <div className="w-2 h-2 rounded-sm" style={{ backgroundColor:c, opacity:0.75 }} />
                      <span style={{ fontSize:'9px', color:'var(--text-muted)' }}>{l}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="space-y-2.5">
                {categories.sort((a,b) => b.fail - a.fail).map((cat) => {
                  const total = cat.pass + cat.fail;
                  const failPct = Math.round((cat.fail / total) * 100);
                  const isHighRisk = failPct > 30 || cat.critical >= 5;
                  return (
                    <div key={cat.cat}>
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-xs font-semibold truncate" style={{ color:'var(--text-secondary)' }}>{cat.cat}</span>
                          {cat.critical > 0 && (
                            <span className="text-xs font-bold flex-shrink-0"
                              style={{ color:'#ef4444', fontSize:'9px' }}>▲{cat.critical} crit</span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <span className="text-xs" style={{ color: failPct > 30 ? '#ef4444' : 'var(--text-muted)' }}>
                            {failPct}% fail
                          </span>
                          <span className="text-xs font-semibold tabular-nums" style={{ color: 'var(--text-muted)' }}>
                            {cat.fail}/{total}
                          </span>
                        </div>
                      </div>
                      <div className="flex h-3 rounded overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                        <div style={{ width:`${(cat.pass/maxTotal)*100}%`, backgroundColor:'#22c55e', opacity:0.55, minWidth: cat.pass > 0 ? 3 : 0 }} />
                        <div style={{ width:`${(cat.fail/maxTotal)*100}%`, backgroundColor:'#ef4444', opacity: isHighRisk ? 0.75 : 0.5, minWidth: cat.fail > 0 ? 3 : 0 }} />
                      </div>
                    </div>
                  );
                })}
              </div>
              <p className="text-xs mt-3 pt-3 border-t" style={{ color:'var(--text-muted)', borderColor:'var(--border-primary)' }}>
                Fixing <span style={{ color:'#ef4444', fontWeight:700 }}>Access Control</span> + <span style={{ color:'#ef4444', fontWeight:700 }}>Identity & MFA</span> would resolve{' '}
                <span style={{ color:'var(--text-secondary)', fontWeight:700 }}>53 controls</span> across all 6 frameworks
              </p>
            </>
          );
        })(),

        /* ═══════════════════════════════════════════════════════════
           RIGHT — "WHERE is compliance risk concentrated?"
           Framework Scores bar + Top Failing Accounts list
           ═══════════════════════════════════════════════════════════ */
        right: (() => {
          /* Per-account compliance score — derived from domainScores.compliance */
          const accountRows = MOCK_TENANTS.flatMap(t =>
            t.accounts
              .filter(a => (a.domainScores?.compliance || 0) > 0)
              .map(a => ({
                name: a.name, provider: a.provider, tenant: t.name,
                score: a.domainScores.compliance,
                criticals: a.domainCritical?.compliance || 0,
                failingControls: Math.round((1 - a.domainScores.compliance / 100) * 50),
              }))
          ).sort((a,b) => a.score - b.score).slice(0, 5); // worst first

          return (
            <>
              {/* Framework score bar */}
              <div className="flex items-center justify-between mb-2">
                <div>
                  <h3 className="text-sm font-semibold" style={{ color:'var(--text-primary)' }}>Framework Scores</h3>
                  <p className="text-xs mt-0.5" style={{ color:'var(--text-muted)' }}>Current pass rate · dashed = 80% target</p>
                </div>
              </div>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart
                  data={frameworks.map(fw => ({ name: fw.short || fw.name, score: fw.score, critical: fw.critical || 0 }))}
                  margin={{ top:4, right:8, left:-20, bottom:4 }}
                  barCategoryGap="28%"
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-primary)" vertical={false} />
                  <XAxis dataKey="name" tick={{ fill:'var(--text-tertiary)', fontSize:10 }} tickLine={false} axisLine={{ stroke:'var(--border-primary)' }} />
                  <YAxis domain={[0,100]} ticks={[0,50,80,100]} tick={{ fill:'var(--text-tertiary)', fontSize:10 }} tickLine={false} axisLine={false} width={28} />
                  <ReferenceLine y={80} stroke="#22c55e" strokeDasharray="4 4" strokeOpacity={0.5}
                    label={{ value:'Target 80%', position:'insideTopRight', fill:'#22c55e', fontSize:9, opacity:0.7 }} />
                  <Tooltip cursor={{ fill:'rgba(148,163,184,0.06)' }}
                    content={({ active, payload }) => {
                      if (!active || !payload?.length) return null;
                      const it = payload[0].payload;
                      const c = fwC(it.score);
                      return (
                        <div style={{ backgroundColor:'var(--bg-card)', border:'1px solid var(--border-primary)', borderRadius:8, padding:'8px 12px', minWidth:150 }}>
                          <p style={{ color:'var(--text-primary)', fontWeight:700, fontSize:12, marginBottom:3 }}>{it.name}</p>
                          <p style={{ color:'var(--text-muted)', fontSize:11 }}>Score: <span style={{ color:c, fontWeight:700 }}>{it.score}%</span></p>
                          <p style={{ color:'var(--text-muted)', fontSize:11 }}>Status: <span style={{ color:c }}>{fwLabel(it.score)}</span></p>
                          {it.critical > 0 && <p style={{ color:'var(--text-muted)', fontSize:11 }}>Critical gaps: <span style={{ color:'#ef4444', fontWeight:700 }}>{it.critical}</span></p>}
                        </div>
                      );
                    }}
                  />
                  <Bar dataKey="score" radius={[3,3,0,0]} isAnimationActive={false} maxBarSize={38}>
                    <LabelList dataKey="score" position="top" formatter={(v) => `${v}%`} style={{ fill:'var(--text-muted)', fontSize:9 }} />
                    {frameworks.map((fw, idx) => (
                      <Cell key={idx} fill={fwC(fw.score)} fillOpacity={0.65} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>

              {/* Top Failing Accounts — compact ranked list */}
              <div className="mt-3 pt-3 border-t" style={{ borderColor:'var(--border-primary)' }}>
                <p className="text-xs font-semibold mb-2" style={{ color:'var(--text-muted)' }}>
                  Top Failing Accounts · worst compliance score first
                </p>
                <div className="space-y-1.5">
                  {accountRows.map((acc, i) => {
                    const c = fwC(acc.score);
                    return (
                      <div key={acc.name} className="flex items-center gap-3 rounded px-2 py-1.5"
                        style={{ backgroundColor:'var(--bg-secondary)', border:'1px solid var(--border-primary)' }}>
                        <span className="text-xs font-bold w-4 text-center flex-shrink-0"
                          style={{ color: i < 2 ? '#ef4444' : 'var(--text-muted)' }}>#{i+1}</span>
                        <CloudProviderBadge provider={acc.provider} size="sm" />
                        <span className="text-xs font-semibold flex-1 truncate" style={{ color:'var(--text-primary)' }}>{acc.name}</span>
                        <span className="text-xs flex-shrink-0" style={{ color:'var(--text-muted)' }}>{acc.tenant}</span>
                        <div className="w-16 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                          <div className="h-full rounded-full" style={{ width:`${acc.score}%`, backgroundColor:c }} />
                        </div>
                        <span className="text-xs font-bold tabular-nums flex-shrink-0 w-9 text-right" style={{ color:c }}>{acc.score}%</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          );
        })(),

        /* ═══════════════════════════════════════════════════════════
           BOTTOM LEFT — "WHAT should I fix first?"
           Cross-Framework Rules — fix one rule → fix multiple frameworks
           ═══════════════════════════════════════════════════════════ */
        bottomLeft: (() => {
          const crossRules = [
            { rule:'Root account MFA disabled',         frameworks:['CIS AWS','PCI-DSS','NIST','ISO 27001'], accounts:9, severity:'critical', uplift:'+4.2%' },
            { rule:'S3 bucket public access not blocked',frameworks:['CIS AWS','PCI-DSS','HIPAA'],           accounts:7, severity:'critical', uplift:'+2.8%' },
            { rule:'CloudTrail not enabled all regions', frameworks:['CIS AWS','NIST','SOC 2','HIPAA'],      accounts:6, severity:'high',     uplift:'+3.1%' },
            { rule:'Security group allows 0.0.0.0/0',   frameworks:['PCI-DSS','ISO 27001','SOC 2'],          accounts:5, severity:'high',     uplift:'+2.4%' },
            { rule:'IAM password policy not compliant',  frameworks:['CIS AWS','NIST','PCI-DSS'],            accounts:9, severity:'high',     uplift:'+1.9%' },
            { rule:'RDS snapshot publicly accessible',   frameworks:['HIPAA','PCI-DSS'],                     accounts:4, severity:'critical', uplift:'+1.2%' },
          ];
          const SEV_C4 = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b' };
          const FW_COLORS = { 'CIS AWS':'#f97316','PCI-DSS':'#ef4444','NIST':'#3b82f6','ISO 27001':'#8b5cf6','HIPAA':'#22c55e','SOC 2':'#06b6d4' };
          return (
            <>
              <h3 className="text-sm font-semibold mb-0.5" style={{ color:'var(--text-primary)' }}>Cross-Framework Rules</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>
                Fix one rule → improve multiple frameworks simultaneously · sorted by impact
              </p>
              <div className="space-y-2">
                {crossRules.map((r, i) => {
                  const sc = SEV_C4[r.severity] || '#6b7280';
                  return (
                    <div key={i} className="rounded-lg border overflow-hidden flex"
                      style={{ backgroundColor:'var(--bg-secondary)', borderColor:'var(--border-primary)' }}>
                      <div className="w-1 flex-shrink-0" style={{ backgroundColor: sc }} />
                      <div className="flex-1 px-3 py-2.5">
                        <div className="flex items-start justify-between gap-2 mb-1.5">
                          <span className="text-xs font-semibold leading-tight" style={{ color:'var(--text-primary)' }}>{r.rule}</span>
                          <span className="text-xs font-bold flex-shrink-0 px-1.5 py-0.5 rounded"
                            style={{ backgroundColor:`${sc}18`, color:sc, fontSize:'9px' }}>
                            {r.severity.toUpperCase()}
                          </span>
                        </div>
                        {/* Framework tags */}
                        <div className="flex items-center gap-1.5 flex-wrap mb-1.5">
                          {r.frameworks.map(fw => (
                            <span key={fw} className="text-xs px-1.5 py-0.5 rounded font-semibold"
                              style={{ backgroundColor:`${FW_COLORS[fw] || '#6b7280'}18`, color: FW_COLORS[fw] || '#6b7280', fontSize:'9px' }}>
                              {fw}
                            </span>
                          ))}
                        </div>
                        {/* Stats row */}
                        <div className="flex items-center gap-3">
                          <span style={{ fontSize:'10px', color:'var(--text-muted)' }}>
                            <span style={{ color:'var(--text-secondary)', fontWeight:700 }}>{r.accounts}</span> accounts affected
                          </span>
                          <span style={{ fontSize:'10px', color:'var(--text-muted)' }}>
                            fixes <span style={{ color:'var(--text-secondary)', fontWeight:700 }}>{r.frameworks.length}</span> frameworks
                          </span>
                          <span className="ml-auto text-xs font-bold"
                            style={{ color:'#22c55e', fontSize:'10px' }}>
                            {r.uplift} score
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          );
        })(),

        /* ═══════════════════════════════════════════════════════════
           BOTTOM RIGHT — "WHEN does it matter?"
           Audit Deadline Risk — certification countdown
           ═══════════════════════════════════════════════════════════ */
        bottomRight: (() => {
          const audits = [
            { fw:'PCI-DSS 4.0',  daysLeft:47,  currentScore:68, requiredScore:80, lastAudit:'Oct 2025', auditor:'QSA External' },
            { fw:'SOC 2 Type II',daysLeft:89,  currentScore:76, requiredScore:80, lastAudit:'Sep 2025', auditor:'Ernst & Young' },
            { fw:'HIPAA',        daysLeft:134, currentScore:82, requiredScore:80, lastAudit:'Jan 2026', auditor:'Internal'      },
            { fw:'ISO 27001',    daysLeft:203, currentScore:74, requiredScore:80, lastAudit:'Jul 2025', auditor:'BSI'           },
            { fw:'NIST 800-53',  daysLeft:312, currentScore:71, requiredScore:75, lastAudit:'Apr 2025', auditor:'Internal'      },
            { fw:'CIS AWS',      daysLeft:365, currentScore:78, requiredScore:80, lastAudit:'Mar 2025', auditor:'Automated'     },
          ];
          const urgencyColor = (days) => days < 60 ? '#ef4444' : days < 120 ? '#f97316' : days < 180 ? '#f59e0b' : '#22c55e';
          const urgencyLabel = (days) => days < 60 ? 'Critical' : days < 120 ? 'Urgent' : days < 180 ? 'Prepare' : 'On Track';
          return (
            <>
              <h3 className="text-sm font-semibold mb-0.5" style={{ color:'var(--text-primary)' }}>Audit Deadline Risk</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>
                Certification schedule · current score vs required threshold
              </p>
              <div className="space-y-2">
                {audits.map((a) => {
                  const uc   = urgencyColor(a.daysLeft);
                  const ul   = urgencyLabel(a.daysLeft);
                  const gap  = a.requiredScore - a.currentScore;
                  const fc   = fwC(a.currentScore);
                  return (
                    <div key={a.fw} className="rounded-lg border overflow-hidden flex"
                      style={{ backgroundColor:'var(--bg-secondary)', borderColor: a.daysLeft < 60 ? `${uc}40` : 'var(--border-primary)' }}>
                      <div className="w-1 flex-shrink-0" style={{ backgroundColor: uc }} />
                      <div className="flex-1 px-3 py-2">
                        <div className="flex items-center justify-between mb-1.5">
                          <span className="text-xs font-semibold" style={{ color:'var(--text-primary)' }}>{a.fw}</span>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold px-1.5 py-0.5 rounded"
                              style={{ backgroundColor:`${uc}18`, color:uc, fontSize:'9px' }}>{ul}</span>
                            <span className="text-xs font-black tabular-nums" style={{ color: uc }}>
                              {a.daysLeft}d
                            </span>
                          </div>
                        </div>
                        {/* Score progress: current vs required */}
                        <div className="relative mb-1">
                          <div className="h-2 rounded overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                            <div className="h-full rounded" style={{ width:`${a.currentScore}%`, backgroundColor: fc, opacity:0.7 }} />
                          </div>
                          {/* Required threshold marker */}
                          <div className="absolute top-0 bottom-0 w-px"
                            style={{ left:`${a.requiredScore}%`, backgroundColor:'#ffffff', opacity:0.6 }} />
                        </div>
                        <div className="flex items-center gap-3">
                          <span style={{ fontSize:'10px', color:'var(--text-muted)' }}>
                            Current: <span style={{ color:fc, fontWeight:700 }}>{a.currentScore}%</span>
                          </span>
                          <span style={{ fontSize:'10px', color:'var(--text-muted)' }}>
                            Need: <span style={{ color:'var(--text-secondary)', fontWeight:600 }}>{a.requiredScore}%</span>
                          </span>
                          {gap > 0 ? (
                            <span style={{ fontSize:'10px' }}>
                              <span style={{ color:'#ef4444', fontWeight:700 }}>-{gap}%</span>
                              <span style={{ color:'var(--text-muted)' }}> gap</span>
                            </span>
                          ) : (
                            <span style={{ fontSize:'10px', color:'#22c55e', fontWeight:700 }}>✓ Ready</span>
                          )}
                          <span className="ml-auto" style={{ fontSize:'9px', color:'var(--text-muted)' }}>{a.auditor}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          );
        })(),

      };
    },
    getTable: (d) => {
      const mockControls = [
        { control_id:'PCI-DSS-8.2.1', title:'Unique user IDs for all users',              framework:'PCI-DSS 4.0', severity:'critical', days_open:34 },
        { control_id:'NIST-AC-2',     title:'Account Management — stale accounts',        framework:'NIST 800-53', severity:'high',     days_open:21 },
        { control_id:'CIS-1.4',       title:'Ensure root account MFA is enabled',         framework:'CIS AWS',     severity:'critical', days_open:47 },
        { control_id:'ISO-A.9.4.1',   title:'Information access restriction — public S3', framework:'ISO 27001',   severity:'high',     days_open:12 },
        { control_id:'HIPAA-164.312', title:'Audit controls — CloudTrail disabled',       framework:'HIPAA',       severity:'high',     days_open: 8 },
        { control_id:'PCI-DSS-6.3.3', title:'Software patching — EC2 instances',         framework:'PCI-DSS 4.0', severity:'medium',   days_open:19 },
        { control_id:'SOC2-CC6.1',    title:'Logical access controls — SG 0.0.0.0/0',    framework:'SOC 2',       severity:'high',     days_open:28 },
        { control_id:'CIS-2.1.2',     title:'S3 bucket public access — account level',   framework:'CIS AWS',     severity:'critical', days_open:55 },
        { control_id:'NIST-SI-2',     title:'Flaw remediation — unpatched RDS',           framework:'NIST 800-53', severity:'medium',   days_open:14 },
        { control_id:'PCI-DSS-10.2', title:'Implement audit logs — Lambda missing',      framework:'PCI-DSS 4.0', severity:'medium',   days_open: 6 },
      ];
      const data = (d.failingControls || []).filter(c => c.title).length >= 2 ? d.failingControls : mockControls;
      return { data: data.slice(0, 10), columns: complianceColumns };
    },
    tableTitle: 'Top Failing Controls',
  },
  iam: {
    label: 'IAM', Icon: KeyRound, href: '/iam', color: '#f59e0b', bffView: 'iam',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      const SEV_C = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };

      return {

        /* ═══ LEFT — "What identity types are at risk?"
               Stacked bar: identity type × severity breakdown ═══ */
        left: (() => {
          /* Use real module data if available, else mock */
          const fm = d.findingsByModule || {};
          const hasRealModules = Object.keys(fm).length >= 2;

          /* Identity type risk — mock when API has no breakdown */
          const identityTypes = hasRealModules ? null : [
            { type:'IAM Users',         critical:3,  high:14, medium:8,  low:2  },
            { type:'IAM Roles',         critical:2,  high:28, medium:16, low:4  },
            { type:'Service Accounts',  critical:1,  high:12, medium:9,  low:1  },
            { type:'IAM Policies',      critical:0,  high:8,  medium:14, low:6  },
            { type:'Access Keys',       critical:1,  high:6,  medium:4,  low:3  },
          ];

          /* Real module data when available */
          const moduleRows = hasRealModules
            ? Object.entries(fm).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([name,val]) => ({
                type: name.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase()),
                high: val, critical:0, medium:0, low:0,
              }))
            : identityTypes;

          const maxTotal = Math.max(...moduleRows.map(r => r.critical+r.high+r.medium+r.low), 1);
          const totalFindings = moduleRows.reduce((s,r)=>s+r.critical+r.high+r.medium+r.low,0);

          return (
            <>
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3 className="text-sm font-semibold" style={{ color:'var(--text-primary)' }}>
                    {hasRealModules ? 'Findings by Module' : 'Identity Type Risk Breakdown'}
                  </h3>
                  <p className="text-xs mt-0.5" style={{ color:'var(--text-muted)' }}>
                    <span className="font-semibold" style={{ color:'#f59e0b' }}>{totalFindings.toLocaleString()}</span> total findings · sorted by severity
                  </p>
                </div>
                <div className="flex flex-col gap-0.5 items-end">
                  {[['#ef4444','Critical'],['#f97316','High'],['#f59e0b','Medium']].map(([c,l]) => (
                    <div key={l} className="flex items-center gap-1">
                      <div className="w-2 h-2 rounded-sm" style={{ backgroundColor:c, opacity:0.75 }} />
                      <span style={{ fontSize:'9px', color:'var(--text-muted)' }}>{l}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="space-y-2.5">
                {moduleRows.map((row) => {
                  const total = row.critical+row.high+row.medium+(row.low||0);
                  const critHighPct = Math.round(((row.critical+row.high)/Math.max(total,1))*100);
                  return (
                    <div key={row.type}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-semibold" style={{ color:'var(--text-secondary)' }}>{row.type}</span>
                        <div className="flex items-center gap-2">
                          {row.critical > 0 && (
                            <span style={{ fontSize:'9px', color:'#ef4444', fontWeight:700 }}>▲{row.critical} crit</span>
                          )}
                          <span className="text-xs font-bold tabular-nums" style={{ color:'var(--text-muted)' }}>{total}</span>
                        </div>
                      </div>
                      <div className="flex h-3 rounded overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                        {[['critical','#ef4444'],['high','#f97316'],['medium','#f59e0b'],['low','#10b981']].map(([k,c]) =>
                          (row[k]||0) > 0 && (
                            <div key={k}
                              style={{ width:`${((row[k]||0)/maxTotal)*100}%`, backgroundColor:c, opacity:0.7, minWidth:3 }}
                              title={`${k}: ${row[k]}`} />
                          )
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          );
        })(),

        /* ═══ RIGHT — "What's the MFA + credential hygiene?"
               MFA coverage donut + access key age histogram ═══ */
        right: (() => {
          const identities = d.identities || [];
          const mfaEnabled  = identities.filter(i => i.mfa).length;
          const mfaDisabled = identities.filter(i => !i.mfa).length;
          const hasMfaData  = mfaEnabled + mfaDisabled > 0;

          /* Mock MFA breakdown when no real data */
          const mfaData = hasMfaData
            ? { enabled: mfaEnabled, disabled: mfaDisabled, privilegedDisabled: Math.ceil(mfaDisabled * 0.4) }
            : { enabled: 47, disabled: 7, privilegedDisabled: 4 };

          const mfaTotal = mfaData.enabled + mfaData.disabled;
          const mfaPct = Math.round((mfaData.enabled / Math.max(mfaTotal, 1)) * 100);

          /* Access key age buckets */
          const keyAgeBuckets = [
            { label:'0–30d',   count:28, color:'#22c55e' },
            { label:'31–90d',  count:14, color:'#f59e0b' },
            { label:'91–180d', count: 9, color:'#f97316' },
            { label:'180d+',   count: 5, color:'#ef4444' },
          ];
          const maxKeyCount = Math.max(...keyAgeBuckets.map(b=>b.count), 1);

          return (
            <>
              {/* MFA Coverage */}
              <h3 className="text-sm font-semibold mb-0.5" style={{ color:'var(--text-primary)' }}>MFA Coverage</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>
                Multi-factor authentication status across all identities
              </p>
              <div className="flex items-center gap-6 mb-4">
                {/* Arc gauge */}
                <div className="relative flex-shrink-0" style={{ width:80, height:44 }}>
                  <svg width={80} height={44} className="overflow-visible">
                    <path d="M 8,40 A 32,32 0 0,1 72,40" fill="none" stroke="var(--bg-tertiary)" strokeWidth="7" strokeLinecap="round" />
                    <path d="M 8,40 A 32,32 0 0,1 72,40" fill="none" stroke={mfaPct >= 90 ? '#22c55e' : mfaPct >= 70 ? '#f59e0b' : '#ef4444'}
                      strokeWidth="7" strokeLinecap="round"
                      strokeDasharray={`${Math.PI * 32}`}
                      strokeDashoffset={Math.PI * 32 * (1 - mfaPct / 100)} />
                    <text x="40" y="36" textAnchor="middle" fontSize="14" fontWeight="800"
                      fill={mfaPct >= 90 ? '#22c55e' : mfaPct >= 70 ? '#f59e0b' : '#ef4444'}>{mfaPct}%</text>
                  </svg>
                </div>
                <div className="flex-1 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor:'#22c55e' }} />
                      <span className="text-xs" style={{ color:'var(--text-muted)' }}>MFA Enabled</span>
                    </div>
                    <span className="text-xs font-bold" style={{ color:'#22c55e' }}>{mfaData.enabled}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor:'#ef4444' }} />
                      <span className="text-xs" style={{ color:'var(--text-muted)' }}>MFA Disabled</span>
                    </div>
                    <span className="text-xs font-bold" style={{ color:'#ef4444' }}>{mfaData.disabled}</span>
                  </div>
                  {mfaData.privilegedDisabled > 0 && (
                    <div className="flex items-center justify-between rounded px-2 py-1"
                      style={{ backgroundColor:'#ef444412', border:'1px solid #ef444425' }}>
                      <span className="text-xs font-semibold" style={{ color:'#ef4444' }}>Privileged w/o MFA</span>
                      <span className="text-xs font-bold" style={{ color:'#ef4444' }}>▲{mfaData.privilegedDisabled}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Access Key Age */}
              <div className="pt-3 border-t" style={{ borderColor:'var(--border-primary)' }}>
                <p className="text-xs font-semibold mb-2" style={{ color:'var(--text-muted)' }}>
                  Access Key Age Distribution · <span style={{ color:'#ef4444' }}>180d+ = stale, rotate immediately</span>
                </p>
                <div className="space-y-1.5">
                  {keyAgeBuckets.map((b) => (
                    <div key={b.label} className="flex items-center gap-3">
                      <span className="text-xs font-mono flex-shrink-0" style={{ color:'var(--text-muted)', width:52 }}>{b.label}</span>
                      <div className="flex-1 h-4 rounded overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                        <div className="h-full rounded flex items-center justify-end pr-1.5"
                          style={{ width:`${(b.count/maxKeyCount)*100}%`, backgroundColor:b.color, opacity:0.7, minWidth:20, transition:'width 0.4s ease' }}>
                          <span style={{ fontSize:'9px', fontWeight:700, color:'#fff' }}>{b.count}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                <p className="text-xs mt-2" style={{ color:'var(--text-muted)' }}>
                  <span className="font-semibold" style={{ color:'#ef4444' }}>5 keys</span> are 180+ days old and should be rotated
                </p>
              </div>
            </>
          );
        })(),

        /* ═══ BOTTOM LEFT — "Which IAM rules drive the most failures?"
               Top failing IAM rules ranked by scope × severity ═══ */
        bottomLeft: (() => {
          const iamRules = [
            { rule:'Root account MFA not enabled',       module:'MFA',              accounts:9, severity:'critical', findings:9  },
            { rule:'Access keys not rotated 90d+',       module:'Access Keys',      accounts:7, severity:'high',     findings:14 },
            { rule:'IAM password policy weak',           module:'Password Policy',  accounts:9, severity:'high',     findings:27 },
            { rule:'Unused IAM credentials 90d+',        module:'Access Keys',      accounts:6, severity:'high',     findings:18 },
            { rule:'Overly permissive IAM policy (*:*)', module:'Policies',         accounts:5, severity:'critical', findings:11 },
            { rule:'Cross-account trust not reviewed',   module:'Role Management',  accounts:4, severity:'high',     findings: 8 },
            { rule:'No MFA for console access',          module:'MFA',              accounts:7, severity:'high',     findings:12 },
          ];
          const maxFindings = Math.max(...iamRules.map(r=>r.findings), 1);
          const SEV_C2 = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b' };

          return (
            <>
              <h3 className="text-sm font-semibold mb-0.5" style={{ color:'var(--text-primary)' }}>Top Failing IAM Rules</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>
                Rules with the most active failures · fix these for maximum IAM posture improvement
              </p>
              <div className="space-y-1.5">
                {iamRules.map((r, i) => {
                  const sc = SEV_C2[r.severity] || '#6b7280';
                  const barPct = Math.round((r.findings / maxFindings) * 100);
                  return (
                    <div key={i} className="flex items-center gap-0 rounded-lg overflow-hidden"
                      style={{ backgroundColor:'var(--bg-secondary)', border:'1px solid var(--border-primary)' }}>
                      <div className="w-1 self-stretch flex-shrink-0" style={{ backgroundColor: sc }} />
                      <span className="text-xs font-bold w-6 text-center flex-shrink-0"
                        style={{ color:'var(--text-muted)' }}>#{i+1}</span>
                      <div className="flex-1 min-w-0 py-2.5 pr-2">
                        <p className="text-xs font-semibold truncate" style={{ color:'var(--text-primary)' }}>{r.rule}</p>
                        <p className="text-xs mt-0.5" style={{ color:'var(--text-muted)' }}>
                          <span style={{ color:'var(--text-secondary)' }}>{r.module}</span>
                          {' · '}{r.accounts} accounts
                        </p>
                      </div>
                      {/* Mini bar */}
                      <div className="w-16 h-1.5 rounded-full flex-shrink-0 mx-2" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                        <div className="h-full rounded-full" style={{ width:`${barPct}%`, backgroundColor:sc, opacity:0.7 }} />
                      </div>
                      <span className="text-xs font-bold w-12 text-center flex-shrink-0 py-2.5"
                        style={{ color:sc }}>{r.findings}<span className="font-normal text-xs" style={{ color:'var(--text-muted)' }}> fail</span></span>
                    </div>
                  );
                })}
              </div>
            </>
          );
        })(),

        /* ═══ BOTTOM RIGHT — "Which accounts have worst IAM posture?"
               Ranked by IAM domain score, lowest first ═══ */
        bottomRight: (() => {
          const iamAccounts = MOCK_TENANTS.flatMap(t =>
            t.accounts
              .filter(a => (a.domainScores?.iam || 0) > 0)
              .map(a => ({
                name: a.name, provider: a.provider, tenant: t.name,
                score: a.domainScores.iam,
                criticals: a.domainCritical?.iam || 0,
                mfaIssues: Math.round((1 - a.domainScores.iam / 100) * 8),
                staleKeys: Math.round((1 - a.domainScores.iam / 100) * 5),
              }))
          ).sort((a,b) => a.score - b.score);

          const scoreC = (s) => s >= 75 ? '#22c55e' : s >= 50 ? '#f97316' : '#ef4444';

          return (
            <>
              <h3 className="text-sm font-semibold mb-0.5" style={{ color:'var(--text-primary)' }}>Top At-Risk Accounts</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>
                IAM posture score per account · worst first — click to investigate
              </p>
              <div className="space-y-2">
                {iamAccounts.map((acc, i) => {
                  const sc = scoreC(acc.score);
                  return (
                    <div key={acc.name} className="rounded-lg border overflow-hidden flex"
                      style={{ backgroundColor:'var(--bg-secondary)', borderColor: i < 2 ? `${sc}40` : 'var(--border-primary)' }}>
                      <div className="w-1 flex-shrink-0" style={{ backgroundColor: sc }} />
                      <div className="flex-1 px-3 py-2.5">
                        <div className="flex items-center justify-between mb-1.5">
                          <div className="flex items-center gap-2 min-w-0">
                            <span className="text-xs font-bold flex-shrink-0" style={{ color:'var(--text-muted)' }}>#{i+1}</span>
                            <CloudProviderBadge provider={acc.provider} size="sm" />
                            <span className="text-xs font-semibold truncate" style={{ color:'var(--text-primary)' }}>{acc.name}</span>
                          </div>
                          <span className="text-xl font-black tabular-nums flex-shrink-0" style={{ color: sc }}>{acc.score}</span>
                        </div>
                        {/* Score bar */}
                        <div className="h-1.5 rounded-full mb-1.5" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                          <div className="h-full rounded-full transition-all duration-500"
                            style={{ width:`${acc.score}%`, backgroundColor:sc, opacity:0.7 }} />
                        </div>
                        {/* Stats */}
                        <div className="flex items-center gap-3">
                          <span style={{ fontSize:'10px', color:'var(--text-muted)' }}>
                            {acc.tenant}
                          </span>
                          {acc.mfaIssues > 0 && (
                            <span style={{ fontSize:'10px' }}>
                              <span style={{ color:'#ef4444', fontWeight:700 }}>{acc.mfaIssues}</span>
                              <span style={{ color:'var(--text-muted)' }}> MFA issues</span>
                            </span>
                          )}
                          {acc.staleKeys > 0 && (
                            <span style={{ fontSize:'10px' }}>
                              <span style={{ color:'#f97316', fontWeight:700 }}>{acc.staleKeys}</span>
                              <span style={{ color:'var(--text-muted)' }}> stale keys</span>
                            </span>
                          )}
                          {acc.criticals > 0 && (
                            <span className="ml-auto text-xs font-bold px-1.5 py-0.5 rounded"
                              style={{ backgroundColor:'#ef444418', color:'#ef4444', fontSize:'9px' }}>
                              ▲{acc.criticals} crit
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          );
        })(),

      };
    },
    getTable: (d) => ({ data: (d.identities || []).slice(0, 10), columns: iamColumns }),
    tableTitle: 'Top IAM Risks',
  },
  inventory: {
    label: 'Assets', Icon: Server, href: '/inventory', color: '#06b6d4', bffView: 'inventory',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      return {

        /* ══ LEFT: Asset Inventory by Service — stacked clean/misconfig/exposed ═══ */
        left: (() => {
          const apiSvc = (d.summary?.assets_by_service || []).slice(0, 7);
          const hasReal = apiSvc.length >= 4;
          const services = hasReal
            ? apiSvc.map(s => {
                const total = s.count || 0;
                const misconfig = Math.round(total * 0.05);
                const exposed   = Math.round(total * 0.02);
                return { svc: (s.service || '').replace(/\./g,' ').toUpperCase(), total, clean: total - misconfig - exposed, misconfig, exposed };
              })
            : [
                { svc:'EC2 Instances',     total:4823, clean:4767, misconfig:34, exposed:22 },
                { svc:'IAM Roles',         total:2104, clean:2078, misconfig:18, exposed:8  },
                { svc:'S3 Buckets',        total:892,  clean:851,  misconfig:22, exposed:19 },
                { svc:'Lambda Functions',  total:645,  clean:629,  misconfig:9,  exposed:7  },
                { svc:'RDS Instances',     total:318,  clean:296,  misconfig:15, exposed:7  },
                { svc:'VPCs / Subnets',    total:287,  clean:269,  misconfig:11, exposed:7  },
                { svc:'EKS / Containers',  total:214,  clean:202,  misconfig:7,  exposed:5  },
              ];
          const maxTotal = Math.max(...services.map(s => s.total));
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Asset Inventory by Service</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Resource count · risk exposure per service type</p>
              <div className="flex items-center gap-3 mb-3">
                {[['#06b6d4','Clean'],['#f97316','Misconfigured'],['#ef4444','Publicly Exposed']].map(([c,l]) => (
                  <div key={l} className="flex items-center gap-1">
                    <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor:c }} />
                    <span className="text-xs" style={{ color:'var(--text-muted)' }}>{l}</span>
                  </div>
                ))}
              </div>
              <div className="space-y-2">
                {services.map(({ svc, total, clean, misconfig, exposed }) => (
                  <div key={svc}>
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="text-xs font-medium" style={{ color:'var(--text-secondary)' }}>{svc}</span>
                      <span className="text-xs font-semibold" style={{ color:'var(--text-primary)' }}>{total.toLocaleString()}</span>
                    </div>
                    <div className="flex h-4 rounded overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                      <div style={{ width:`${(clean/maxTotal)*100}%`, backgroundColor:'#06b6d4', opacity:0.8 }} />
                      <div style={{ width:`${(misconfig/maxTotal)*100}%`, backgroundColor:'#f97316' }} />
                      <div style={{ width:`${(exposed/maxTotal)*100}%`, backgroundColor:'#ef4444' }} />
                    </div>
                  </div>
                ))}
              </div>
              <p className="text-xs mt-3 pt-3" style={{ color:'var(--text-muted)', borderTop:'1px solid var(--border-primary)' }}>
                <span style={{ color:'#ef4444', fontWeight:600 }}>19 publicly exposed</span> S3 buckets are the highest-priority exposure — enable Block Public Access across all accounts.
              </p>
            </div>
          );
        })(),

        /* ══ RIGHT: Internet Exposure / External Attack Surface ════════════════ */
        right: (() => {
          const exposureTypes = [
            { label:'Public S3 Buckets',        count:19, critical:7,  high:8,  icon:'🪣', risk:'critical', detail:'Block Public Access disabled' },
            { label:'Open Security Groups',     count:34, critical:12, high:14, icon:'🔓', risk:'critical', detail:'0.0.0.0/0 inbound rules' },
            { label:'EC2 with Public IPs',      count:87, critical:4,  high:22, icon:'🖥',  risk:'high',     detail:'Directly internet-routable' },
            { label:'Publicly Accessible RDS',  count:6,  critical:3,  high:2,  icon:'🗄',  risk:'critical', detail:'Database exposed to internet' },
            { label:'Lambda w/ Public URLs',    count:11, critical:0,  high:5,  icon:'⚡', risk:'high',     detail:'Unauthenticated invocation' },
            { label:'Exposed Load Balancers',   count:18, critical:1,  high:6,  icon:'⚖',  risk:'medium',   detail:'HTTP (non-TLS) listeners' },
            { label:'Public Container Registries', count:4, critical:0, high:3, icon:'📦', risk:'high',     detail:'Image pulls without auth' },
          ];
          const RC = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
          const totalExposed = exposureTypes.reduce((s,e) => s+e.count, 0);
          const criticalExposed = exposureTypes.reduce((s,e) => s+e.critical, 0);
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Internet Exposure · Attack Surface</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Assets reachable from the public internet — external attacker view</p>
              {/* Summary strip */}
              <div className="flex items-center gap-3 mb-4 p-3 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)' }}>
                <div className="text-center px-3" style={{ borderRight:'1px solid var(--border-primary)' }}>
                  <div className="text-2xl font-bold" style={{ color:'#ef4444' }}>{totalExposed}</div>
                  <div className="text-xs" style={{ color:'var(--text-muted)' }}>Exposed assets</div>
                </div>
                <div className="text-center px-3" style={{ borderRight:'1px solid var(--border-primary)' }}>
                  <div className="text-2xl font-bold" style={{ color:'#ef4444' }}>{criticalExposed}</div>
                  <div className="text-xs" style={{ color:'var(--text-muted)' }}>Critical risk</div>
                </div>
                <div className="flex-1 text-xs" style={{ color:'var(--text-secondary)' }}>
                  <span style={{ color:'#f97316', fontWeight:600 }}>RDS + S3 public exposure</span> are your highest-priority attack surface — fix before next threat scan.
                </div>
              </div>
              {/* Exposure type rows */}
              <div className="space-y-2">
                {exposureTypes.map(({ label, count, critical, high, icon, risk, detail }) => (
                  <div key={label} className="flex items-center gap-2 px-2 py-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)', borderLeft:`3px solid ${RC[risk]}` }}>
                    <span className="text-base w-5 text-center">{icon}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold" style={{ color:'var(--text-primary)' }}>{label}</span>
                        <span className="text-sm font-bold" style={{ color: RC[risk] }}>{count}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-xs" style={{ color:'var(--text-muted)' }}>{detail}</span>
                        <div className="flex items-center gap-1 ml-auto">
                          {critical > 0 && <span className="text-xs px-1 rounded" style={{ backgroundColor:'#ef444420', color:'#ef4444' }}>{critical}C</span>}
                          {high > 0    && <span className="text-xs px-1 rounded" style={{ backgroundColor:'#f9731620', color:'#f97316' }}>{high}H</span>}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })(),

        /* ══ BOTTOM LEFT: Top Drifted Resources ════════════════════════════════ */
        bottomLeft: (() => {
          const drifted = [
            { resource:'prod-api-sg-01',   type:'Security Group',  change:'Inbound rule added (0.0.0.0/0:443)', env:'Production', sev:'critical', ago:'2h ago' },
            { resource:'eks-node-role',    type:'IAM Role',        change:'AdministratorAccess policy attached', env:'Production', sev:'critical', ago:'3h ago' },
            { resource:'s3-customer-data', type:'S3 Bucket',       change:'Block Public Access disabled',        env:'Production', sev:'critical', ago:'5h ago' },
            { resource:'rds-main-db',      type:'RDS Instance',    change:'Backup retention changed 7d → 1d',    env:'Production', sev:'high',     ago:'6h ago' },
            { resource:'staging-asg-fleet',type:'EC2 Auto Scaling',change:'Min capacity changed 3 → 0',          env:'Staging',    sev:'high',     ago:'8h ago' },
            { resource:'vpc-flow-logs',    type:'VPC',             change:'Flow logs disabled',                  env:'Dev',        sev:'medium',   ago:'12h ago'},
          ];
          const SC = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
          const EC = { Production:'#ef444420', Staging:'#f59e0b20', Dev:'#3b82f620' };
          const ET = { Production:'#ef4444', Staging:'#f59e0b', Dev:'#3b82f6' };
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Top Drifted Resources</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Configuration changes detected since last scan baseline</p>
              <div className="space-y-2">
                {drifted.map((r, i) => (
                  <div key={i} className="flex items-start gap-2 p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)', borderLeft:`3px solid ${SC[r.sev]}` }}>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-xs font-semibold font-mono" style={{ color:'var(--text-primary)' }}>{r.resource}</span>
                        <span className="text-xs px-1.5 py-0.5 rounded" style={{ backgroundColor: EC[r.env]||'var(--bg-tertiary)', color: ET[r.env]||'var(--text-muted)', fontSize:'10px' }}>{r.env}</span>
                      </div>
                      <span className="text-xs" style={{ color:'var(--text-muted)' }}>{r.type}</span>
                      <p className="text-xs mt-0.5" style={{ color:'var(--text-secondary)' }}>{r.change}</p>
                    </div>
                    <span className="text-xs whitespace-nowrap mt-0.5" style={{ color:'var(--text-muted)' }}>{r.ago}</span>
                  </div>
                ))}
              </div>
              <p className="text-xs mt-3 pt-3" style={{ color:'var(--text-muted)', borderTop:'1px solid var(--border-primary)' }}>
                <span style={{ color:'#f97316', fontWeight:600 }}>47 total drifted</span> · 12 in Production require immediate review
              </p>
            </div>
          );
        })(),

        /* ══ BOTTOM RIGHT: Asset Risk by Cloud-Native Category ═════════════════ */
        bottomRight: (() => {
          const categories = [
            { cat:'Compute',    icon:'🖥',  total:5540, critical:16, high:56, medium:34, score:72, trend:'+3', desc:'EC2, Lambda, ECS tasks' },
            { cat:'Storage',    icon:'🗄',  total:1210, critical:22, high:31, medium:19, score:61, trend:'-2', desc:'S3, EBS, Azure Blob, GCS' },
            { cat:'Identity',   icon:'🔑', total:3890, critical:11, high:42, medium:28, score:62, trend:'+1', desc:'IAM users, roles, policies' },
            { cat:'Networking', icon:'🌐', total:890,  critical:14, high:37, medium:22, score:65, trend:'-1', desc:'VPCs, SGs, load balancers' },
            { cat:'Data',       icon:'💾', total:430,  critical:8,  high:18, medium:31, score:74, trend:'0',  desc:'RDS, DynamoDB, Cosmos DB' },
            { cat:'Containers', icon:'📦', total:287,  critical:5,  high:14, medium:18, score:79, trend:'+2', desc:'EKS, GKE, AKS, ECR images' },
          ];
          const SC = (s) => s >= 80 ? '#10b981' : s >= 65 ? '#f59e0b' : '#ef4444';
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Asset Risk by Cloud-Native Category</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Security posture per workload category — like Wiz technology graph</p>
              <div className="space-y-2">
                {categories.map(({ cat, icon, total, critical, high, medium, score, trend, desc }) => {
                  const trendColor = trend.startsWith('+') ? '#10b981' : trend === '0' ? 'var(--text-muted)' : '#ef4444';
                  const maxIssues = 110; // normalise bars
                  const totalIssues = critical + high + medium;
                  return (
                    <div key={cat} className="p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)' }}>
                      <div className="flex items-center gap-2 mb-1.5">
                        <span className="text-base w-5 text-center">{icon}</span>
                        <div className="flex-1">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-semibold" style={{ color:'var(--text-primary)' }}>{cat}</span>
                            <div className="flex items-center gap-2">
                              <span className="text-xs" style={{ color:'var(--text-muted)' }}>{total.toLocaleString()} res</span>
                              <div className="flex items-center gap-0.5">
                                <div className="w-8 h-4 rounded" style={{ backgroundColor:'var(--bg-tertiary)', position:'relative', overflow:'hidden' }}>
                                  <div style={{ position:'absolute', inset:0, width:`${score}%`, backgroundColor: SC(score), opacity:0.8 }} />
                                  <span style={{ position:'absolute', inset:0, display:'flex', alignItems:'center', justifyContent:'center', fontSize:'9px', fontWeight:700, color:'white' }}>{score}</span>
                                </div>
                                <span className="text-xs font-semibold" style={{ color: trendColor, fontSize:'10px' }}>{trend}</span>
                              </div>
                            </div>
                          </div>
                          <span className="text-xs" style={{ color:'var(--text-muted)' }}>{desc}</span>
                        </div>
                      </div>
                      {/* Stacked issue bar */}
                      <div className="flex h-2 rounded overflow-hidden gap-px" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                        <div style={{ width:`${(critical/maxIssues)*100}%`, backgroundColor:'#ef4444', minWidth: critical?'2px':0 }} title={`${critical} critical`} />
                        <div style={{ width:`${(high/maxIssues)*100}%`,     backgroundColor:'#f97316', minWidth: high?'2px':0     }} title={`${high} high`} />
                        <div style={{ width:`${(medium/maxIssues)*100}%`,   backgroundColor:'#f59e0b', minWidth: medium?'2px':0   }} title={`${medium} medium`} />
                      </div>
                      <div className="flex items-center gap-3 mt-1">
                        {critical>0 && <span className="text-xs" style={{ color:'#ef4444' }}>{critical} critical</span>}
                        {high>0     && <span className="text-xs" style={{ color:'#f97316' }}>{high} high</span>}
                        {medium>0   && <span className="text-xs" style={{ color:'#f59e0b' }}>{medium} medium</span>}
                        <span className="text-xs ml-auto" style={{ color:'var(--text-muted)' }}>{totalIssues} total issues</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })(),

      };
    },
    getTable: (d) => {
      const mockAssets = [
        { resource_name:'prod-api-ec2-01',    resource_type:'ec2.instance',         provider:'aws',   region:'us-east-1',   findings:3, risk_score:82 },
        { resource_name:'s3-customer-data',   resource_type:'s3.bucket',            provider:'aws',   region:'us-east-1',   findings:2, risk_score:76 },
        { resource_name:'eks-node-role',      resource_type:'iam.role',             provider:'aws',   region:'global',      findings:2, risk_score:74 },
        { resource_name:'rds-main-db',        resource_type:'rds.instance',         provider:'aws',   region:'us-east-1',   findings:2, risk_score:68 },
        { resource_name:'prod-api-sg-01',     resource_type:'ec2.security-group',   provider:'aws',   region:'us-east-1',   findings:1, risk_score:65 },
        { resource_name:'az-storage-corp',    resource_type:'storage.account',      provider:'azure', region:'eastus',      findings:1, risk_score:58 },
        { resource_name:'lambda-data-proc',   resource_type:'lambda.function',      provider:'aws',   region:'us-west-2',   findings:1, risk_score:55 },
        { resource_name:'gcp-gke-cluster',    resource_type:'container.cluster',    provider:'gcp',   region:'us-central1', findings:1, risk_score:52 },
        { resource_name:'vpc-flow-logs',      resource_type:'ec2.vpc',              provider:'aws',   region:'us-east-1',   findings:1, risk_score:48 },
        { resource_name:'cloudwatch-alarms',  resource_type:'cloudwatch.alarm',     provider:'aws',   region:'us-east-1',   findings:0, risk_score:30 },
      ];
      const apiAssets = (d.assets || []).filter(a => a.resource_name || a.name);
      const data = apiAssets.length >= 3 ? apiAssets.slice(0,10) : mockAssets;
      return { data, columns: inventoryColumns };
    },
    tableTitle: 'Top Resources by Risk',
  },
  datasec: {
    label: 'Data', Icon: Lock, href: '/datasec', color: '#ec4899', bffView: 'datasec',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      return {

        /* ══ LEFT: Data Classification Breakdown ════════════════════════════════ */
        left: (() => {
          const apiClass = (d.classifications || []).filter(c => c.count > 0);
          const hasReal  = apiClass.length >= 3;
          const classes  = hasReal ? apiClass.map(c => ({ ...c, name: c.name || c.type })) : [
            { name:'PII',           stores:142, critical:7,  exposed:8,  color:'#ef4444', icon:'👤', desc:'Names, emails, SSNs, addresses' },
            { name:'Financial',     stores:87,  critical:5,  exposed:3,  color:'#f97316', icon:'💳', desc:'Card numbers, bank accounts' },
            { name:'Health / PHI',  stores:34,  critical:4,  exposed:2,  color:'#ec4899', icon:'🏥', desc:'Medical records, diagnoses' },
            { name:'Credentials',   stores:28,  critical:8,  exposed:5,  color:'#8b5cf6', icon:'🔑', desc:'API keys, passwords, tokens' },
            { name:'Confidential',  stores:198, critical:2,  exposed:1,  color:'#f59e0b', icon:'🔒', desc:'Internal business data' },
            { name:'Public',        stores:358, critical:0,  exposed:0,  color:'#10b981', icon:'🌐', desc:'Non-sensitive, publicly shareable' },
          ];
          const maxStores = Math.max(...classes.map(c => c.stores || 0));
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Data Classification</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Sensitive data detected across all data stores</p>
              <div className="space-y-2.5">
                {classes.map(({ name, stores, critical, exposed, color, icon, desc }) => (
                  <div key={name}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-1.5">
                        <span className="text-sm">{icon}</span>
                        <span className="text-xs font-semibold" style={{ color:'var(--text-primary)' }}>{name}</span>
                        {critical > 0 && <span className="text-xs px-1.5 py-0.5 rounded-full font-semibold" style={{ backgroundColor:'#ef444420', color:'#ef4444' }}>{critical} critical</span>}
                      </div>
                      <div className="flex items-center gap-2">
                        {exposed > 0 && <span className="text-xs" style={{ color:'#ef4444' }}>⚠ {exposed} exposed</span>}
                        <span className="text-xs font-semibold" style={{ color:'var(--text-secondary)' }}>{stores} stores</span>
                      </div>
                    </div>
                    <div className="w-full h-3 rounded-full overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                      <div className="h-full rounded-full" style={{ width:`${(stores/maxStores)*100}%`, backgroundColor: color, opacity:0.85 }} />
                    </div>
                    <p className="text-xs mt-0.5" style={{ color:'var(--text-muted)' }}>{desc}</p>
                  </div>
                ))}
              </div>
              <p className="text-xs mt-3 pt-3" style={{ color:'var(--text-muted)', borderTop:'1px solid var(--border-primary)' }}>
                <span style={{ color:'#8b5cf6', fontWeight:600 }}>Credential exposure</span> in 5 stores is the highest-severity risk — rotate keys and revoke stale tokens immediately.
              </p>
            </div>
          );
        })(),

        /* ══ RIGHT: Exposure × Encryption Risk ══════════════════════════════════ */
        right: (() => {
          const totalStores  = 847;
          const exposed      = 12;
          const unencrypted  = 34;
          const piiExposed   = 8;
          const noBackup     = 23;
          const staleAccess  = 41;
          const exposedPct   = Math.round((exposed / totalStores) * 100);
          const encryptedPct = Math.round(((totalStores - unencrypted) / totalStores) * 100);
          const metrics = [
            { label:'Publicly Exposed',  value:exposed,     pct:exposedPct,   color:'#ef4444', detail:`${piiExposed} contain PII` },
            { label:'Unencrypted',       value:unencrypted, pct:100-encryptedPct, color:'#f97316', detail:'At-rest encryption disabled' },
            { label:'No Backup Policy',  value:noBackup,    pct:Math.round((noBackup/totalStores)*100), color:'#f59e0b', detail:'Recovery point undefined' },
            { label:'Stale Access',      value:staleAccess, pct:Math.round((staleAccess/totalStores)*100), color:'#8b5cf6', detail:'Access not reviewed 90d+' },
          ];
          const storesByProvider = [
            { provider:'AWS',   stores:512, exposed:7,  unencrypted:21, color:'#f97316' },
            { provider:'Azure', stores:198, exposed:3,  unencrypted:9,  color:'#3b82f6' },
            { provider:'GCP',   stores:137, exposed:2,  unencrypted:4,  color:'#10b981' },
          ];
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Data Risk · Exposure & Encryption</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Critical data security axes across {totalStores.toLocaleString()} monitored stores</p>
              {/* Risk metric rows */}
              <div className="space-y-3 mb-4">
                {metrics.map(({ label, value, pct, color, detail }) => (
                  <div key={label}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium" style={{ color:'var(--text-secondary)' }}>{label}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-xs" style={{ color:'var(--text-muted)' }}>{detail}</span>
                        <span className="text-sm font-bold" style={{ color }}>{value}</span>
                      </div>
                    </div>
                    <div className="w-full h-2.5 rounded-full overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                      <div className="h-full rounded-full" style={{ width:`${Math.max(pct, 1)}%`, backgroundColor: color }} />
                    </div>
                    <div className="text-xs mt-0.5" style={{ color:'var(--text-muted)' }}>{pct}% of total data stores</div>
                  </div>
                ))}
              </div>
              {/* By provider */}
              <p className="text-xs font-semibold mb-2" style={{ color:'var(--text-secondary)' }}>Risk by Cloud Provider</p>
              <div className="space-y-1.5">
                {storesByProvider.map(({ provider, stores, exposed: exp, unencrypted: unenc, color }) => (
                  <div key={provider} className="flex items-center gap-2 px-2 py-1.5 rounded" style={{ backgroundColor:'var(--bg-secondary)' }}>
                    <span className="text-xs font-semibold w-10" style={{ color }}>{provider}</span>
                    <span className="text-xs w-16" style={{ color:'var(--text-muted)' }}>{stores} stores</span>
                    <div className="flex-1 flex items-center gap-2">
                      <span className="text-xs" style={{ color:'#ef4444' }}>{exp} exposed</span>
                      <span className="text-xs" style={{ color:'#f97316' }}>{unenc} unencrypted</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })(),

        /* ══ BOTTOM LEFT: Top At-Risk Data Stores (Crown Jewels) ════════════════ */
        bottomLeft: (() => {
          const crownJewels = [
            { name:'s3-customer-pii',     type:'S3 Bucket',    classification:'PII',        exposed:true,  encrypted:false, account:'AWS Production', risk:97 },
            { name:'rds-financial-db',    type:'RDS Instance',  classification:'Financial',   exposed:true,  encrypted:false, account:'AWS Production', risk:94 },
            { name:'az-health-records',   type:'Azure Blob',    classification:'PHI',         exposed:false, encrypted:false, account:'Azure Corp',      risk:88 },
            { name:'s3-api-keys-backup',  type:'S3 Bucket',    classification:'Credentials', exposed:true,  encrypted:true,  account:'AWS Staging',     risk:85 },
            { name:'dynamo-user-profile', type:'DynamoDB',      classification:'PII',         exposed:false, encrypted:false, account:'AWS Production', risk:79 },
            { name:'gcs-analytics-pii',   type:'GCS Bucket',    classification:'PII',         exposed:false, encrypted:true,  account:'GCP Primary',     risk:74 },
          ];
          const CC = { PII:'#ef4444', Financial:'#f97316', PHI:'#ec4899', Credentials:'#8b5cf6', Confidential:'#f59e0b' };
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Top At-Risk Data Stores</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Crown jewels — sensitive stores with highest exposure risk</p>
              <div className="space-y-2">
                {crownJewels.map((s, i) => {
                  const riskColor = s.risk >= 90 ? '#ef4444' : s.risk >= 80 ? '#f97316' : '#f59e0b';
                  return (
                    <div key={i} className="p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)', borderLeft:`3px solid ${riskColor}` }}>
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="text-xs font-semibold font-mono" style={{ color:'var(--text-primary)' }}>{s.name}</span>
                            <span className="text-xs px-1.5 py-0.5 rounded" style={{ backgroundColor:`${CC[s.classification]||'#6b7280'}20`, color: CC[s.classification]||'#6b7280', fontSize:'10px' }}>{s.classification}</span>
                          </div>
                          <div className="flex items-center gap-2 mt-1 flex-wrap">
                            <span className="text-xs" style={{ color:'var(--text-muted)' }}>{s.type}</span>
                            <span className="text-xs px-1 rounded" style={{ backgroundColor: s.exposed ? '#ef444420':'#10b98120', color: s.exposed?'#ef4444':'#10b981' }}>{s.exposed ? '🌐 Public':'🔒 Private'}</span>
                            <span className="text-xs px-1 rounded" style={{ backgroundColor: s.encrypted ? '#10b98120':'#ef444420', color: s.encrypted?'#10b981':'#ef4444' }}>{s.encrypted ? '🔐 Encrypted':'⚠ Unencrypted'}</span>
                          </div>
                          <span className="text-xs" style={{ color:'var(--text-muted)' }}>{s.account}</span>
                        </div>
                        <div className="text-right">
                          <div className="text-sm font-bold" style={{ color: riskColor }}>{s.risk}</div>
                          <div className="text-xs" style={{ color:'var(--text-muted)' }}>risk</div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
              <p className="text-xs mt-3 pt-3" style={{ color:'var(--text-muted)', borderTop:'1px solid var(--border-primary)' }}>
                <span style={{ color:'#ef4444', fontWeight:600 }}>2 stores</span> are publicly exposed AND contain PII — immediate remediation required.
              </p>
            </div>
          );
        })(),

        /* ══ BOTTOM RIGHT: Data Store Type Risk Breakdown ═══════════════════════ */
        bottomRight: (() => {
          const storeTypes = [
            { type:'S3 Buckets',       icon:'🪣', count:412, critical:12, high:28, encrypted:88, exposed:11, score:58 },
            { type:'RDS Databases',    icon:'🗄',  count:187, critical:6,  high:14, encrypted:91, exposed:4,  score:67 },
            { type:'DynamoDB',         icon:'⚡', count:94,  critical:3,  high:8,  encrypted:95, exposed:1,  score:74 },
            { type:'Azure Blob/ADLS',  icon:'☁',  count:86,  critical:4,  high:11, encrypted:82, exposed:3,  score:63 },
            { type:'GCS Buckets',      icon:'🌩',  count:62,  critical:2,  high:6,  encrypted:94, exposed:2,  score:72 },
            { type:'BigQuery',         icon:'📊', count:6,   critical:0,  high:2,  encrypted:100, exposed:0, score:83 },
          ];
          const SC = (s) => s >= 80 ? '#10b981' : s >= 65 ? '#f59e0b' : '#ef4444';
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Data Store Type Risk</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Security posture per storage technology</p>
              <div className="space-y-2">
                {storeTypes.map(({ type, icon, count, critical, high, encrypted, exposed: exp, score }) => (
                  <div key={type} className="p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)' }}>
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="text-base w-5 text-center">{icon}</span>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold" style={{ color:'var(--text-primary)' }}>{type}</span>
                          <div className="flex items-center gap-1.5">
                            <span className="text-xs" style={{ color:'var(--text-muted)' }}>{count} stores</span>
                            <div className="w-8 h-4 rounded text-center relative overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                              <div style={{ position:'absolute', inset:0, width:`${score}%`, backgroundColor: SC(score), opacity:0.85 }} />
                              <span style={{ position:'relative', fontSize:'9px', fontWeight:700, color:'white', lineHeight:'16px' }}>{score}</span>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3 mt-0.5">
                          {critical > 0 && <span className="text-xs" style={{ color:'#ef4444' }}>{critical}C</span>}
                          {high > 0     && <span className="text-xs" style={{ color:'#f97316' }}>{high}H</span>}
                          <span className="text-xs" style={{ color: encrypted>=95?'#10b981':encrypted>=85?'#f59e0b':'#ef4444' }}>🔐 {encrypted}% enc</span>
                          {exp > 0 && <span className="text-xs" style={{ color:'#ef4444' }}>🌐 {exp} exposed</span>}
                        </div>
                      </div>
                    </div>
                    {/* Issue bar */}
                    <div className="flex h-1.5 rounded overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                      <div style={{ width:`${(critical/(critical+high+1))*100}%`, backgroundColor:'#ef4444' }} />
                      <div style={{ width:`${(high/(critical+high+1))*100}%`,     backgroundColor:'#f97316' }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })(),

      };
    },
    getTable: (d) => {
      const mockStores = [
        { name:'s3-customer-pii',     type:'S3 Bucket',    classification:'PII',        provider:'aws',   region:'us-east-1',   risk_score:97, encrypted:false },
        { name:'rds-financial-db',    type:'RDS Instance',  classification:'Financial',   provider:'aws',   region:'us-east-1',   risk_score:94, encrypted:false },
        { name:'az-health-records',   type:'Azure Blob',    classification:'PHI',         provider:'azure', region:'eastus',      risk_score:88, encrypted:false },
        { name:'s3-api-keys-backup',  type:'S3 Bucket',    classification:'Credentials', provider:'aws',   region:'us-west-2',   risk_score:85, encrypted:true  },
        { name:'dynamo-user-profile', type:'DynamoDB',      classification:'PII',         provider:'aws',   region:'us-east-1',   risk_score:79, encrypted:false },
        { name:'gcs-analytics-pii',   type:'GCS Bucket',    classification:'PII',         provider:'gcp',   region:'us-central1', risk_score:74, encrypted:true  },
        { name:'cosmos-orders',       type:'Cosmos DB',     classification:'Financial',   provider:'azure', region:'westus',      risk_score:68, encrypted:true  },
        { name:'s3-logs-archive',     type:'S3 Bucket',    classification:'Confidential',provider:'aws',   region:'us-east-1',   risk_score:45, encrypted:true  },
        { name:'rds-analytics',       type:'RDS Instance',  classification:'Confidential',provider:'aws',   region:'eu-west-1',   risk_score:38, encrypted:true  },
        { name:'gcs-public-assets',   type:'GCS Bucket',    classification:'Public',      provider:'gcp',   region:'us-central1', risk_score:12, encrypted:true  },
      ];
      const apiData = (d.catalog || []).filter(s => s.name);
      const data = apiData.length >= 3 ? apiData.slice(0,10) : mockStores;
      return { data, columns: datasecColumns };
    },
    tableTitle: 'Top Data Stores',
  },
  network: {
    label: 'Network', Icon: Network, href: '/network-security', color: '#3b82f6', bffView: 'network-security',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      return {

        /* ══ LEFT: Internet-Exposed Ports / Protocols ════════════════════════════ */
        left: (() => {
          const ports = [
            { port:'22  SSH',       count:18, risk:'critical', proto:'TCP', detail:'Root access path — disable or restrict to bastion only' },
            { port:'3389 RDP',      count:7,  risk:'critical', proto:'TCP', detail:'Windows remote desktop exposed to internet' },
            { port:'23  Telnet',    count:3,  risk:'critical', proto:'TCP', detail:'Unencrypted protocol — immediate closure required' },
            { port:'3306 MySQL',    count:5,  risk:'critical', proto:'TCP', detail:'Database directly exposed — no VPC isolation' },
            { port:'5432 Postgres', count:4,  risk:'high',     proto:'TCP', detail:'Database port open to 0.0.0.0/0' },
            { port:'80  HTTP',      count:31, risk:'high',     proto:'TCP', detail:'Unencrypted web traffic — redirect to HTTPS' },
            { port:'443 HTTPS',     count:62, risk:'medium',   proto:'TCP', detail:'Encrypted — review certificate & WAF coverage' },
            { port:'8080 Alt-HTTP', count:9,  risk:'medium',   proto:'TCP', detail:'Development ports exposed in production' },
          ];
          const RC = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
          const maxCount = Math.max(...ports.map(p => p.count));
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Internet-Exposed Ports · 0.0.0.0/0</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Ports open to the public internet via security group rules</p>
              <div className="space-y-2">
                {ports.map(({ port, count, risk, proto, detail }) => (
                  <div key={port}>
                    <div className="flex items-center justify-between mb-0.5">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-semibold w-24" style={{ color: RC[risk] }}>{port}</span>
                        <span className="text-xs px-1 rounded" style={{ backgroundColor:'var(--bg-tertiary)', color:'var(--text-muted)' }}>{proto}</span>
                      </div>
                      <span className="text-sm font-bold" style={{ color: RC[risk] }}>{count}</span>
                    </div>
                    <div className="w-full h-3 rounded overflow-hidden mb-0.5" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                      <div style={{ width:`${(count/maxCount)*100}%`, height:'100%', backgroundColor: RC[risk], opacity:0.85 }} />
                    </div>
                    <p className="text-xs" style={{ color:'var(--text-muted)' }}>{detail}</p>
                  </div>
                ))}
              </div>
              <p className="text-xs mt-3 pt-3" style={{ color:'var(--text-muted)', borderTop:'1px solid var(--border-primary)' }}>
                <span style={{ color:'#ef4444', fontWeight:600 }}>SSH + RDP + Telnet</span> open to 0.0.0.0/0 — 28 critical exposures requiring immediate SG rule updates.
              </p>
            </div>
          );
        })(),

        /* ══ RIGHT: Security Group Risk by Account ══════════════════════════════ */
        right: (() => {
          const sgAccounts = MOCK_TENANTS.flatMap(t =>
            t.accounts.filter(a => a.resources > 0).map((a, idx) => {
              const base    = Math.round(a.resources / 100);
              const unrest  = Math.max(0, Math.round(base * (1.2 - (a.score||60)/100) + idx));
              const unused  = Math.round(base * 0.4 + idx * 2);
              const total   = Math.round(base * 3 + 10);
              return { name:a.name, provider:a.provider, total, unrest, unused, score:a.score||0 };
            })
          ).sort((a,b) => b.unrest - a.unrest);
          const totalUnrest = sgAccounts.reduce((s,a)=>s+a.unrest,0);
          const totalUnused = sgAccounts.reduce((s,a)=>s+a.unused,0);
          const totalSGs    = sgAccounts.reduce((s,a)=>s+a.total,0);
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Security Group Risk by Account</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Overly permissive and unused SG rules across all accounts</p>
              {/* Summary */}
              <div className="flex gap-3 mb-4">
                {[
                  { label:'Total SGs',         val:totalSGs,    color:'var(--text-primary)' },
                  { label:'Unrestricted rules', val:totalUnrest, color:'#ef4444' },
                  { label:'Unused / orphaned',  val:totalUnused, color:'#f59e0b' },
                ].map(({ label, val, color }) => (
                  <div key={label} className="flex-1 text-center p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)' }}>
                    <div className="text-lg font-bold" style={{ color }}>{val}</div>
                    <div className="text-xs" style={{ color:'var(--text-muted)' }}>{label}</div>
                  </div>
                ))}
              </div>
              {/* Per-account rows */}
              <div className="space-y-2">
                {sgAccounts.map((a, i) => (
                  <div key={i} className="flex items-center gap-2 px-2 py-1.5 rounded" style={{ backgroundColor:'var(--bg-secondary)' }}>
                    <CloudProviderBadge provider={a.provider} size="sm" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="text-xs font-medium truncate" style={{ color:'var(--text-primary)', maxWidth:'120px' }}>{a.name}</span>
                        <span className="text-xs" style={{ color:'var(--text-muted)' }}>{a.total} SGs</span>
                      </div>
                      <div className="flex items-center gap-3">
                        {a.unrest > 0 && <span className="text-xs" style={{ color:'#ef4444' }}>⚠ {a.unrest} unrestricted</span>}
                        {a.unused > 0 && <span className="text-xs" style={{ color:'#f59e0b' }}>⊘ {a.unused} unused</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })(),

        /* ══ BOTTOM LEFT: Top Risky Network Findings ════════════════════════════ */
        bottomLeft: (() => {
          const findings = [
            { title:'Security group allows SSH from internet',    module:'Security Groups', resource:'prod-api-sg-01',    sev:'critical', account:'AWS Production', effort:'Low — 1 rule change' },
            { title:'RDP port 3389 open to 0.0.0.0/0',           module:'Security Groups', resource:'win-bastion-sg',     sev:'critical', account:'AWS Production', effort:'Low — restrict CIDR' },
            { title:'Unrestricted outbound to all ports',         module:'Security Groups', resource:'eks-worker-sg',      sev:'high',     account:'AWS Production', effort:'Medium — review app ports' },
            { title:'MySQL port exposed without VPC restriction',  module:'Security Groups', resource:'rds-sg-main',        sev:'critical', account:'AWS Staging',    effort:'Low — add VPC CIDR' },
            { title:'Load balancer missing WAF association',       module:'WAF',             resource:'prod-alb-01',        sev:'high',     account:'AWS Production', effort:'Medium — attach WAF' },
            { title:'VPC Flow Logs disabled',                      module:'VPC',             resource:'vpc-prod-main',      sev:'high',     account:'AWS Production', effort:'Low — enable logs' },
            { title:'Network ACL allows all inbound traffic',      module:'Network ACLs',    resource:'subnet-public-1a',   sev:'medium',   account:'Azure Corp',     effort:'Medium — tighten ACL' },
          ];
          const SC = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
          const EC = { 'Low — 1 rule change':'#10b981', 'Low — restrict CIDR':'#10b981', 'Low — add VPC CIDR':'#10b981', 'Low — enable logs':'#10b981' };
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Top Risky Network Findings</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Highest-priority network issues sorted by severity + remediation effort</p>
              <div className="space-y-2">
                {findings.map((f, i) => (
                  <div key={i} className="p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)', borderLeft:`3px solid ${SC[f.sev]}` }}>
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-semibold" style={{ color:'var(--text-primary)' }}>{f.title}</p>
                        <div className="flex items-center gap-2 mt-1 flex-wrap">
                          <span className="text-xs px-1.5 rounded" style={{ backgroundColor:`${SC[f.sev]}20`, color:SC[f.sev] }}>{f.sev}</span>
                          <span className="text-xs" style={{ color:'var(--text-muted)' }}>{f.module}</span>
                          <span className="text-xs font-mono" style={{ color:'var(--text-muted)' }}>{f.resource}</span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-xs" style={{ color:'var(--text-muted)' }}>{f.account}</span>
                          <span className="text-xs ml-auto" style={{ color: EC[f.effort] || '#f59e0b' }}>⚡ {f.effort}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })(),

        /* ══ BOTTOM RIGHT: Network Segmentation Health ══════════════════════════ */
        bottomRight: (() => {
          const segmentation = [
            { account:'AWS Production',  provider:'aws',   vpcs:4, publicSubnets:6,  privateSubnets:18, igws:2, natGws:3, peeringRisks:1, score:72 },
            { account:'AWS Staging',     provider:'aws',   vpcs:2, publicSubnets:4,  privateSubnets:8,  igws:1, natGws:1, peeringRisks:0, score:81 },
            { account:'Azure Corp',      provider:'azure', vpcs:3, publicSubnets:8,  privateSubnets:12, igws:3, natGws:2, peeringRisks:2, score:65 },
            { account:'Azure Enterprise',provider:'azure', vpcs:2, publicSubnets:5,  privateSubnets:14, igws:2, natGws:2, peeringRisks:1, score:70 },
            { account:'GCP Primary',     provider:'gcp',   vpcs:2, publicSubnets:3,  privateSubnets:11, igws:1, natGws:1, peeringRisks:0, score:84 },
            { account:'AWS Compliance',  provider:'aws',   vpcs:3, publicSubnets:4,  privateSubnets:16, igws:1, natGws:2, peeringRisks:0, score:88 },
          ];
          const SC = (s) => s >= 80 ? '#10b981' : s >= 70 ? '#f59e0b' : '#ef4444';
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Network Segmentation Health</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>VPC segmentation, public subnet exposure, and peering risk per account</p>
              <div className="space-y-2">
                {segmentation.map((s, i) => {
                  const pubRatio = Math.round((s.publicSubnets / (s.publicSubnets + s.privateSubnets)) * 100);
                  return (
                    <div key={i} className="p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)' }}>
                      <div className="flex items-center gap-2 mb-1.5">
                        <CloudProviderBadge provider={s.provider} size="sm" />
                        <span className="text-xs font-medium flex-1" style={{ color:'var(--text-primary)' }}>{s.account}</span>
                        <div className="w-8 h-4 rounded text-center relative overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                          <div style={{ position:'absolute', inset:0, width:`${s.score}%`, backgroundColor: SC(s.score), opacity:0.85 }} />
                          <span style={{ position:'relative', fontSize:'9px', fontWeight:700, color:'white', lineHeight:'16px' }}>{s.score}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className="text-xs" style={{ color:'var(--text-muted)' }}>{s.vpcs} VPCs</span>
                        <span className="text-xs" style={{ color: pubRatio > 35 ? '#f97316':'var(--text-muted)' }}>🌐 {s.publicSubnets} public ({pubRatio}%)</span>
                        <span className="text-xs" style={{ color:'#10b981' }}>🔒 {s.privateSubnets} private</span>
                        {s.peeringRisks > 0 && <span className="text-xs" style={{ color:'#ef4444' }}>⚡ {s.peeringRisks} risky peering</span>}
                      </div>
                      {/* Public ratio bar */}
                      <div className="flex h-1.5 rounded overflow-hidden mt-1.5" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                        <div style={{ width:`${pubRatio}%`, backgroundColor: pubRatio>35?'#f97316':'#f59e0b' }} title="Public subnets" />
                        <div style={{ width:`${100-pubRatio}%`, backgroundColor:'#10b981', opacity:0.5 }} title="Private subnets" />
                      </div>
                    </div>
                  );
                })}
              </div>
              <p className="text-xs mt-3 pt-3" style={{ color:'var(--text-muted)', borderTop:'1px solid var(--border-primary)' }}>
                <span style={{ color:'#f97316', fontWeight:600 }}>Azure Corp</span> has the highest public-to-private ratio (40%) — review subnet architecture for unnecessary exposure.
              </p>
            </div>
          );
        })(),

      };
    },
    getTable: (d) => {
      const mockFindings = [
        { severity:'CRITICAL', title:'Security group allows SSH from internet (0.0.0.0/0)', module:'Security Groups', resource_type:'aws.ec2.security-group', account_id:'AWS Production' },
        { severity:'CRITICAL', title:'RDP port 3389 exposed to public internet',             module:'Security Groups', resource_type:'aws.ec2.security-group', account_id:'AWS Production' },
        { severity:'CRITICAL', title:'MySQL database port open to 0.0.0.0/0',               module:'Security Groups', resource_type:'aws.rds.instance',        account_id:'AWS Staging' },
        { severity:'HIGH',     title:'Unrestricted outbound traffic (all ports)',            module:'Security Groups', resource_type:'aws.ec2.security-group', account_id:'AWS Production' },
        { severity:'HIGH',     title:'Load balancer missing WAF protection',                 module:'WAF',             resource_type:'aws.elasticloadbalancing', account_id:'AWS Production' },
        { severity:'HIGH',     title:'VPC Flow Logs disabled — traffic not audited',         module:'VPC',             resource_type:'aws.ec2.vpc',              account_id:'AWS Production' },
        { severity:'HIGH',     title:'Internet gateway attached to sensitive VPC',           module:'VPC',             resource_type:'aws.ec2.internet-gateway', account_id:'Azure Corp' },
        { severity:'MEDIUM',   title:'Network ACL allows all inbound traffic',               module:'Network ACLs',    resource_type:'aws.ec2.network-acl',      account_id:'Azure Corp' },
        { severity:'MEDIUM',   title:'Unused elastic IP addresses — potential hijack risk',  module:'Elastic IPs',     resource_type:'aws.ec2.elastic-ip',       account_id:'AWS Staging' },
        { severity:'LOW',      title:'Security group with no associated resources',          module:'Security Groups', resource_type:'aws.ec2.security-group', account_id:'AWS Compliance' },
      ];
      const apiFindings = (d.data?.findings || d.findings || []).filter(f => f.title);
      const data = apiFindings.length >= 3 ? apiFindings.slice(0,10) : mockFindings;
      return { data, columns: networkColumns };
    },
    tableTitle: 'Top Network Findings',
  },
  risk: {
    label: 'Risk', Icon: Activity, href: '/risk', color: '#f97316', bffView: 'risk',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      return {

        /* ══ LEFT: Risk by Category — score + financial exposure + scenario count ═ */
        left: (() => {
          const apiCats = (d.riskCategories || []).filter(c => (c.score || c.count) > 0);
          const hasReal = apiCats.length >= 3;
          const categories = hasReal ? apiCats.map(c => ({
            name: c.category || c.name,
            score: c.score || 50,
            exposure: c.estimated_loss || 0,
            scenarios: c.count || 1,
            critical: c.critical_count || 0,
          })) : [
            { name:'Data Exposure',     score:82, exposure:1200000, scenarios:3, critical:2 },
            { name:'Identity & Access', score:74, exposure:850000,  scenarios:4, critical:2 },
            { name:'Network Security',  score:61, exposure:620000,  scenarios:3, critical:1 },
            { name:'Compliance',        score:55, exposure:480000,  scenarios:2, critical:0 },
            { name:'Infrastructure',    score:48, exposure:350000,  scenarios:2, critical:0 },
            { name:'Supply Chain',      score:34, exposure:180000,  scenarios:1, critical:0 },
          ];
          const fmtM = (v) => v >= 1000000 ? `$${(v/1000000).toFixed(1)}M` : `$${(v/1000).toFixed(0)}K`;
          const scoreColor = (s) => s >= 70 ? '#ef4444' : s >= 50 ? '#f97316' : '#f59e0b';
          const maxScore = 100;
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Risk by Category</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Risk score, estimated financial exposure, and scenario count per category</p>
              <div className="space-y-3">
                {categories.map(({ name, score, exposure, scenarios, critical }) => (
                  <div key={name}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs font-semibold" style={{ color:'var(--text-primary)' }}>{name}</span>
                        {critical > 0 && <span className="text-xs px-1.5 rounded-full" style={{ backgroundColor:'#ef444420', color:'#ef4444' }}>{critical}C</span>}
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs" style={{ color:'var(--text-muted)' }}>{scenarios} scenarios</span>
                        <span className="text-xs font-semibold" style={{ color:'#f97316' }}>{fmtM(exposure)}</span>
                        <span className="text-xs font-bold w-6 text-right" style={{ color: scoreColor(score) }}>{score}</span>
                      </div>
                    </div>
                    <div className="w-full h-3 rounded-full overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                      <div style={{ width:`${(score/maxScore)*100}%`, height:'100%', backgroundColor: scoreColor(score), opacity:0.85 }} />
                    </div>
                  </div>
                ))}
              </div>
              <p className="text-xs mt-3 pt-3" style={{ color:'var(--text-muted)', borderTop:'1px solid var(--border-primary)' }}>
                Total estimated exposure: <span style={{ color:'#f97316', fontWeight:600 }}>$2.4M</span> across {categories.reduce((s,c)=>s+c.scenarios,0)} risk scenarios
              </p>
            </div>
          );
        })(),

        /* ══ RIGHT: Risk Trend — 30-day time series (keep real data) ════════════ */
        right: (
          <div>
            <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Risk Score Trend</h3>
            <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>30-day rolling risk score — lower is better</p>
            <TrendLine data={d.trendData || []} dataKeys={['score']} colors={['#f97316']} />
          </div>
        ),

        /* ══ BOTTOM LEFT: Risk by Account ════════════════════════════════════════ */
        bottomLeft: (() => {
          const riskAccounts = MOCK_TENANTS.flatMap(t =>
            t.accounts.filter(a => a.resources > 0).map((a, idx) => {
              const riskScore   = Math.max(0, 100 - (a.score || 50));
              const exposure    = Math.round((riskScore / 100) * 800000 + idx * 50000);
              const scenarios   = Math.max(1, Math.round(riskScore / 15) + idx % 3);
              const critScenarios = Math.max(0, Math.round(riskScore / 30));
              return { name:a.name, provider:a.provider, tenant:t.name, riskScore, exposure, scenarios, critScenarios };
            })
          ).sort((a, b) => b.riskScore - a.riskScore);
          const fmtK = (v) => v >= 1000000 ? `$${(v/1000000).toFixed(1)}M` : `$${(v/1000).toFixed(0)}K`;
          const RC = (s) => s >= 50 ? '#ef4444' : s >= 30 ? '#f97316' : '#f59e0b';
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Risk Concentration by Account</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Which accounts drive the most financial exposure</p>
              <div className="space-y-2">
                {riskAccounts.map((a, i) => (
                  <div key={i} className="flex items-center gap-2 p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)', borderLeft:`3px solid ${RC(a.riskScore)}` }}>
                    <span className="text-xs w-4 text-right font-semibold" style={{ color:'var(--text-muted)' }}>#{i+1}</span>
                    <CloudProviderBadge provider={a.provider} size="sm" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-medium truncate" style={{ color:'var(--text-primary)', maxWidth:'110px' }}>{a.name}</span>
                        <span className="text-xs font-semibold" style={{ color:'#f97316' }}>{fmtK(a.exposure)}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <div className="flex-1 h-1.5 rounded-full" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                          <div className="h-full rounded-full" style={{ width:`${a.riskScore}%`, backgroundColor: RC(a.riskScore) }} />
                        </div>
                        <span className="text-xs w-6 text-right font-bold" style={{ color: RC(a.riskScore) }}>{a.riskScore}</span>
                        <span className="text-xs" style={{ color:'var(--text-muted)' }}>{a.scenarios} scenarios</span>
                        {a.critScenarios > 0 && <span className="text-xs" style={{ color:'#ef4444' }}>{a.critScenarios}C</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })(),

        /* ══ BOTTOM RIGHT: Risk Reduction Roadmap (Quick Wins) ══════════════════ */
        bottomRight: (() => {
          const roadmap = [
            { action:'Enable MFA on all privileged accounts',     category:'Identity', impact:'High',   effort:'Low',  scoreGain:'+4.2', exposure:'$850K eliminated', priority:1 },
            { action:'Block public access on 3 S3 buckets',       category:'Data',     impact:'High',   effort:'Low',  scoreGain:'+3.8', exposure:'$620K eliminated', priority:2 },
            { action:'Close SSH port 22 to 0.0.0.0/0',           category:'Network',  impact:'High',   effort:'Low',  scoreGain:'+3.1', exposure:'$480K eliminated', priority:3 },
            { action:'Encrypt 21 unencrypted RDS instances',      category:'Data',     impact:'Medium', effort:'Low',  scoreGain:'+2.4', exposure:'$320K eliminated', priority:4 },
            { action:'Rotate API keys older than 90 days',        category:'Identity', impact:'Medium', effort:'Low',  scoreGain:'+2.1', exposure:'$280K eliminated', priority:5 },
            { action:'Enable VPC Flow Logs on production VPCs',   category:'Network',  impact:'Medium', effort:'Low',  scoreGain:'+1.8', exposure:'$190K eliminated', priority:6 },
          ];
          const IC = { High:'#ef4444', Medium:'#f97316', Low:'#f59e0b' };
          const EC = { Low:'#10b981', Medium:'#f59e0b', High:'#ef4444' };
          const CC = { Identity:'#f59e0b', Data:'#ec4899', Network:'#3b82f6', Compliance:'#22c55e', Infrastructure:'#8b5cf6' };
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Risk Reduction Roadmap</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Quick wins ranked by risk score gain ÷ remediation effort</p>
              <div className="space-y-2">
                {roadmap.map(({ action, category, impact, effort, scoreGain, exposure, priority }) => (
                  <div key={priority} className="p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)' }}>
                    <div className="flex items-start gap-2">
                      <div className="w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5" style={{ backgroundColor:`${IC[impact]}20`, color: IC[impact], fontSize:'10px', fontWeight:700 }}>
                        {priority}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-semibold" style={{ color:'var(--text-primary)' }}>{action}</p>
                        <div className="flex items-center gap-2 mt-1 flex-wrap">
                          <span className="text-xs px-1.5 py-0.5 rounded" style={{ backgroundColor:`${CC[category]||'#6b7280'}20`, color:CC[category]||'#6b7280', fontSize:'10px' }}>{category}</span>
                          <span className="text-xs" style={{ color: IC[impact] }}>↑ {impact} impact</span>
                          <span className="text-xs" style={{ color: EC[effort] }}>⚡ {effort} effort</span>
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-xs font-semibold" style={{ color:'#10b981' }}>{scoreGain} pts</span>
                          <span className="text-xs" style={{ color:'var(--text-muted)' }}>{exposure}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              <p className="text-xs mt-3 pt-3" style={{ color:'var(--text-muted)', borderTop:'1px solid var(--border-primary)' }}>
                Completing top 3 actions would raise risk score by <span style={{ color:'#10b981', fontWeight:600 }}>+11.1 pts</span> and eliminate <span style={{ color:'#10b981', fontWeight:600 }}>$1.95M</span> in exposure.
              </p>
            </div>
          );
        })(),

      };
    },
    getTable: (d) => {
      const mockScenarios = [
        { scenario_name:'Customer PII breach via public S3',           threat_category:'data_exposure',      probability:0.35, expected_loss:2400000, rating:'CRITICAL' },
        { scenario_name:'Credential theft via exposed IAM keys',       threat_category:'credential_theft',   probability:0.28, expected_loss:1800000, rating:'CRITICAL' },
        { scenario_name:'Privilege escalation to admin',               threat_category:'privilege_escalation',probability:0.22, expected_loss:950000,  rating:'HIGH'     },
        { scenario_name:'Lateral movement via SG misconfiguration',    threat_category:'lateral_movement',   probability:0.18, expected_loss:720000,  rating:'HIGH'     },
        { scenario_name:'Ransomware on unpatched EC2 instances',       threat_category:'resource_hijacking', probability:0.15, expected_loss:1200000, rating:'HIGH'     },
        { scenario_name:'Compliance violation — PHI data residency',   threat_category:'data_exposure',      probability:0.12, expected_loss:500000,  rating:'MEDIUM'   },
        { scenario_name:'DDoS on public-facing services',              threat_category:'resource_hijacking', probability:0.25, expected_loss:180000,  rating:'MEDIUM'   },
        { scenario_name:'Shadow IT resource provisioning',             threat_category:'defense_evasion',    probability:0.30, expected_loss:120000,  rating:'MEDIUM'   },
      ];
      const apiScenarios = (d.scenarios || []).filter(s => s.scenario_name || s.scenario);
      const data = apiScenarios.length >= 3 ? apiScenarios.slice(0,10) : mockScenarios;
      return { data, columns: riskColumns };
    },
    tableTitle: 'Top Risk Scenarios',
  },
  ciem: {
    label: 'CIEM', Icon: Eye, href: '/ciem', color: '#a855f7', bffView: 'ciem',
    getKpis: (d) => d.kpiGroups || [],
    getCharts: (d) => {
      return {

        /* ══ LEFT: Entitlement Risk by Identity Type ════════════════════════════ */
        left: (() => {
          const identityTypes = [
            { type:'IAM Users',         total:54,  overPriv:18, unusedPerms:142, lastUsedGap:31, critical:3, color:'#ef4444' },
            { type:'IAM Roles',         total:187, overPriv:62, unusedPerms:489, lastUsedGap:18, critical:4, color:'#f97316' },
            { type:'Service Accounts',  total:43,  overPriv:21, unusedPerms:198, lastUsedGap:44, critical:2, color:'#ec4899' },
            { type:'Federated / OIDC',  total:28,  overPriv:9,  unusedPerms:87,  lastUsedGap:12, critical:1, color:'#8b5cf6' },
            { type:'Machine Identities',total:62,  overPriv:14, unusedPerms:234, lastUsedGap:67, critical:0, color:'#3b82f6' },
          ];
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Entitlement Risk by Identity Type</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Overprivileged identities vs total · unused permissions count</p>
              <div className="space-y-3">
                {identityTypes.map(({ type, total, overPriv, unusedPerms, lastUsedGap, critical, color }) => {
                  const overPct = Math.round((overPriv / total) * 100);
                  return (
                    <div key={type}>
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs font-semibold" style={{ color:'var(--text-primary)' }}>{type}</span>
                          {critical > 0 && <span className="text-xs px-1.5 rounded-full" style={{ backgroundColor:'#ef444420', color:'#ef4444' }}>{critical}C</span>}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs" style={{ color:'var(--text-muted)' }}>{unusedPerms} unused perms</span>
                          <span className="text-xs font-semibold" style={{ color }}>{overPriv}/{total} overprivileged</span>
                        </div>
                      </div>
                      {/* Stacked bar: overprivileged vs compliant */}
                      <div className="flex h-3 rounded overflow-hidden" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                        <div style={{ width:`${overPct}%`, backgroundColor: color, opacity:0.9 }} title={`${overPriv} overprivileged`} />
                        <div style={{ width:`${100-overPct}%`, backgroundColor:'#10b981', opacity:0.3 }} title={`${total-overPriv} compliant`} />
                      </div>
                      <div className="flex items-center justify-between mt-0.5">
                        <span className="text-xs" style={{ color }}>{overPct}% overprivileged</span>
                        <span className="text-xs" style={{ color:'var(--text-muted)' }}>avg last used {lastUsedGap}d ago</span>
                      </div>
                    </div>
                  );
                })}
              </div>
              <p className="text-xs mt-3 pt-3" style={{ color:'var(--text-muted)', borderTop:'1px solid var(--border-primary)' }}>
                <span style={{ color:'#f97316', fontWeight:600 }}>234 unused permissions</span> across 374 identities — safe to remove via least-privilege enforcement.
              </p>
            </div>
          );
        })(),

        /* ══ RIGHT: Privilege Escalation Paths ══════════════════════════════════ */
        right: (() => {
          const paths = [
            { id:1, start:'dev-service-account',  via:'iam:PassRole',         target:'AdministratorAccess', account:'AWS Production', sev:'critical', hops:2 },
            { id:2, start:'analytics-role',       via:'sts:AssumeRole',       target:'prod-admin-role',     account:'AWS Production', sev:'critical', hops:3 },
            { id:3, start:'ci-cd-deployer',       via:'iam:AttachUserPolicy', target:'AdministratorAccess', account:'AWS Staging',    sev:'critical', hops:2 },
            { id:4, start:'lambda-execution-role',via:'iam:CreatePolicyVersion',target:'Full Admin via policy', account:'AWS Production', sev:'high', hops:2 },
            { id:5, start:'contractor-user',      via:'sts:AssumeRole',       target:'prod-readonly + data', account:'Azure Corp',    sev:'high',     hops:3 },
            { id:6, start:'backup-service-acct',  via:'s3:GetObject',         target:'credential files',    account:'AWS Staging',   sev:'high',     hops:2 },
            { id:7, start:'monitoring-role',      via:'ec2:DescribeInstances', target:'metadata service keys',account:'GCP Primary', sev:'medium',   hops:2 },
            { id:8, start:'readonly-user-01',     via:'iam:ListRoles',        target:'undocumented trust',  account:'Azure Corp',   sev:'medium',   hops:4 },
          ];
          const SC = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b' };
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Privilege Escalation Paths</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Attack chains from low-privilege identity to admin — sorted by severity</p>
              <div className="space-y-2">
                {paths.map(({ id, start, via, target, account, sev, hops }) => (
                  <div key={id} className="p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)', borderLeft:`3px solid ${SC[sev]}` }}>
                    <div className="flex items-start justify-between gap-1">
                      <div className="flex-1 min-w-0">
                        {/* Path chain visualization */}
                        <div className="flex items-center gap-1 flex-wrap text-xs mb-1">
                          <span className="font-mono px-1.5 py-0.5 rounded" style={{ backgroundColor:'var(--bg-tertiary)', color:'var(--text-secondary)' }}>{start}</span>
                          <span style={{ color:'var(--text-muted)' }}>→</span>
                          <span className="px-1.5 py-0.5 rounded" style={{ backgroundColor:`${SC[sev]}20`, color:SC[sev] }}>{via}</span>
                          <span style={{ color:'var(--text-muted)' }}>→</span>
                          <span className="font-semibold" style={{ color:SC[sev] }}>{target}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs" style={{ color:'var(--text-muted)' }}>{account}</span>
                          <span className="text-xs" style={{ color:'var(--text-muted)' }}>{hops} hops</span>
                        </div>
                      </div>
                      <span className="text-xs px-1.5 py-0.5 rounded flex-shrink-0" style={{ backgroundColor:`${SC[sev]}20`, color:SC[sev] }}>{sev}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })(),

        /* ══ BOTTOM LEFT: Top Overprivileged Identities ═════════════════════════ */
        bottomLeft: (() => {
          const identities = [
            { name:'eks-node-iam-role',    type:'IAM Role',      granted:847, used:12, lastUsed:'47d ago', account:'AWS Production', sev:'critical' },
            { name:'dev-service-account',  type:'Service Acct',  granted:634, used:8,  lastUsed:'12d ago', account:'AWS Production', sev:'critical' },
            { name:'analytics-role',       type:'IAM Role',      granted:521, used:34, lastUsed:'3d ago',  account:'AWS Staging',    sev:'high'     },
            { name:'contractor-user-03',   type:'IAM User',      granted:418, used:19, lastUsed:'89d ago', account:'Azure Corp',     sev:'critical' },
            { name:'ci-cd-deployer',       type:'Service Acct',  granted:389, used:45, lastUsed:'1d ago',  account:'AWS Staging',    sev:'high'     },
            { name:'backup-svc-account',   type:'Service Acct',  granted:312, used:6,  lastUsed:'31d ago', account:'AWS Production', sev:'high'     },
          ];
          const SC = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b' };
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Top Overprivileged Identities</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Granted vs used permissions — ranked by permission excess</p>
              <div className="space-y-2">
                {identities.map((id, i) => {
                  const usedPct = Math.round((id.used / id.granted) * 100);
                  const excess = id.granted - id.used;
                  return (
                    <div key={i} className="p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)' }}>
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs font-semibold font-mono" style={{ color:'var(--text-primary)' }}>{id.name}</span>
                          <span className="text-xs px-1 rounded" style={{ backgroundColor:'var(--bg-tertiary)', color:'var(--text-muted)' }}>{id.type}</span>
                        </div>
                        <span className="text-xs font-bold" style={{ color: SC[id.sev] }}>-{excess} excess</span>
                      </div>
                      {/* Permission usage bar */}
                      <div className="flex h-2 rounded overflow-hidden mb-1" style={{ backgroundColor:'var(--bg-tertiary)' }}>
                        <div style={{ width:`${usedPct}%`, backgroundColor:'#10b981' }} title={`${id.used} used`} />
                        <div style={{ width:`${100-usedPct}%`, backgroundColor: SC[id.sev], opacity:0.6 }} title={`${excess} unused`} />
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span style={{ color:'#10b981' }}>{id.used} used</span>
                        <span style={{ color:'var(--text-muted)' }}>{id.granted} granted · last used {id.lastUsed}</span>
                        <span style={{ color:'var(--text-muted)' }}>{id.account}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })(),

        /* ══ BOTTOM RIGHT: Cross-Account Trust Map ══════════════════════════════ */
        bottomRight: (() => {
          const trustRels = [
            { from:'AWS Staging',     to:'AWS Production',   type:'sts:AssumeRole', roles:3, reviewed:false, external:false, sev:'high'     },
            { from:'Azure Corp',      to:'AWS Production',   type:'Federated OIDC', roles:1, reviewed:false, external:true,  sev:'critical' },
            { from:'GCP Primary',     to:'AWS Production',   type:'Workload Identity',roles:2,reviewed:true, external:true,  sev:'medium'   },
            { from:'AWS Production',  to:'AWS Compliance',   type:'sts:AssumeRole', roles:4, reviewed:true,  external:false, sev:'low'      },
            { from:'ci-cd-pipeline',  to:'AWS Production',   type:'sts:AssumeRole', roles:1, reviewed:false, external:true,  sev:'critical' },
            { from:'AWS DevOps',      to:'Azure Enterprise', type:'Service Principal',roles:2,reviewed:false,external:false, sev:'high'     },
          ];
          const SC = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
          const unreviewed = trustRels.filter(r => !r.reviewed).length;
          const externalUnrev = trustRels.filter(r => !r.reviewed && r.external).length;
          return (
            <div>
              <h3 className="text-sm font-semibold mb-1" style={{ color:'var(--text-primary)' }}>Cross-Account Trust Relationships</h3>
              <p className="text-xs mb-3" style={{ color:'var(--text-muted)' }}>Role assumption and federated trust chains across accounts</p>
              {/* Summary */}
              <div className="flex gap-3 mb-3">
                <div className="flex-1 text-center p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)' }}>
                  <div className="text-lg font-bold" style={{ color:'var(--text-primary)' }}>{trustRels.length}</div>
                  <div className="text-xs" style={{ color:'var(--text-muted)' }}>Total trusts</div>
                </div>
                <div className="flex-1 text-center p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)' }}>
                  <div className="text-lg font-bold" style={{ color:'#f97316' }}>{unreviewed}</div>
                  <div className="text-xs" style={{ color:'var(--text-muted)' }}>Unreviewed</div>
                </div>
                <div className="flex-1 text-center p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)' }}>
                  <div className="text-lg font-bold" style={{ color:'#ef4444' }}>{externalUnrev}</div>
                  <div className="text-xs" style={{ color:'var(--text-muted)' }}>External + unreviewed</div>
                </div>
              </div>
              <div className="space-y-2">
                {trustRels.map((r, i) => (
                  <div key={i} className="flex items-center gap-2 p-2 rounded-lg" style={{ backgroundColor:'var(--bg-secondary)', borderLeft:`3px solid ${SC[r.sev]}` }}>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1 text-xs flex-wrap">
                        <span className="font-semibold" style={{ color:'var(--text-primary)' }}>{r.from}</span>
                        <span style={{ color:'var(--text-muted)' }}>→</span>
                        <span className="font-semibold" style={{ color:'var(--text-primary)' }}>{r.to}</span>
                        {r.external && <span className="px-1.5 rounded" style={{ backgroundColor:'#ef444420', color:'#ef4444', fontSize:'10px' }}>External</span>}
                        {!r.reviewed && <span className="px-1.5 rounded" style={{ backgroundColor:'#f9731620', color:'#f97316', fontSize:'10px' }}>Unreviewed</span>}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5 text-xs">
                        <span style={{ color:'var(--text-muted)' }}>{r.type}</span>
                        <span style={{ color:'var(--text-muted)' }}>{r.roles} role{r.roles>1?'s':''}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })(),

      };
    },
    getTable: (d) => {
      const mockDetections = [
        { severity:'CRITICAL', title:'Privilege escalation via iam:PassRole',              rule_id:'CIEM-001', detection:'eks-node-iam-role → AdministratorAccess',    account_id:'AWS Production' },
        { severity:'CRITICAL', title:'Cross-account assume role without MFA',              rule_id:'CIEM-002', detection:'analytics-role → prod-admin-role',            account_id:'AWS Production' },
        { severity:'CRITICAL', title:'Service account with unused AdministratorAccess',    rule_id:'CIEM-003', detection:'dev-service-account: 847 perms, 12 used',     account_id:'AWS Production' },
        { severity:'HIGH',     title:'Contractor account active after 90d with no review', rule_id:'CIEM-004', detection:'contractor-user-03: last used 89d ago',       account_id:'Azure Corp'     },
        { severity:'HIGH',     title:'Lambda role can create IAM policy versions',         rule_id:'CIEM-005', detection:'lambda-execution-role → policy escalation',   account_id:'AWS Production' },
        { severity:'HIGH',     title:'External trust relationship unreviewed 30d+',        rule_id:'CIEM-006', detection:'Azure Corp → AWS Production (OIDC)',          account_id:'AWS Production' },
        { severity:'HIGH',     title:'CI/CD pipeline has production admin access',         rule_id:'CIEM-007', detection:'ci-cd-deployer → iam:AttachUserPolicy',       account_id:'AWS Staging'    },
        { severity:'MEDIUM',   title:'Role with full S3 access never used on prod data',   rule_id:'CIEM-008', detection:'backup-svc-account: 312 perms, 6 used',      account_id:'AWS Production' },
        { severity:'MEDIUM',   title:'Monitoring role can access instance metadata',       rule_id:'CIEM-009', detection:'monitoring-role → IMDS credential exposure',  account_id:'GCP Primary'    },
        { severity:'LOW',      title:'Unused IAM role candidates for removal',             rule_id:'CIEM-010', detection:'234 permissions flagged for cleanup',         account_id:'All Accounts'   },
      ];
      const apiData = (d.topCritical || []).filter(c => c.title);
      const data = apiData.length >= 3 ? apiData.slice(0,10) : mockDetections;
      return { data, columns: ciemColumns };
    },
    tableTitle: 'Top CIEM Detections',
  },
};

/* ═══════════════════════════════════════════════════════════════════════════
   DOMAIN KPI DEFINITIONS — mock fallbacks per domain
   ═══════════════════════════════════════════════════════════════════════════ */
const DOMAIN_KPIS = {
  threats: [
    { label: 'Active Threats', value: 23, delta: '+5', bad: true, color: '#ef4444', context: '4 critical severity' },
    { label: 'MITRE Techniques', value: 12, delta: '+2', bad: true, color: '#f97316', context: 'mapped this week' },
    { label: 'Affected Resources', value: 47, delta: '+8', bad: true, color: '#f59e0b', context: 'across all accounts' },
    { label: 'Avg Detection Time', value: '2.3h', delta: '-0.5h', bad: false, color: '#10b981', context: 'improving trend' },
  ],
  posture: [
    { label: 'Misconfigurations', value: 312, delta: '-14', bad: false, color: '#8b5cf6', context: 'open findings' },
    { label: 'Critical + High', value: 47, delta: '+3', bad: true, color: '#ef4444', context: 'need immediate fix' },
    { label: 'Failing Rules', value: 68, delta: '-5', bad: false, color: '#f59e0b', context: 'out of 143 rules' },
    { label: 'Posture Score', value: '71%', delta: '+3%', bad: false, color: '#10b981', context: 'vs last scan' },
  ],
  compliance: [
    { label: 'Overall Score', value: '78%', delta: '+2%', bad: false, color: '#10b981', context: 'across 6 frameworks' },
    { label: 'Passing Controls', value: 456, delta: '+18', bad: false, color: '#10b981', context: 'out of 610 total' },
    { label: 'Failing Controls', value: 154, delta: '-18', bad: false, color: '#ef4444', context: 'require remediation' },
    { label: 'Critical Gaps', value: 23, delta: '+1', bad: true, color: '#f97316', context: 'blocking certification' },
  ],
  iam: [
    { label: 'Identities at Risk', value: 18, delta: '+2', bad: true, color: '#f59e0b', context: 'users & roles' },
    { label: 'MFA Disabled', value: 7, delta: '0', bad: true, color: '#ef4444', context: 'privileged accounts' },
    { label: 'Over-privileged', value: 34, delta: '-3', bad: false, color: '#f97316', context: 'roles with excess perms' },
    { label: 'Stale Access Keys', value: 12, delta: '+1', bad: true, color: '#8b5cf6', context: 'unused 90+ days' },
  ],
  inventory: [
    { label: 'Total Assets', value: 12847, delta: '+234', bad: false, color: '#06b6d4', context: 'across all clouds' },
    { label: 'Drifted Resources', value: 47, delta: '+12', bad: true, color: '#f59e0b', context: 'config changed' },
    { label: 'Untagged Assets', value: 389, delta: '-22', bad: false, color: '#8b5cf6', context: 'missing required tags' },
    { label: 'Misconfigured', value: 156, delta: '+8', bad: true, color: '#ef4444', context: 'need remediation' },
  ],
  datasec: [
    { label: 'Data Stores', value: 847, delta: '+12', bad: false, color: '#ec4899', context: 'monitored stores' },
    { label: 'Publicly Exposed', value: 12, delta: '+2', bad: true, color: '#ef4444', context: 'internet accessible' },
    { label: 'Unencrypted', value: 34, delta: '-4', bad: false, color: '#f97316', context: 'stores without encryption' },
    { label: 'PII Detected', value: 8, delta: '+1', bad: true, color: '#8b5cf6', context: 'stores with sensitive data' },
  ],
  network: [
    { label: 'Open Ports', value: 34, delta: '+3', bad: true, color: '#3b82f6', context: 'publicly reachable' },
    { label: 'Unrestricted SGs', value: 12, delta: '-2', bad: false, color: '#ef4444', context: '0.0.0.0/0 rules' },
    { label: 'Public IPs', value: 89, delta: '+5', bad: true, color: '#f97316', context: 'external-facing' },
    { label: 'Unused SGs', value: 23, delta: '-8', bad: false, color: '#10b981', context: 'candidates for cleanup' },
  ],
  risk: [
    { label: 'Risk Score', value: '67/100', delta: '-3', bad: false, color: '#f97316', context: 'overall posture' },
    { label: 'Critical Scenarios', value: 5, delta: '+1', bad: true, color: '#ef4444', context: 'high-impact risks' },
    { label: 'Est. Exposure', value: '$2.4M', delta: '+$0.3M', bad: true, color: '#ef4444', context: 'potential loss value' },
    { label: 'Attack Surface', value: 34, delta: '-2', bad: false, color: '#10b981', context: 'exposed entry points' },
  ],
  ciem: [
    { label: 'CIEM Violations', value: 47, delta: '+4', bad: true, color: '#a855f7', context: 'active detections' },
    { label: 'Unused Permissions', value: 234, delta: '-18', bad: false, color: '#f59e0b', context: 'candidates for removal' },
    { label: 'Cross-account Access', value: 12, delta: '+2', bad: true, color: '#ef4444', context: 'unreviewed trust' },
    { label: 'Priv Esc Paths', value: 8, delta: '+1', bad: true, color: '#ef4444', context: 'escalation chains' },
  ],
};

/* ═══════════════════════════════════════════════════════════════════════════
   DOMAIN DASHBOARD — renders a single domain's executive summary
   ═══════════════════════════════════════════════════════════════════════════ */
function DomainDashboard({ view, data }) {
  const config = DOMAIN_VIEWS[view];
  if (!config) return null;

  // Loading state
  if (!data) {
    return (
      <div className="space-y-5">
        {/* KPI skeleton */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[0,1,2,3].map(i => (
            <div key={i} className="rounded-xl border p-5 animate-pulse" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              <div className="h-3 w-24 rounded mb-3" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
              <div className="h-8 w-16 rounded mb-2" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
              <div className="h-3 w-32 rounded" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
            </div>
          ))}
        </div>
        <div className="flex items-center justify-center py-16 gap-3">
          <Loader2 className="w-5 h-5 animate-spin" style={{ color: config.color }} />
          <span className="text-sm" style={{ color: 'var(--text-tertiary)' }}>Loading {config.label} data…</span>
        </div>
      </div>
    );
  }

  const charts = config.getCharts(data);
  const table = config.getTable(data);
  const domainKpis = DOMAIN_KPIS[view] || [];

  // Extract real KPI values where available, fall back to mock
  const getKpiValue = (mockKpi, idx) => {
    const kpiGroups = config.getKpis(data);
    if (kpiGroups.length > 0) {
      const allCells = kpiGroups.flatMap(g => g.cells || []);
      if (allCells[idx]?.value && allCells[idx].value !== '--') return allCells[idx].value;
    }
    return mockKpi.value;
  };

  return (
    <div className="space-y-5">

      {/* ── DOMAIN KPI STRIP ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {domainKpis.map((k, i) => (
          <div key={k.label} className="rounded-xl border relative overflow-hidden"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
            <div className="absolute left-0 top-0 bottom-0 w-1 rounded-tl-xl rounded-bl-xl" style={{ backgroundColor: k.color }} />
            <div className="absolute top-0 right-0 w-16 h-16 rounded-full opacity-5 -translate-y-4 translate-x-4"
              style={{ backgroundColor: k.color }} />
            <div className="pl-5 pr-4 pt-4 pb-3">
              <p className="text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: 'var(--text-muted)', letterSpacing: '0.06em' }}>{k.label}</p>
              <p className="text-2xl font-bold leading-none mb-2" style={{ color: 'var(--text-primary)' }}>
                {typeof getKpiValue(k, i) === 'number' ? getKpiValue(k, i).toLocaleString() : getKpiValue(k, i)}
              </p>
              <div className="flex items-center gap-1.5">
                <span className="text-xs font-semibold tabular-nums"
                  style={{ color: k.bad ? '#ef4444' : '#10b981' }}>
                  {k.delta.startsWith('+') ? '▲' : k.delta.startsWith('-') ? '▼' : '→'} {k.delta}
                </span>
                <span className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>{k.context}</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* ── DOMAIN INSIGHT CALLOUT ───────────────────────────────────────── */}
      {(() => {
        const insights = {
          threats:    { label: 'Key Finding',   text: 'T1530 (Data from Cloud Storage) is the most active technique — 28 findings across S3 and RDS. 4 critical-severity threats need immediate triage.' },
          posture:    { label: 'Key Finding',   text: '47 critical/high misconfigurations open. IAM and S3 account for 62% of all failing rules — fix these two services for maximum posture gain.' },
          compliance: { label: 'Audit Risk',    text: 'PCI-DSS 4.0 is your lowest-scoring framework at 68.4%. 23 critical controls are failing certification — review before next audit window.' },
          iam:        { label: 'Access Risk',   text: '7 privileged accounts have MFA disabled. 3 service accounts have overly broad permissions — immediate review required for Zero Trust alignment.' },
          inventory:  { label: 'Drift Alert',   text: '47 resources drifted from baseline since last scan. 12 are in production environments — review before next deployment cycle.' },
          datasec:    { label: 'Exposure',      text: '12 data stores are publicly accessible; 8 contain classified PII. Encrypt and restrict access before next compliance review.' },
          network:    { label: 'Exposure',      text: '12 security groups allow unrestricted inbound (0.0.0.0/0). These represent the highest-priority network fixes with lowest remediation effort.' },
          risk:       { label: 'Exposure Est.', text: 'Estimated financial exposure is $2.4M across 7 risk scenarios. Top 5 scenarios account for 78% of total exposure value.' },
          ciem:       { label: 'Privilege Risk', text: '8 privilege escalation paths detected. Cross-account trust relationships require immediate access review to prevent lateral movement.' },
        };
        const ins = insights[view] || { label: 'Summary', text: 'Review the findings below and prioritise by severity.' };
        return (
          <div className="rounded-xl border overflow-hidden flex"
            style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
            {/* Left colour stripe */}
            <div className="w-1 flex-shrink-0" style={{ backgroundColor: config.color }} />
            <div className="flex items-center gap-3 px-4 py-3 flex-1">
              <config.Icon className="w-4 h-4 flex-shrink-0 opacity-60" style={{ color: config.color }} />
              <div className="flex-1 min-w-0">
                <span className="text-xs font-bold uppercase tracking-wider mr-2"
                  style={{ color: config.color, opacity: 0.8 }}>{ins.label}</span>
                <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{ins.text}</span>
              </div>
              <Link href={config.href}
                className="text-xs font-semibold flex-shrink-0 flex items-center gap-1 px-3 py-1.5 rounded-lg border transition-colors"
                style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)', backgroundColor: 'var(--bg-card)' }}>
                Details <ArrowRight className="w-3 h-3" />
              </Link>
            </div>
          </div>
        );
      })()}

      {/* ── CHARTS ROW 1 ─────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="rounded-xl border overflow-hidden p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {charts.left}
        </div>
        <div className="rounded-xl border overflow-hidden p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {charts.right}
        </div>
      </div>

      {/* ── CHARTS ROW 2 · optional bottom charts ────────────────────────── */}
      {(charts.bottomLeft || charts.bottomRight) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {charts.bottomLeft && (
            <div className="rounded-xl border overflow-hidden p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              {charts.bottomLeft}
            </div>
          )}
          {charts.bottomRight && (
            <div className="rounded-xl border overflow-hidden p-5" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
              {charts.bottomRight}
            </div>
          )}
        </div>
      )}

      {/* ── FOOTER STRIP · optional compact resource/finding list ─────────── */}
      {charts.footer && (
        <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {charts.footer}
        </div>
      )}

      {/* ── TABLE · only shown when the domain provides a table (posture skips — chart covers it) ── */}
      {table && (
        <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <div className="px-5 py-3 border-b flex items-center justify-between" style={{ borderColor: 'var(--border-primary)' }}>
            <div>
              <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{config.tableTitle || 'Top Findings'}</h3>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Top 10 items requiring attention · sorted by severity</p>
            </div>
            <Link href={config.href} className="flex items-center gap-1 text-xs font-semibold px-3 py-1.5 rounded-lg"
              style={{ color: config.color, backgroundColor: `${config.color}10` }}>
              View All <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <DataTable
            data={table.data}
            columns={table.columns}
            pageSize={10}
            emptyMessage={`No ${config.label.toLowerCase()} findings`}
            hideToolbar
            defaultDensity="compact"
          />
        </div>
      )}

      {/* ── FULL PAGE CTA ─────────────────────────────────────────────────── */}
      <div className="rounded-xl border p-4 flex items-center justify-between"
        style={{ backgroundColor: `${config.color}05`, borderColor: `${config.color}20` }}>
        <div>
          <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            Ready to dive deeper into {config.label}?
          </p>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            Full dashboard with advanced filtering, drill-down, and export capabilities
          </p>
        </div>
        <Link href={config.href}
          className="flex items-center gap-2 text-sm font-semibold px-4 py-2 rounded-lg transition-all hover:opacity-90 whitespace-nowrap"
          style={{ color: '#fff', backgroundColor: config.color }}>
          Open {config.label} <ArrowRight className="w-4 h-4" />
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

  /* ── Tenant / Account filter (shared by Domain Breakdown + Cloud Health) ── */
  const [selectedTenantId,  setSelectedTenantId]  = useState('all');
  const [selectedAccountId, setSelectedAccountId] = useState('all');

  /* Which tenant groups are collapsed in the "All tenants" view — starts all expanded */
  const [collapsedTenants, setCollapsedTenants] = useState(new Set());
  const toggleTenantCollapse = (tenantId) =>
    setCollapsedTenants(prev => {
      const next = new Set(prev);
      next.has(tenantId) ? next.delete(tenantId) : next.add(tenantId);
      return next;
    });

  const activeTenant  = useMemo(() => MOCK_TENANTS.find(t => t.id === selectedTenantId) ?? null, [selectedTenantId]);
  const activeAccount = useMemo(() => activeTenant?.accounts.find(a => a.id === selectedAccountId) ?? null, [activeTenant, selectedAccountId]);

  /* Domain scores based on filter level */
  const activeDomainScores   = activeAccount?.domainScores   ?? activeTenant?.domainScores   ?? ALL_DOMAIN_SCORES;
  const activeDomainCritical = activeAccount?.domainCritical ?? activeTenant?.domainCritical ?? ALL_DOMAIN_CRITICAL;


  /* Accounts to list in Cloud Account Health */
  const displayAccounts = activeTenant?.accounts ?? null; // null = show all tenants grouped

  /* Total criticals for active context */
  const activeCriticals = activeAccount?.criticals
    ?? activeTenant?.criticals
    ?? MOCK_TENANTS.reduce((s, t) => s + t.criticals, 0);

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
        else setKpiData({
          totalAssets: MOCK_DASHBOARD.total_assets,
          criticalHighFindings: MOCK_DASHBOARD.critical_threats + MOCK_DASHBOARD.high_threats,
          complianceScore: Math.round(MOCK_DASHBOARD.compliance_score),
          activeThreats: MOCK_DASHBOARD.total_threats,
          internetExposed: 156,
          mttr: 4.2, slaCompliance: 87, attackSurfaceScore: 34,
          criticalHighFindingsChange: +3, complianceScoreChange: +2,
        });
        if (data.securityScoreTrendData) setSecurityScoreTrendData(data.securityScoreTrendData);
        else setSecurityScoreTrendData(
          /* 30-day per-engine trends + overall aggregate */
          Array.from({ length: 30 }, (_, i) => {
            const t = i / 29;
            const wave = (phase, amp) => Math.round(Math.sin(i / 4 + phase) * amp);
            const engines = {
              compliance: Math.min(100, Math.max(0, Math.round(68 + t * 8  + wave(0,   3)))),
              threats:    Math.min(100, Math.max(0, Math.round(52 + t * 6  + wave(1,   4)))),
              iam:        Math.min(100, Math.max(0, Math.round(44 - t * 2  + wave(0.5, 3)))),
              misconfigs: Math.min(100, Math.max(0, Math.round(65 + t * 6  + wave(2,   3)))),
              dataSec:    Math.min(100, Math.max(0, Math.round(58 + t * 5  + wave(1.5, 3)))),
              network:    Math.min(100, Math.max(0, Math.round(63 + t * 6  + wave(3,   4)))),
              codeSec:    Math.min(100, Math.max(0, Math.round(50 + t * 5  + wave(2.5, 3)))),
              risk:       Math.min(100, Math.max(0, Math.round(52 - t * 4  + wave(1,   3)))),
            };
            const vals = Object.values(engines);
            const overall = Math.round(vals.reduce((s, v) => s + v, 0) / vals.length);
            return {
              date: new Date(2024, 0, i + 1).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
              overall,
              ...engines,
            };
          })
        );
        if (data.frameworks)             setRealComplianceFrameworks(data.frameworks);
        else setRealComplianceFrameworks(MOCK_FRAMEWORKS);
        if (data.mitreTopTechniques)     setMitreTopTechniques(data.mitreTopTechniques);
        else setMitreTopTechniques([
          {id:'T1530',name:'Data from Cloud Storage',count:28},
          {id:'T1190',name:'Exploit Public-Facing App',count:21},
          {id:'T1078',name:'Valid Accounts',count:19},
          {id:'T1562',name:'Impair Defenses',count:15},
          {id:'T1548',name:'Privilege Escalation',count:12},
        ]);
        if (data.toxicCombinations)      setToxicCombos(data.toxicCombinations);
        else setToxicCombos([
          {id:'tc-1',title:'Public S3 + Admin IAM Role',riskScore:96,description:'Publicly exposed S3 bucket combined with overly permissive IAM role enables data exfiltration.',provider:'AWS',affectedResources:3},
          {id:'tc-2',title:'Exposed RDS + No Encryption',riskScore:89,description:'Internet-accessible RDS instance storing unencrypted sensitive data.',provider:'AWS',affectedResources:1},
          {id:'tc-3',title:'Open Security Group + Privilege Escalation',riskScore:82,description:'Security group allows 0.0.0.0/0 on SSH combined with instance with pass-role permissions.',provider:'AWS',affectedResources:5},
        ]);
        if (data.remediationSLA)         setRemediationSLA(data.remediationSLA);
        else setRemediationSLA([
          {severity:'Critical',slaTarget:'24h',openCount:4,withinSLA:2,breached:2,compliant:50},
          {severity:'High',slaTarget:'72h',openCount:23,withinSLA:19,breached:4,compliant:82.6},
          {severity:'Medium',slaTarget:'7d',openCount:118,withinSLA:107,breached:11,compliant:90.7},
          {severity:'Low',slaTarget:'30d',openCount:234,withinSLA:231,breached:3,compliant:98.7},
        ]);
        if (data.riskyResources)         setRiskyResources(data.riskyResources);
        else setRiskyResources([
          {resource:'s3-prod-eu-sensitive',type:'S3 Bucket',provider:'AWS',region:'eu-west-1',findings:8,riskScore:96,owner:'platform-team',age:'47d'},
          {resource:'rds-master-prod',type:'RDS Instance',provider:'AWS',region:'us-east-1',findings:5,riskScore:91,owner:'data-team',age:'32d'},
          {resource:'iam-admin-break-glass',type:'IAM Role',provider:'AWS',region:'global',findings:6,riskScore:88,owner:'security-team',age:'89d'},
          {resource:'ec2-bastion-host',type:'EC2 Instance',provider:'AWS',region:'us-east-1',findings:4,riskScore:84,owner:'infra-team',age:'12d'},
          {resource:'sg-allow-all-443',type:'Security Group',provider:'AWS',region:'ap-south-1',findings:3,riskScore:79,owner:'network-team',age:'24d'},
          {resource:'lambda-data-processor',type:'Lambda',provider:'AWS',region:'us-east-1',findings:3,riskScore:74,owner:'dev-team',age:'7d'},
          {resource:'cloudtrail-disabled-bucket',type:'CloudTrail',provider:'AWS',region:'us-west-2',findings:2,riskScore:71,owner:'security-team',age:'15d'},
          {resource:'azure-vm-jumpbox',type:'Virtual Machine',provider:'Azure',region:'eastus',findings:3,riskScore:68,owner:'cloud-ops',age:'4d'},
        ]);
        if (data.criticalAlerts)         setCriticalAlerts(data.criticalAlerts);
        /* TODO: swap to data.cloudHealthData once BFF returns enriched fields
           (criticals, score, lastScan, coverage, statusDetail).
           BFF currently returns criticals:0 for all accounts so we always use mock. */
        setCloudHealthData([
          { name:'AWS Production', provider:'aws',   status:'healthy', credStatus:'valid',   regions:8, resources:9412, criticals:12, score:82, lastScan:'2h ago', coverage:100 },
          { name:'AWS Staging',    provider:'aws',   status:'healthy', credStatus:'valid',   regions:3, resources:1843, criticals:4,  score:74, lastScan:'4h ago', coverage:98  },
          { name:'Azure Corp',     provider:'azure', status:'healthy', credStatus:'valid',   regions:4, resources:1247, criticals:7,  score:71, lastScan:'1h ago', coverage:100 },
          { name:'GCP Analytics',  provider:'gcp',   status:'warning', credStatus:'warning', regions:2, resources:345,  criticals:0,  score:0,  lastScan:'3d ago', coverage:0, statusDetail:'Credential expired — re-auth needed' },
        ]);
        if (data.findingsByCategoryData) setFindingsByCategoryData(data.findingsByCategoryData);
        else setFindingsByCategoryData([
          {category:'IAM',critical:12,high:28,medium:45,low:18},
          {category:'Storage',critical:8,high:15,medium:32,low:24},
          {category:'Network',critical:5,high:19,medium:38,low:12},
          {category:'Compute',critical:4,high:11,medium:22,low:9},
          {category:'Database',critical:3,high:9,medium:17,low:6},
        ]);
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

  // ── Inline sub-components ─────────────────────────────────────────────

  /* Posture Score Banner — compact horizontal card above the KPI strip */
  const PostureScoreBanner = ({ score, delta, status, criticalActions }) => {
    const isImproving = delta >= 0;
    const statusColor = score >= 75 ? '#22c55e' : score >= 50 ? '#f97316' : '#ef4444';
    const r = 28, circ = Math.PI * r;
    const offset = circ * (1 - score / 100);
    const cx = 38, cy = 38;
    return (
      <Link href="?tab=posture"
        className="flex items-center gap-6 rounded-xl border px-6 py-4 group hover:border-slate-600 transition-all"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>

        {/* Mini half-gauge */}
        <div className="relative flex-shrink-0" style={{ width: 76, height: 40 }}>
          <svg width={76} height={40} className="overflow-visible">
            <path d={`M ${cx-r},${cy} A ${r},${r} 0 0,1 ${cx+r},${cy}`}
              fill="none" stroke="var(--bg-tertiary)" strokeWidth="6" strokeLinecap="round" />
            <path d={`M ${cx-r},${cy} A ${r},${r} 0 0,1 ${cx+r},${cy}`}
              fill="none" stroke={statusColor} strokeWidth="6" strokeLinecap="round"
              strokeDasharray={circ} strokeDashoffset={offset}
              style={{ transition: 'stroke-dashoffset 0.6s ease-in-out' }} />
            <text x={cx} y={cy - 4} textAnchor="middle" dominantBaseline="middle">
              <tspan fontSize="15" fontWeight="800" fill="var(--text-primary)">{score}</tspan>
              <tspan fontSize="8" fill="var(--text-muted)" dx="1" dy="4">/100</tspan>
            </text>
          </svg>
        </div>

        {/* Title + status */}
        <div className="flex-shrink-0">
          <p className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-muted)' }}>
            Overall Security Posture
          </p>
          <span className="text-xs font-semibold px-2 py-0.5 rounded"
            style={{ backgroundColor: `${statusColor}20`, color: statusColor }}>
            {status} Posture
          </span>
        </div>

        {/* Delta */}
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {isImproving
            ? <TrendingUp className="w-4 h-4" style={{ color: '#22c55e' }} />
            : <TrendingDown className="w-4 h-4" style={{ color: '#ef4444' }} />}
          <span className="text-sm font-semibold"
            style={{ color: isImproving ? '#22c55e' : '#ef4444' }}>
            {isImproving ? '+' : ''}{delta} pts this week
          </span>
        </div>

        {/* Divider */}
        <div className="hidden lg:block w-px h-8 flex-shrink-0" style={{ backgroundColor: 'var(--border-primary)' }} />

        {/* Quick stats */}
        <div className="hidden lg:flex items-center gap-6 flex-1">
          <div>
            <p className="text-lg font-black" style={{ color: '#ef4444' }}>{criticalActions}</p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>critical actions</p>
          </div>
          <div>
            <p className="text-lg font-black" style={{ color: 'var(--text-primary)' }}>8</p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>domains tracked</p>
          </div>
          <div>
            <p className="text-lg font-black" style={{ color: 'var(--text-primary)' }}>3</p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>poor domains</p>
          </div>
        </div>

        {/* CTA */}
        <div className="ml-auto flex items-center gap-1.5 flex-shrink-0 opacity-50 group-hover:opacity-100 transition-opacity">
          <span className="text-xs font-semibold" style={{ color: 'var(--text-secondary)' }}>View domains</span>
          <ArrowRight className="w-3.5 h-3.5" style={{ color: 'var(--text-secondary)' }} />
        </div>
      </Link>
    );
  };

  /* KPI card — label+icon, big number, delta, segmented breakdown chips */
  const KpiCard = ({ label, value, delta, deltaGood, color, Icon, href, segments }) => {
    const deltaColor = deltaGood ? '#10b981' : '#ef4444';
    const displayValue = loading
      ? null
      : typeof value === 'number' ? value.toLocaleString() : (value ?? '—');
    return (
      <Link href={href || '#'}
        className="rounded-xl border relative overflow-hidden block transition-all hover:translate-y-[-1px] group"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        {/* Left accent stripe */}
        <div className="absolute left-0 top-0 bottom-0 w-1" style={{ backgroundColor: color }} />
        <div className="pl-4 pr-4 pt-3 pb-0">
          {/* Row 1: label + icon */}
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs font-bold uppercase" style={{ color: 'var(--text-muted)', letterSpacing: '0.07em', fontSize: '10px' }}>{label}</p>
            <div className="w-6 h-6 rounded-md flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: `${color}18` }}>
              <Icon className="w-3.5 h-3.5" style={{ color }} />
            </div>
          </div>
          {/* Row 2: main value */}
          <p className="text-3xl font-black leading-none mb-2" style={{ color: 'var(--text-primary)' }}>
            {loading
              ? <span className="inline-block w-16 h-8 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
              : displayValue}
          </p>
          {/* Row 3: delta */}
          {delta && (
            <p className="text-xs font-bold mb-3" style={{ color: deltaColor }}>
              {deltaGood ? '↑' : '↓'} {delta}
            </p>
          )}
        </div>
        {/* Row 4: segmented breakdown — divider + chips grid */}
        {segments?.length > 0 && (
          <div className="border-t grid divide-x"
            style={{
              borderColor: 'var(--border-primary)',
              gridTemplateColumns: `repeat(${segments.length}, 1fr)`,
            }}>
            {segments.map((seg, i) => (
              <div key={i} className="px-3 py-2 text-center" style={{ borderColor: 'var(--border-primary)' }}>
                <p className="text-xs font-bold leading-none mb-0.5"
                  style={{ color: seg.color || 'var(--text-primary)' }}>{seg.value}</p>
                <p style={{ color: 'var(--text-muted)', fontSize: '9px', letterSpacing: '0.04em' }}>{seg.label}</p>
              </div>
            ))}
          </div>
        )}
      </Link>
    );
  };

  /* Cloud account health card — focused on OPERATIONAL health only.
     Score / criticals are security findings — they live in DOMAIN COVERAGE, not here.
     This card answers: connected? scan running? credentials valid? coverage ok? */
  const CloudAccountCard = ({ account, compact = false }) => {
    const isIssue = account.status === 'warning' || account.status === 'critical';

    const connMeta = {
      healthy:      { color: '#22c55e', label: 'Connected'    },
      warning:      { color: '#f59e0b', label: 'Degraded'     },
      critical:     { color: '#ef4444', label: 'Disconnected' },
      disconnected: { color: '#6b7280', label: 'Disconnected' },
    };
    const scanMeta = {
      ok:     { color: '#22c55e', label: 'Scan OK'     },
      stale:  { color: '#f59e0b', label: 'Scan Stale'  },
      failed: { color: '#ef4444', label: 'Scan Failed' },
    };
    const credMeta = {
      valid:    { color: '#22c55e', label: 'Creds OK'   },
      expiring: { color: '#f59e0b', label: 'Expiring'   },
      expired:  { color: '#ef4444', label: 'Expired'    },
    };

    const conn = connMeta[account.status]               || connMeta.healthy;
    const scan = scanMeta[account.scanState || 'ok']    || scanMeta.ok;
    const cred = credMeta[account.credentialStatus || 'valid'] || credMeta.valid;

    if (compact) {
      /* ── Compact row: one line per account in grouped tenant view ── */
      return (
        <Link href="/onboarding"
          className="flex items-center gap-3 rounded-lg border px-3 py-2 hover:border-slate-500 transition-colors text-xs"
          style={{
            backgroundColor: 'var(--bg-secondary)',
            borderColor: isIssue ? `${conn.color}50` : 'var(--border-primary)',
          }}>
          <CloudProviderBadge provider={account.provider} size="sm" />
          <span className="font-semibold flex-1 truncate" style={{ color: 'var(--text-primary)' }}>{account.name}</span>
          {/* Connection */}
          <span className="flex items-center gap-1 flex-shrink-0" style={{ color: conn.color }}>
            <span style={{ fontSize: '7px' }}>●</span> {conn.label}
          </span>
          <span style={{ color: 'var(--border-primary)' }}>·</span>
          {/* Scan */}
          <span className="flex items-center gap-1 flex-shrink-0" style={{ color: scan.color }}>
            <span style={{ fontSize: '7px' }}>●</span> {scan.label}
          </span>
          <span style={{ color: 'var(--border-primary)' }}>·</span>
          <span className="flex-shrink-0" style={{ color: 'var(--text-muted)' }}>Last: {account.lastScan}</span>
          <span style={{ color: 'var(--border-primary)' }}>·</span>
          <span className="flex-shrink-0" style={{ color: 'var(--text-muted)' }}>{account.coverage ?? 0}% coverage</span>
          {(account.credentialStatus === 'expiring' || account.credentialStatus === 'expired') && (
            <span className="flex-shrink-0 font-semibold" style={{ color: cred.color }}>⚠ {cred.label}</span>
          )}
        </Link>
      );
    }

    /* ── Full card: per-account operational detail ── */
    return (
      <Link href="/onboarding"
        className="rounded-lg border p-3 block hover:border-slate-500 transition-colors"
        style={{
          backgroundColor: 'var(--bg-secondary)',
          borderColor: isIssue ? `${conn.color}50` : 'var(--border-primary)',
        }}>

        {/* Row 1: provider + name + connection status */}
        <div className="flex items-center gap-2 mb-2.5">
          <CloudProviderBadge provider={account.provider} size="sm" />
          <span className="text-xs font-semibold flex-1 truncate" style={{ color: 'var(--text-primary)' }}>
            {account.name}
          </span>
          <span className="flex items-center gap-1 text-xs font-semibold flex-shrink-0"
            style={{ color: conn.color }}>
            <span style={{ fontSize: '8px' }}>●</span> {conn.label}
          </span>
        </div>

        {/* Row 2: scan status + last / next */}
        <div className="flex items-center justify-between text-xs rounded px-2 py-1.5 mb-2"
          style={{ backgroundColor: `${scan.color}10`, border: `1px solid ${scan.color}20` }}>
          <span className="flex items-center gap-1.5 font-semibold" style={{ color: scan.color }}>
            <span style={{ fontSize: '8px' }}>●</span> {scan.label}
          </span>
          <span style={{ color: 'var(--text-muted)' }}>
            Last: <span className="font-medium" style={{ color: 'var(--text-secondary)' }}>{account.lastScan}</span>
            {account.nextScan && account.nextScan !== 'N/A' &&
              <> · Next: <span className="font-medium" style={{ color: 'var(--text-secondary)' }}>{account.nextScan}</span></>}
          </span>
        </div>

        {/* Row 3: coverage bar + regions + resources */}
        <div className="mb-2">
          <div className="flex items-center justify-between text-xs mb-1">
            <span style={{ color: 'var(--text-muted)' }}>{account.regions} regions · {(account.resources||0).toLocaleString()} resources</span>
            <span className="font-semibold" style={{ color: (account.coverage||0) >= 90 ? '#22c55e' : '#f59e0b' }}>
              {account.coverage ?? 0}% coverage
            </span>
          </div>
          <div className="h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
            <div className="h-full rounded-full transition-all duration-500"
              style={{ width: `${account.coverage ?? 0}%`, backgroundColor: (account.coverage||0) >= 90 ? '#22c55e' : '#f59e0b' }} />
          </div>
        </div>

        {/* Row 4: credential status */}
        <div className="flex items-center justify-between text-xs">
          <span className="flex items-center gap-1.5" style={{ color: cred.color }}>
            <span style={{ fontSize: '8px' }}>●</span>
            <span className="font-semibold">{cred.label}</span>
          </span>
          <span style={{ color: 'var(--text-muted)' }}>{account.credentialNote}</span>
        </div>

        {/* Warning detail */}
        {isIssue && account.statusDetail && (
          <div className="mt-2 rounded px-2 py-1.5 text-xs font-medium"
            style={{ backgroundColor: `${conn.color}12`, color: conn.color }}>
            {account.statusDetail}
          </div>
        )}
      </Link>
    );
  };

  /* Compliance framework card */
  const FwCard = ({ fw }) => {
    const c = fw.score >= 80 ? '#10b981' : fw.score >= 65 ? '#f59e0b' : '#ef4444';
    const radius = 28; const circ = 2 * Math.PI * radius;
    const dash = circ * (fw.score / 100);
    return (
      <Link href="/compliance" className="rounded-xl border p-4 flex items-center gap-4 hover:border-opacity-70 transition-all block"
        style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
        <div className="relative flex-shrink-0 w-14 h-14">
          <svg width="56" height="56" viewBox="0 0 56 56" className="-rotate-90">
            <circle cx="28" cy="28" r={radius} fill="none" stroke="var(--bg-tertiary)" strokeWidth="5" />
            <circle cx="28" cy="28" r={radius} fill="none" stroke={c} strokeWidth="5"
              strokeDasharray={`${dash} ${circ}`} strokeLinecap="round" />
          </svg>
          <span className="absolute inset-0 flex items-center justify-center text-sm font-bold" style={{ color: c }}>{fw.score}%</span>
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold mb-0.5 truncate" style={{ color: 'var(--text-primary)' }}>{fw.name}</p>
          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            {fw.passed_controls ?? Math.round((fw.score/100)*(fw.total_controls||100))}/{fw.total_controls ?? 100} controls
          </p>
          <div className="mt-2 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
            <div className="h-full rounded-full transition-all" style={{ width: `${fw.score}%`, backgroundColor: c }} />
          </div>
        </div>
      </Link>
    );
  };

  // ═══════════════════════════════════════════════════════════════════════════
  return (
    <div className="space-y-5">

      {/* ── Error state ───────────────────────────────────────────────────── */}
      {pageError && (
        <div className="rounded-xl p-4 border flex items-center gap-3"
          style={{ backgroundColor: 'rgba(239,68,68,0.06)', borderColor: 'rgba(239,68,68,0.4)' }}>
          <AlertCircle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
          <div>
            <p className="text-sm font-semibold" style={{ color: '#ef4444' }}>Failed to load dashboard data</p>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{pageError} — showing demo data</p>
          </div>
        </div>
      )}

      {/* [1] Critical Alert Banner ───────────────────────────────────────── */}
      {hasCriticalAlerts && (
        <AlertBanner
          severity="critical"
          title={`${criticalAlerts.length} critical alert${criticalAlerts.length > 1 ? 's' : ''} require immediate attention`}
          description={criticalAlerts[0]?.message}
          items={criticalAlerts.slice(0, 4).map((a) => ({ label: a.resource || a.message, count: a.count, link: '/threats' }))}
          action={{ label: 'View Threats', onClick: () => (window.location.href = '/threats') }}
        />
      )}

      {/* [2a] POSTURE SCORE BANNER ────────────────────────────────────────── */}
      <PostureScoreBanner
        score={kpiData.complianceScore || MOCK_POSTURE.score}
        delta={kpiData.complianceScoreChange || MOCK_POSTURE.delta}
        status={kpiData.complianceScore >= 75 ? 'Good' : kpiData.complianceScore >= 50 ? 'Fair' : 'Critical'}
        criticalActions={kpiData.criticalHighFindings || MOCK_POSTURE.criticalActions}
      />

      {/* [2b] KPI STRIP — 5 action-oriented metrics ─────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <KpiCard label="Total Assets" Icon={Server} href="/inventory" color="#3b82f6"
          value={kpiData.totalAssets || MOCK_DASHBOARD.total_assets}
          delta="+47 this week" deltaGood
          segments={[
            { label: 'AWS · 2 accts',   value: '9.4K', color: '#f97316' },
            { label: 'Azure · 1 acct',  value: '1.2K', color: '#3b82f6' },
            { label: 'GCP · 1 acct',    value: '345',  color: '#10b981' },
          ]} />
        <KpiCard label="Critical + High Findings" Icon={AlertCircle} href="/misconfig?severity=critical" color="#ef4444"
          value={kpiData.criticalHighFindings || (MOCK_DASHBOARD.critical_threats + MOCK_DASHBOARD.high_threats)}
          delta={`+${kpiData.criticalHighFindingsChange ?? 3} new today`} deltaGood={false}
          segments={[
            { label: 'Critical',  value: MOCK_DASHBOARD.critical_threats,  color: '#ef4444' },
            { label: 'High',      value: MOCK_DASHBOARD.high_threats,       color: '#f97316' },
            { label: 'Medium',    value: 89,                                color: '#f59e0b' },
          ]} />
        <KpiCard label="Active Threats" Icon={AlertTriangle} href="/threats" color="#f97316"
          value={kpiData.activeThreats || MOCK_DASHBOARD.total_threats}
          delta="+5 new today" deltaGood={false}
          segments={[
            { label: 'Critical',     value: 4,  color: '#ef4444' },
            { label: 'High',         value: 8,  color: '#f97316' },
            { label: 'MITRE TTPs',   value: 12, color: '#8b5cf6' },
          ]} />
        <KpiCard label="Internet Exposed" Icon={Network} href="/network-security" color="#f59e0b"
          value={kpiData.internetExposed || 156}
          delta="+12 since yesterday" deltaGood={false}
          segments={[
            { label: 'Open Ports',  value: 18, color: '#ef4444' },
            { label: 'Public SGs',  value: 34, color: '#f97316' },
            { label: 'Public IPs',  value: 89, color: '#f59e0b' },
          ]} />
        <KpiCard label="Compliance Score" Icon={ClipboardCheck} href="/compliance" color="#10b981"
          value={`${kpiData.complianceScore || Math.round(MOCK_DASHBOARD.compliance_score)}%`}
          delta={`+${kpiData.complianceScoreChange ?? 2}% vs last week`} deltaGood
          segments={[
            { label: 'CIS AWS',   value: '78%', color: '#10b981' },
            { label: 'NIST',      value: '71%', color: '#f59e0b' },
            { label: 'PCI-DSS',   value: '68%', color: '#ef4444' },
          ]} />
      </div>

      {/* [3] TENANT/ACCOUNT FILTER + POSTURE HERO + CLOUD HEALTH ─────────── */}

      {/* ── Shared filter bar ── */}
      <div className="rounded-xl border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex flex-wrap items-center gap-3 px-5 py-3">
          {/* Section label */}
          <span className="text-xs font-semibold uppercase tracking-wider flex-shrink-0"
            style={{ color: 'var(--text-muted)' }}>Scope:</span>

          {/* Tenant pills */}
          <div className="flex flex-wrap items-center gap-2 flex-1">
            {/* All tenants pill */}
            <button
              onClick={() => { setSelectedTenantId('all'); setSelectedAccountId('all'); }}
              className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full border transition-all"
              style={{
                backgroundColor: selectedTenantId === 'all' ? '#3b82f620' : 'transparent',
                borderColor:     selectedTenantId === 'all' ? '#3b82f6'   : 'var(--border-primary)',
                color:           selectedTenantId === 'all' ? '#3b82f6'   : 'var(--text-secondary)',
              }}>
              All Tenants
              <span className="text-xs px-1.5 py-0.5 rounded-full font-bold"
                style={{ backgroundColor: selectedTenantId === 'all' ? '#3b82f630' : 'var(--bg-tertiary)', color: selectedTenantId === 'all' ? '#3b82f6' : 'var(--text-muted)' }}>
                {MOCK_TENANTS.length}
              </span>
            </button>

            {/* Per-tenant pills */}
            {MOCK_TENANTS.map(t => {
              const isActive = selectedTenantId === t.id;
              return (
                <button key={t.id}
                  onClick={() => { setSelectedTenantId(t.id); setSelectedAccountId('all'); }}
                  className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1 rounded-full border transition-all"
                  style={{
                    backgroundColor: isActive ? '#8b5cf620' : 'transparent',
                    borderColor:     isActive ? '#8b5cf6'   : 'var(--border-primary)',
                    color:           isActive ? '#8b5cf6'   : 'var(--text-secondary)',
                  }}>
                  {t.name}
                  {t.criticals > 0 && (
                    <span className="text-xs font-bold" style={{ color: '#ef4444' }}>▲{t.criticals}</span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Account dropdown — only when a tenant is selected */}
          {selectedTenantId !== 'all' && activeTenant && (
            <div className="flex items-center gap-2 flex-shrink-0 border-l pl-3"
              style={{ borderColor: 'var(--border-primary)' }}>
              <span className="text-xs flex-shrink-0" style={{ color: 'var(--text-muted)' }}>Account:</span>
              <select
                value={selectedAccountId}
                onChange={e => setSelectedAccountId(e.target.value)}
                className="text-xs rounded-lg px-2 py-1.5 border outline-none cursor-pointer"
                style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
                <option value="all">All Accounts ({activeTenant.accounts.length})</option>
                {activeTenant.accounts.map(acc => (
                  <option key={acc.id} value={acc.id}>
                    {acc.name} — {acc.status === 'warning' ? '⚠ Warning' : `${acc.criticals} criticals`}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Active filter label */}
          {(selectedTenantId !== 'all' || selectedAccountId !== 'all') && (
            <div className="flex items-center gap-2 flex-shrink-0">
              <span className="text-xs px-2 py-1 rounded font-medium"
                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                {activeAccount ? `${activeTenant.name} / ${activeAccount.name}` : activeTenant?.name}
              </span>
              <button
                onClick={() => { setSelectedTenantId('all'); setSelectedAccountId('all'); }}
                className="text-xs px-2 py-1 rounded border transition-colors hover:opacity-80"
                style={{ borderColor: 'var(--border-primary)', color: 'var(--text-muted)' }}>
                Clear ×
              </button>
            </div>
          )}
        </div>
      </div>

      {/* [4] DOMAIN TAB SWITCHER ─────────────────────────────────────────── */}
      <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-stretch overflow-x-auto">
          {tabs.map((tab) => {
            const isActive = activeView === tab.id;
            return (
              <button key={tab.id} onClick={() => setActiveView(tab.id)}
                className="flex flex-col items-center gap-1 px-4 py-3 border-r last:border-r-0 whitespace-nowrap transition-all hover:opacity-90 relative"
                style={{
                  borderColor: 'var(--border-primary)',
                  backgroundColor: isActive ? `${tab.color}10` : 'transparent',
                  cursor: 'pointer', minWidth: 90,
                }}>
                {isActive && <div className="absolute bottom-0 left-0 right-0 h-0.5" style={{ backgroundColor: tab.color }} />}
                <tab.Icon className="w-4 h-4" style={{ color: isActive ? tab.color : 'var(--text-muted)' }} />
                <span className="text-xs font-semibold" style={{ color: isActive ? tab.color : 'var(--text-secondary)' }}>{tab.label}</span>
                {tab.score != null && (
                  <span className="text-xs font-bold" style={{ color: scoreColor(tab.score) }}>{tab.score}%</span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Content: Overview or Domain-specific ──────────────────────── */}
      {activeView === 'overview' ? (
        <>

          {/* ══ C: DOMAIN HEALTH GRID · Aggregate score per security domain ══ */}
          <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
            <div className="px-5 py-2.5 border-b flex items-center gap-2" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
              <Shield className="w-3.5 h-3.5" style={{ color: 'var(--accent-primary)' }} />
              <span className="text-xs font-bold tracking-widest uppercase" style={{ color: 'var(--accent-primary)' }}>DOMAIN HEALTH</span>
              <span className="text-xs mx-1" style={{ color: 'var(--border-primary)' }}>·</span>
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Aggregate posture score per security domain — click to drill down</span>
              {(activeAccount || activeTenant) && (
                <span className="text-xs font-semibold px-2 py-0.5 rounded ml-1"
                  style={{ backgroundColor: '#8b5cf620', color: '#8b5cf6' }}>
                  {activeAccount ? `${activeTenant.name} / ${activeAccount.name}` : activeTenant?.name}
                </span>
              )}
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 divide-x divide-y sm:divide-y-0"
              style={{ borderColor: 'var(--border-primary)' }}>
              {[
                { label: 'Threats',     Icon: AlertTriangle,  color: '#ef4444', score: activeDomainScores.threats    ?? 58, href: '/threats'    },
                { label: 'IAM',         Icon: KeyRound,       color: '#f59e0b', score: activeDomainScores.iam         ?? MOCK_POSTURE.domainScores.iam, href: '/iam' },
                { label: 'Compliance',  Icon: ClipboardCheck, color: '#22c55e', score: activeDomainScores.compliance  ?? MOCK_POSTURE.domainScores.compliance, href: '/compliance' },
                { label: 'Assets',      Icon: Server,         color: '#06b6d4', score: 85,                              href: '/inventory'  },
                { label: 'Risk',        Icon: TrendingUp,     color: '#8b5cf6', score: activeDomainScores.risk        ?? MOCK_POSTURE.domainScores.misconfigs, href: '/risk' },
                { label: 'Data Sec',    Icon: Database,       color: '#10b981', score: activeDomainScores.dataSec     ?? MOCK_POSTURE.domainScores.dataSec, href: '/datasec' },
                { label: 'Network',     Icon: Network,        color: '#0ea5e9', score: activeDomainScores.network     ?? 80, href: '/network'   },
                { label: 'Code Sec',    Icon: Code,           color: '#a78bfa', score: activeDomainScores.codeSec     ?? 84, href: '/codesec'   },
              ].map((dom) => {
                const sc = dom.score >= 75 ? '#22c55e' : dom.score >= 50 ? '#f97316' : '#ef4444';
                const sl = dom.score >= 75 ? 'Good'    : dom.score >= 50 ? 'Fair'    : 'Poor';
                return (
                  <Link key={dom.label} href={dom.href}
                    className="flex flex-col gap-2.5 p-3.5 group hover:bg-white/[0.03] transition-colors relative"
                    style={{ borderColor: 'var(--border-primary)' }}>

                    {/* Row 1: domain icon + name left, status badge right */}
                    <div className="flex items-center justify-between gap-1 min-w-0">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <dom.Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: dom.color }} />
                        <span className="text-xs font-semibold truncate" style={{ color: 'var(--text-secondary)' }}>{dom.label}</span>
                      </div>
                      <span className="text-xs font-bold px-1.5 py-0.5 rounded flex-shrink-0"
                        style={{ backgroundColor: `${sc}18`, color: sc, fontSize: '9px', letterSpacing: '0.04em' }}>{sl}</span>
                    </div>

                    {/* Row 2: large score + /100 */}
                    <div className="flex items-baseline gap-0.5 leading-none">
                      <span className="text-2xl font-black tabular-nums" style={{ color: sc }}>{dom.score}</span>
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>/100</span>
                    </div>

                    {/* Row 3: progress bar */}
                    <div className="w-full h-[5px] rounded-full overflow-hidden" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                      <div className="h-full rounded-full transition-all duration-500"
                        style={{ width: `${dom.score}%`, backgroundColor: sc, boxShadow: `0 0 6px ${sc}60` }} />
                    </div>

                    {/* Hover arrow */}
                    <span className="absolute bottom-2 right-3 text-xs opacity-0 group-hover:opacity-50 transition-opacity"
                      style={{ color: 'var(--accent-primary)' }}>→</span>
                  </Link>
                );
              })}
            </div>
          </div>

          {/* ══ D: OVERALL POSTURE TREND · 30-day aggregated score ════════ */}
          <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
            <div className="px-5 py-2.5 border-b flex items-center gap-2" style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
              <TrendingUp className="w-3.5 h-3.5" style={{ color: 'var(--accent-primary)' }} />
              <span className="text-xs font-bold tracking-widest uppercase" style={{ color: 'var(--accent-primary)' }}>OVERALL POSTURE TREND</span>
              <span className="text-xs mx-1" style={{ color: 'var(--border-primary)' }}>·</span>
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>30-day rolling average across all security engines — score 0–100</span>
            </div>
            <div className="px-5 pt-4 pb-3">
              <TrendLine
                data={securityScoreTrendData}
                dataKeys={['overall']}
                labels={['Overall Posture']}
                colors={['#3b82f6']}
                height={220}
                yDomain={[0, 100]}
                yTicks={[0, 25, 50, 75, 100]}
                yLabel="Score"
                xInterval={6}
                referenceLines={[
                  { y: 75, color: '#22c55e', label: 'Good ≥75' },
                  { y: 50, color: '#f97316', label: 'Fair ≥50' },
                ]}
              />
            </div>
          </div>

          {/* ══ E: TOP AFFECTED ACCOUNTS · Risk-ranked account leaderboard ═══ */}
          {(() => {
            /* Flatten all accounts, compute a risk weight (criticals×4 + highs×2 + mediums×1),
               sort descending, take top 7 */
            const rankedAccounts = MOCK_TENANTS.flatMap(t =>
              t.accounts.map(acc => {
                const ds = acc.domainScores || {};
                const dc = acc.domainCritical || {};
                // sum domain criticals as a proxy for high/medium — use criticals directly
                const critTotal = acc.criticals || 0;
                // derive high/medium from domain critical counts (they track criticals)
                const highProxy   = Math.round(critTotal * 1.8);
                const mediumProxy = Math.round(critTotal * 3.2);
                const riskWeight  = critTotal * 4 + highProxy * 2 + mediumProxy;
                // avg domain score
                const scores = Object.values(ds).filter(v => v > 0);
                const avgScore = scores.length ? Math.round(scores.reduce((s,v)=>s+v,0)/scores.length) : 0;
                return { ...acc, tenant: t, critTotal, highProxy, mediumProxy, riskWeight, avgScore };
              })
            ).sort((a, b) => b.riskWeight - a.riskWeight).slice(0, 7);

            const maxRisk = rankedAccounts[0]?.riskWeight || 1;
            const SEV_C = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b', low:'#10b981' };
            const scoreColor2 = v => v >= 75 ? '#22c55e' : v >= 50 ? '#f97316' : v > 0 ? '#ef4444' : '#6b7280';

            return (
              <div className="rounded-xl border overflow-hidden"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>

                {/* Header */}
                <div className="px-5 py-2.5 border-b flex items-center justify-between gap-3"
                  style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5" style={{ color: '#ef4444' }} />
                    <span className="text-xs font-bold tracking-widest uppercase" style={{ color: '#ef4444' }}>
                      TOP AFFECTED ACCOUNTS
                    </span>
                    <span className="text-xs mx-1" style={{ color: 'var(--border-primary)' }}>·</span>
                    <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                      Ranked by critical + high findings across all tenants — click to drill in
                    </span>
                  </div>
                  <Link href="/onboarding"
                    className="text-xs font-semibold flex-shrink-0"
                    style={{ color: 'var(--accent-primary)' }}>
                    All Accounts →
                  </Link>
                </div>

                {/* Column labels */}
                <div className="hidden md:grid px-5 py-1.5 border-b"
                  style={{ gridTemplateColumns: '28px 1fr 200px 80px 72px 100px', gap: '0 16px', borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                  {['#','Account','Severity Breakdown','Score','Criticals',''].map((h,i) => (
                    <span key={i} className="text-xs font-semibold uppercase tracking-wider"
                      style={{ color: 'var(--text-muted)', fontSize: '9px', letterSpacing: '0.08em' }}>{h}</span>
                  ))}
                </div>

                {/* Rows */}
                <div className="divide-y" style={{ borderColor: 'var(--border-primary)' }}>
                  {rankedAccounts.map((acc, i) => {
                    const sc = scoreColor2(acc.avgScore);
                    const totalFindings = acc.critTotal + acc.highProxy + acc.mediumProxy;
                    const barTotal = Math.max(totalFindings, 1);
                    const isIssue = acc.status === 'warning' || acc.scanState !== 'ok';

                    return (
                      <div key={acc.id}
                        className="flex items-center gap-4 px-5 py-3 hover:bg-white/[0.02] transition-colors"
                        style={{ borderColor: 'var(--border-primary)' }}>

                        {/* Rank */}
                        <span className="text-xs font-bold w-5 flex-shrink-0 tabular-nums text-center"
                          style={{ color: i < 3 ? '#ef4444' : 'var(--text-muted)' }}>
                          #{i + 1}
                        </span>

                        {/* Account name + provider + tenant */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            {/* Provider dot */}
                            <div className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                              style={{ backgroundColor: isIssue ? '#f59e0b' : '#22c55e' }} />
                            <CloudProviderBadge provider={acc.provider} size="sm" />
                            <span className="text-xs font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
                              {acc.name}
                            </span>
                            {isIssue && (
                              <span className="text-xs font-bold px-1.5 py-0.5 rounded flex-shrink-0"
                                style={{ backgroundColor: '#f59e0b18', color: '#f59e0b', fontSize: '9px' }}>
                                ⚠ {acc.scanState !== 'ok' ? 'Scan issue' : 'Cred issue'}
                              </span>
                            )}
                          </div>
                          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {acc.tenant.name} · {acc.regions} regions · {(acc.resources || 0).toLocaleString()} resources
                          </span>
                        </div>

                        {/* Severity breakdown stacked bar */}
                        <div className="hidden md:block w-48 flex-shrink-0">
                          <div className="flex h-3 rounded overflow-hidden mb-1" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                            {[
                              { key: 'critical', val: acc.critTotal  },
                              { key: 'high',     val: acc.highProxy  },
                              { key: 'medium',   val: acc.mediumProxy },
                            ].filter(s => s.val > 0).map(s => (
                              <div key={s.key}
                                style={{ width: `${(s.val / barTotal) * 100}%`, backgroundColor: SEV_C[s.key], minWidth: 3 }}
                                title={`${s.key}: ${s.val}`} />
                            ))}
                          </div>
                          <div className="flex items-center gap-3">
                            {[
                              { label: 'C', val: acc.critTotal,   color: '#ef4444' },
                              { label: 'H', val: acc.highProxy,   color: '#f97316' },
                              { label: 'M', val: acc.mediumProxy, color: '#f59e0b' },
                            ].map(s => (
                              <span key={s.label} style={{ fontSize: '9px', color: 'var(--text-muted)' }}>
                                <span style={{ color: s.color, fontWeight: 700 }}>{s.label}</span>:{s.val}
                              </span>
                            ))}
                          </div>
                        </div>

                        {/* Score arc + number */}
                        <div className="hidden md:flex flex-col items-center flex-shrink-0 w-16">
                          {acc.avgScore > 0 ? (
                            <>
                              <div className="relative" style={{ width: 36, height: 20 }}>
                                <svg width={36} height={20} className="overflow-visible">
                                  <path d="M 4,18 A 14,14 0 0,1 32,18" fill="none" stroke="var(--bg-tertiary)" strokeWidth="4" strokeLinecap="round" />
                                  <path d="M 4,18 A 14,14 0 0,1 32,18" fill="none" stroke={sc} strokeWidth="4" strokeLinecap="round"
                                    strokeDasharray={`${Math.PI * 14}`}
                                    strokeDashoffset={Math.PI * 14 * (1 - acc.avgScore / 100)}
                                    style={{ transition: 'stroke-dashoffset 0.6s ease' }} />
                                </svg>
                                <span className="absolute inset-0 flex items-end justify-center pb-0"
                                  style={{ fontSize: '10px', fontWeight: 800, color: sc, lineHeight: 1 }}>
                                  {acc.avgScore}
                                </span>
                              </div>
                              <span style={{ fontSize: '9px', color: 'var(--text-muted)' }}>score</span>
                            </>
                          ) : (
                            <span className="text-xs font-semibold" style={{ color: '#6b7280' }}>N/A</span>
                          )}
                        </div>

                        {/* Critical badge */}
                        <div className="flex-shrink-0 text-center" style={{ width: 64 }}>
                          {acc.critTotal > 0 ? (
                            <span className="text-xs font-bold px-2 py-1 rounded"
                              style={{ backgroundColor: '#ef444418', color: '#ef4444', border: '1px solid #ef444430' }}>
                              ▲{acc.critTotal} crit
                            </span>
                          ) : (
                            <span className="text-xs font-semibold" style={{ color: '#22c55e' }}>✓ Clean</span>
                          )}
                        </div>

                        {/* Drill-in button — sets the filter */}
                        <button
                          onClick={() => { setSelectedTenantId(acc.tenant.id); setSelectedAccountId(acc.id); }}
                          className="hidden md:flex items-center gap-1 text-xs font-semibold px-3 py-1.5 rounded-lg border flex-shrink-0 transition-colors hover:border-opacity-80"
                          style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)', backgroundColor: 'var(--bg-secondary)' }}>
                          View <ArrowRight className="w-3 h-3" />
                        </button>

                      </div>
                    );
                  })}
                </div>

                {/* Footer totals */}
                <div className="px-5 py-2 border-t flex items-center gap-4 flex-wrap"
                  style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                  <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    <span className="font-semibold" style={{ color: '#ef4444' }}>
                      {MOCK_TENANTS.flatMap(t => t.accounts).reduce((s, a) => s + (a.criticals || 0), 0)}
                    </span> total criticals across{' '}
                    <span className="font-semibold" style={{ color: 'var(--text-secondary)' }}>
                      {MOCK_TENANTS.flatMap(t => t.accounts).length}
                    </span> accounts
                  </span>
                  <span className="text-xs" style={{ color: 'var(--border-primary)' }}>·</span>
                  <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    ranked by{' '}
                    <span className="font-semibold" style={{ color: 'var(--text-secondary)' }}>risk weight</span>
                    {' '}(critical×4 + high×2 + medium×1)
                  </span>
                </div>
              </div>
            );
          })()}

          {/* ══ F: SCAN COVERAGE · Platform Health ══════════════════════ */}
          <div className="rounded-xl border px-5 py-3 flex items-center gap-4 flex-wrap"
            style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full animate-pulse" style={{ backgroundColor: '#10b981' }} />
              <span className="text-xs font-bold tracking-widest uppercase" style={{ color: 'var(--text-muted)' }}>SCAN COVERAGE</span>
            </div>
            {[
              { label: `${totalAcc||4}/${totalAcc||4} accounts active`, color: '#10b981' },
              { label: 'Last scan: 2h ago', color: 'var(--text-muted)' },
              { label: '40+ services monitored', color: 'var(--text-muted)' },
              { label: '143 rules active', color: 'var(--text-muted)' },
              { label: '0 scan failures', color: '#10b981' },
            ].map((s) => (
              <span key={s.label} className="text-xs flex items-center gap-1.5" style={{ color: s.color }}>
                <span style={{ color: 'var(--border-primary)' }}>·</span> {s.label}
              </span>
            ))}
            <Link href="/onboarding" className="ml-auto text-xs font-semibold" style={{ color: 'var(--accent-primary)' }}>Manage Coverage →</Link>
          </div>

        </>
      ) : (
        /* ── Domain-specific view ─────────────────────────────────────── */
        <DomainDashboard view={activeView} data={domainData[activeView]} />
      )}

      {/* ── [5] CLOUD ACCOUNT HEALTH · Overview only — driven by active filter ── */}
      {activeView === 'overview' && (() => {
        /* ── Derived aggregates for "all tenants" summary view ── */
        const allAccounts = MOCK_TENANTS.flatMap(t => t.accounts);
        const totalAccounts  = allAccounts.length;
        const healthyAccounts = allAccounts.filter(a => a.status === 'healthy').length;
        const scanOkAccounts  = allAccounts.filter(a => a.scanState === 'ok').length;
        const credIssueAccounts = allAccounts.filter(a => a.credentialStatus !== 'valid').length;
        const totalResources  = allAccounts.reduce((s, a) => s + (a.resources || 0), 0);

        /* Per-tenant aggregate for tenant-summary rows */
        const tenantRows = MOCK_TENANTS.map(t => {
          const accs = t.accounts;
          const healthy   = accs.filter(a => a.status === 'healthy').length;
          const scanOk    = accs.filter(a => a.scanState === 'ok').length;
          const credOk    = accs.filter(a => a.credentialStatus === 'valid').length;
          const credExp   = accs.filter(a => a.credentialStatus === 'expiring').length;
          const credBad   = accs.filter(a => a.credentialStatus === 'expired').length;
          const lastScanArr = accs.map(a => a.lastScan).filter(Boolean);
          const lastScan = lastScanArr[0] ?? '—';
          const hasIssue = healthy < accs.length || scanOk < accs.length || credBad > 0;
          return { ...t, healthy, scanOk, credOk, credExp, credBad, lastScan, hasIssue, accs };
        });

        /* ── What to render based on active filter ── */
        const isAllTenants  = selectedTenantId === 'all';
        const isSingleAccount = !!activeAccount;

        /* Header context badge */
        const filterBadge = isSingleAccount
          ? `${activeTenant.name}  /  ${activeAccount.name}`
          : activeTenant
            ? activeTenant.name
            : `All Tenants (${MOCK_TENANTS.length})`;

        return (
          <div className="rounded-xl border overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>

            {/* ── Header ── */}
            <div className="px-5 py-3 border-b flex items-center justify-between gap-3"
              style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
              <div className="flex items-center gap-2 min-w-0">
                <Server className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--accent-primary)' }} />
                <span className="text-xs font-bold tracking-widest uppercase" style={{ color: 'var(--accent-primary)' }}>
                  CLOUD ACCOUNT HEALTH
                </span>
                <span className="text-xs mx-0.5" style={{ color: 'var(--border-primary)' }}>·</span>
                {/* Active filter context — clicking clears filter */}
                <button
                  onClick={() => { if (!isAllTenants) { setSelectedTenantId('all'); setSelectedAccountId('all'); } }}
                  className="flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded transition-colors"
                  style={{
                    backgroundColor: isAllTenants ? 'var(--bg-tertiary)' : '#8b5cf620',
                    color: isAllTenants ? 'var(--text-muted)' : '#8b5cf6',
                    cursor: isAllTenants ? 'default' : 'pointer',
                  }}>
                  {filterBadge}
                  {!isAllTenants && <span style={{ fontSize: '10px', opacity: 0.6 }}>× clear</span>}
                </button>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                {/* Summary stats in header */}
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  <span className="font-semibold" style={{ color: healthyAccounts === totalAccounts ? '#22c55e' : '#f59e0b' }}>
                    {healthyAccounts}/{totalAccounts}
                  </span> healthy
                </span>
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  <span className="font-semibold" style={{ color: credIssueAccounts > 0 ? '#f59e0b' : '#22c55e' }}>
                    {credIssueAccounts > 0 ? `${credIssueAccounts} cred issues` : 'Creds OK'}
                  </span>
                </span>
                <Link href="/onboarding" className="text-xs font-semibold" style={{ color: 'var(--accent-primary)' }}>
                  Manage →
                </Link>
              </div>
            </div>

            {/* ── Body ── */}
            {isAllTenants ? (
              /* ══ ALL TENANTS: one summary row per tenant ══ */
              <div className="divide-y" style={{ borderColor: 'var(--border-primary)' }}>
                {tenantRows.map(tr => (
                  <div key={tr.id}
                    className="flex items-center gap-4 px-5 py-3.5 hover:bg-white/[0.02] transition-colors">

                    {/* Tenant name + issue indicator */}
                    <div className="flex items-center gap-2 w-40 flex-shrink-0 min-w-0">
                      <div className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                        style={{ backgroundColor: tr.hasIssue ? '#f59e0b' : '#22c55e' }} />
                      <span className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>{tr.name}</span>
                    </div>

                    {/* Account count */}
                    <div className="text-center flex-shrink-0" style={{ width: 72 }}>
                      <div className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
                        {tr.healthy}/{tr.accs.length}
                      </div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Accounts OK</div>
                    </div>

                    {/* Scan status */}
                    <div className="text-center flex-shrink-0" style={{ width: 80 }}>
                      <div className="text-sm font-bold"
                        style={{ color: tr.scanOk === tr.accs.length ? '#22c55e' : '#f59e0b' }}>
                        {tr.scanOk}/{tr.accs.length}
                      </div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Scans OK</div>
                    </div>

                    {/* Credential status */}
                    <div className="text-center flex-shrink-0" style={{ width: 84 }}>
                      {tr.credBad > 0 ? (
                        <div className="text-xs font-bold px-1.5 py-0.5 rounded inline-block"
                          style={{ backgroundColor: '#ef444420', color: '#ef4444' }}>{tr.credBad} expired</div>
                      ) : tr.credExp > 0 ? (
                        <div className="text-xs font-bold px-1.5 py-0.5 rounded inline-block"
                          style={{ backgroundColor: '#f59e0b20', color: '#f59e0b' }}>{tr.credExp} expiring</div>
                      ) : (
                        <div className="text-xs font-bold px-1.5 py-0.5 rounded inline-block"
                          style={{ backgroundColor: '#22c55e20', color: '#22c55e' }}>Creds OK</div>
                      )}
                      <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>Credentials</div>
                    </div>

                    {/* Provider badges */}
                    <div className="flex items-center gap-1.5 flex-1 min-w-0">
                      {[...new Set(tr.accs.map(a => a.provider))].map(p => (
                        <span key={p} className="text-xs font-semibold px-2 py-0.5 rounded uppercase"
                          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)', fontSize: '9px', letterSpacing: '0.06em' }}>
                          {p}
                        </span>
                      ))}
                      <span className="text-xs ml-1" style={{ color: 'var(--text-muted)' }}>
                        Last scan: {tr.lastScan}
                      </span>
                    </div>

                    {/* Drill-in → sets the tenant filter */}
                    <button
                      onClick={() => { setSelectedTenantId(tr.id); setSelectedAccountId('all'); }}
                      className="flex items-center gap-1 text-xs font-semibold px-3 py-1.5 rounded-lg border flex-shrink-0 transition-colors hover:border-opacity-80"
                      style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)', backgroundColor: 'var(--bg-secondary)' }}>
                      View accounts
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                ))}
              </div>
            ) : isSingleAccount ? (
              /* ══ SINGLE ACCOUNT: full detail card ══ */
              <div className="p-4">
                <CloudAccountCard account={activeAccount} />
              </div>
            ) : (
              /* ══ SINGLE TENANT: all accounts as full cards ══ */
              <div className="p-4">
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                  {displayAccounts.map(acc => (
                    <CloudAccountCard key={acc.id} account={acc} />
                  ))}
                </div>
              </div>
            )}

            {/* ── Footer ── */}
            <div className="px-5 py-2.5 border-t flex items-center gap-4 flex-wrap"
              style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                <span className="font-semibold" style={{ color: 'var(--text-secondary)' }}>
                  {totalResources.toLocaleString()}
                </span> total resources across {totalAccounts} accounts
              </span>
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>·</span>
              <span className="text-xs" style={{ color: scanOkAccounts === totalAccounts ? '#22c55e' : '#f59e0b' }}>
                {scanOkAccounts}/{totalAccounts} scans OK
              </span>
              {!isAllTenants && (
                <button
                  onClick={() => { setSelectedTenantId('all'); setSelectedAccountId('all'); }}
                  className="ml-auto text-xs px-2 py-1 rounded border transition-colors hover:opacity-80"
                  style={{ borderColor: 'var(--border-primary)', color: 'var(--text-muted)' }}>
                  ← All tenants
                </button>
              )}
            </div>
          </div>
        );
      })()}

    </div>
  );
}
