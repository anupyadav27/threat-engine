'use client';

import { useEffect, useState, useMemo, useRef } from 'react';
import {
  ChevronRight, AlertTriangle, Globe, ArrowRight, RotateCcw,
  ShieldAlert, Network, Target, Shield, Zap, Bug, Lock,
  Database, Server, Cloud, Key, Cpu, HardDrive, Box,
  GitBranch, Activity, Layers,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import MetricStrip from '@/components/shared/MetricStrip';
import SeverityBadge from '@/components/shared/SeverityBadge';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';
import { useGlobalFilter } from '@/lib/global-filter-context';

// ── Severity + color maps ─────────────────────────────────────────────────────

const SEV_COLOR = {
  critical: '#ef4444', high: '#f97316',
  medium: '#eab308', low: '#22c55e', info: '#64748b',
};

const CHAIN_LABELS = {
  internet_to_data: 'Internet → Data',
  internet_to_data_access: 'Internet → Data Access',
  internet_to_secrets: 'Internet → Secrets',
  internet_to_compute: 'Internet → Compute',
  internet_to_identity: 'Internet → Identity',
  internet_to_privilege_escalation: 'Internet → Priv Esc',
  internet_to_code_execution: 'Internet → Code Exec',
  internet_to_lateral_movement: 'Internet → Lateral',
  internet_to_generic: 'Internet → Resource',
  internal_secrets: 'Internal → Secrets',
  internal_data: 'Internal → Data',
  internal_data_access: 'Internal → Data Access',
  internal_identity: 'Internal → Identity',
  internal_privilege_escalation: 'Privilege Escalation',
  internal_code_execution: 'Code Execution',
  internal_lateral_movement: 'Lateral Movement',
  internal_compute: 'Internal → Compute',
  internal_generic: 'Internal Path',
};

const CHAIN_COLORS = {
  internet_to_data: '#ef4444', internet_to_data_access: '#ef4444',
  internet_to_secrets: '#a855f7', internet_to_compute: '#f97316',
  internet_to_identity: '#3b82f6', internet_to_privilege_escalation: '#ec4899',
  internet_to_code_execution: '#ef4444', internet_to_lateral_movement: '#f97316',
  internet_to_generic: '#64748b', internal_secrets: '#a855f7',
  internal_data: '#22c55e', internal_data_access: '#22c55e',
  internal_identity: '#3b82f6', internal_privilege_escalation: '#ec4899',
  internal_code_execution: '#ef4444', internal_lateral_movement: '#f97316',
  internal_compute: '#f97316', internal_generic: '#64748b',
};

// ── Resource type → Lucide icon + color ──────────────────────────────────────

const TYPE_CONFIG = {
  internet: { Icon: Globe, color: '#ef4444', label: 'Internet' },
  's3': { Icon: Database, color: '#22c55e', label: 'S3' },
  'ec2': { Icon: Server, color: '#f97316', label: 'EC2' },
  'lambda': { Icon: Cpu, color: '#f59e0b', label: 'Lambda' },
  'iam': { Icon: Key, color: '#a855f7', label: 'IAM' },
  'role': { Icon: Key, color: '#a855f7', label: 'IAM Role' },
  'rds': { Icon: Database, color: '#3b82f6', label: 'RDS' },
  'dynamodb': { Icon: Database, color: '#06b6d4', label: 'DynamoDB' },
  'secretsmanager': { Icon: Lock, color: '#8b5cf6', label: 'Secrets' },
  'ssm': { Icon: Lock, color: '#7c3aed', label: 'SSM' },
  'kms': { Icon: Shield, color: '#6d28d9', label: 'KMS' },
  'sqs': { Icon: Layers, color: '#0ea5e9', label: 'SQS' },
  'sns': { Icon: Activity, color: '#0284c7', label: 'SNS' },
  'security.group': { Icon: Shield, color: '#64748b', label: 'Sec Group' },
  'vpc': { Icon: Network, color: '#0ea5e9', label: 'VPC' },
  'eks': { Icon: Box, color: '#3b82f6', label: 'EKS' },
  'ecs': { Icon: Box, color: '#6366f1', label: 'ECS' },
  'compute': { Icon: Server, color: '#f97316', label: 'Compute' },
  'storage': { Icon: HardDrive, color: '#22c55e', label: 'Storage' },
  'data': { Icon: Database, color: '#22c55e', label: 'Data' },
  'secrets': { Icon: Lock, color: '#a855f7', label: 'Secrets' },
  'identity': { Icon: Key, color: '#a855f7', label: 'Identity' },
  'network': { Icon: Network, color: '#3b82f6', label: 'Network' },
};

function getTypeConfig(typeStr) {
  const t = (typeStr || '').toLowerCase();
  for (const [key, cfg] of Object.entries(TYPE_CONFIG)) {
    if (t.includes(key)) return cfg;
  }
  return { Icon: Cloud, color: '#64748b', label: (typeStr || '').split('.').pop() || 'Resource' };
}

function scoreColor(s) {
  return s >= 80 ? '#ef4444' : s >= 60 ? '#f97316' : s >= 40 ? '#eab308' : '#22c55e';
}

// ── Build flow nodes from path data ──────────────────────────────────────────

function buildFlowNodes(path) {
  // Prefer enriched nodes array (from Neo4j) over raw steps
  if (path.nodes && path.nodes.length > 0) {
    return path.nodes.map((n, i) => ({
      id: `n-${i}`,
      label: n.label || (n.fullLabel || '').split('/').pop().split(':').pop(),
      fullLabel: n.fullLabel || n.label,
      type: n.type || (i === 0 && path.isInternetReachable ? 'internet' : 'compute'),
      riskScore: n.riskScore || 0,
      findingCount: n.findingCount || 0,
      threatCount: n.threatCount || 0,
      threatSeverity: n.threatSeverity,
      findings: n.findings || [],
      threats: n.threats || [],
      isFirst: i === 0,
      isLast: i === path.nodes.length - 1,
    }));
  }

  // Fallback: derive from steps
  const steps = path.steps || [];
  if (steps.length === 0) return [];

  const rawNodes = [
    { label: steps[0]?.from || path.entryPointName || 'Entry', type: 'internet', isFirst: true },
    ...steps.map((s, i) => ({
      label: s.to || '',
      type: s.category || 'compute',
      riskScore: s.toNodeRiskScore || 0,
      findingCount: s.toNodeFindingCount || 0,
      threatCount: s.toNodeThreatCount || 0,
      findings: s.toNodeFindings || [],
      threats: s.toNodeThreats || [],
      isLast: i === steps.length - 1,
    })),
  ];

  return rawNodes.map((n, i) => ({
    id: `n-${i}`,
    label: (n.label || '').split('/').pop().split(':').pop().slice(0, 18),
    fullLabel: n.label,
    type: n.type,
    riskScore: n.riskScore || 0,
    findingCount: n.findingCount || 0,
    threatCount: n.threatCount || 0,
    threatSeverity: n.threatSeverity,
    findings: n.findings || [],
    threats: n.threats || [],
    isFirst: i === 0,
    isLast: i === rawNodes.length - 1,
  }));
}

function buildFlowEdges(path, nodeCount) {
  const steps = path.steps || [];
  return steps.slice(0, nodeCount - 1).map((s, i) => ({
    id: `e-${i}`,
    relationship: (s.relationship || '').replace(/_/g, ' '),
    category: s.category || '',
  }));
}

// ── Node Detail Tooltip ───────────────────────────────────────────────────────

function NodeTooltip({ node, anchorRect }) {
  const cfg = getTypeConfig(node.type);
  const sevColor = node.riskScore >= 80 ? '#ef4444'
    : node.riskScore >= 60 ? '#f97316'
    : node.riskScore >= 40 ? '#eab308' : null;

  const tooltipW = 240;
  const left = Math.max(8, Math.min(
    anchorRect.left + anchorRect.width / 2 - tooltipW / 2,
    window.innerWidth - tooltipW - 8,
  ));

  return (
    <div style={{ position: 'fixed', left, top: anchorRect.top - 8, transform: 'translateY(-100%)', width: tooltipW, zIndex: 9999, pointerEvents: 'none' }}>
      <div style={{ display: 'flex', justifyContent: 'center' }}>
        <div style={{ width: 0, height: 0, borderLeft: '5px solid transparent', borderRight: '5px solid transparent', borderTop: `5px solid ${cfg.color}40`, marginBottom: -1 }} />
      </div>
      <div className="rounded-xl border overflow-hidden text-[11px]"
        style={{ backgroundColor: '#0c111d', borderColor: `${cfg.color}40`, boxShadow: `0 12px 40px rgba(0,0,0,0.7), 0 0 0 1px ${cfg.color}20` }}>

        {/* Header */}
        <div className="px-3 py-2.5 flex items-center gap-2" style={{ backgroundColor: `${cfg.color}10`, borderBottom: `1px solid ${cfg.color}25` }}>
          <div className="w-6 h-6 rounded-md flex items-center justify-center flex-shrink-0"
            style={{ backgroundColor: `${cfg.color}20` }}>
            <cfg.Icon style={{ width: 13, height: 13, color: cfg.color }} />
          </div>
          <div className="min-w-0">
            <div className="font-semibold truncate" style={{ color: cfg.color }}>{cfg.label}</div>
          </div>
          {node.riskScore > 0 && (
            <span className="ml-auto font-bold text-[10px] px-1.5 py-0.5 rounded flex-shrink-0"
              style={{ backgroundColor: `${sevColor || cfg.color}20`, color: sevColor || cfg.color }}>
              Risk {node.riskScore}
            </span>
          )}
        </div>

        <div className="px-3 py-2.5 flex flex-col gap-2">
          {/* Full name */}
          <p className="break-all leading-snug text-[10px]" style={{ color: 'rgba(255,255,255,0.85)' }}>
            {node.fullLabel || node.label}
          </p>

          {/* Findings */}
          {node.findingCount > 0 && (
            <div>
              <div className="flex items-center gap-1 mb-1">
                <Bug style={{ width: 9, height: 9, color: '#f97316' }} />
                <span className="font-semibold" style={{ color: '#f97316' }}>{node.findingCount} Misconfig{node.findingCount !== 1 ? 's' : ''}</span>
              </div>
              {(node.findings || []).slice(0, 3).map((f, i) => (
                <div key={i} className="flex items-start gap-1.5 mb-0.5">
                  <div className="w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0"
                    style={{ backgroundColor: SEV_COLOR[f.severity] || '#f97316' }} />
                  <span className="text-[9px] leading-snug" style={{ color: 'rgba(255,255,255,0.6)' }}>
                    {(f.rule_name || f.finding_id || '').slice(0, 50)}
                  </span>
                </div>
              ))}
              {node.findingCount > 3 && (
                <span className="text-[9px]" style={{ color: 'rgba(255,255,255,0.3)' }}>
                  +{node.findingCount - 3} more
                </span>
              )}
            </div>
          )}

          {/* Threats */}
          {node.threatCount > 0 && (
            <div>
              <div className="flex items-center gap-1 mb-1">
                <Zap style={{ width: 9, height: 9, color: '#ef4444' }} />
                <span className="font-semibold" style={{ color: '#ef4444' }}>
                  {node.threatCount} Active Threat{node.threatCount !== 1 ? 's' : ''}
                  {node.threatSeverity && (
                    <span className="ml-1 font-normal capitalize text-[9px] px-1 py-0.5 rounded"
                      style={{ backgroundColor: `${SEV_COLOR[node.threatSeverity] || '#ef4444'}20`, color: SEV_COLOR[node.threatSeverity] || '#ef4444' }}>
                      {node.threatSeverity}
                    </span>
                  )}
                </span>
              </div>
              {(node.threats || []).slice(0, 2).map((t, i) => (
                <div key={i} className="flex items-start gap-1.5 mb-0.5">
                  <div className="w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0"
                    style={{ backgroundColor: SEV_COLOR[t.severity] || '#ef4444' }} />
                  <span className="text-[9px] leading-snug" style={{ color: 'rgba(255,255,255,0.6)' }}>
                    {(t.rule_name || t.technique || '').slice(0, 50)}
                  </span>
                </div>
              ))}
            </div>
          )}

          {!node.findingCount && !node.threatCount && (
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: '#64748b' }} />
                <span className="text-[9px]" style={{ color: 'rgba(255,255,255,0.45)' }}>No active findings</span>
              </div>
              <p className="text-[9px] leading-snug" style={{ color: 'rgba(255,255,255,0.3)' }}>
                This node is part of the attack route due to its <strong style={{ color: 'rgba(255,255,255,0.5)' }}>structural topology</strong> — the access relationship exists regardless of findings.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Flow Node Card ────────────────────────────────────────────────────────────

function FlowNode({ node }) {
  const [hovered, setHovered] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [anchorRect, setAnchorRect] = useState(null);
  const ref = useRef(null);

  const cfg = getTypeConfig(node.type);
  const riskSev = node.riskScore >= 80 ? 'critical'
    : node.riskScore >= 60 ? 'high'
    : node.riskScore >= 40 ? 'medium'
    : node.riskScore > 0 ? 'low' : null;
  const sevColor = riskSev ? SEV_COLOR[riskSev] : null;
  const borderColor = sevColor || `${cfg.color}50`;

  const show = () => {
    if (ref.current) setAnchorRect(ref.current.getBoundingClientRect());
    setHovered(true);
  };
  const pin = (e) => {
    e.stopPropagation();
    if (ref.current) setAnchorRect(ref.current.getBoundingClientRect());
    setPinned(v => !v);
    setHovered(true);
  };

  return (
    <>
      <div
        ref={ref}
        onClick={pin}
        onMouseEnter={show}
        onMouseLeave={() => { if (!pinned) setHovered(false); }}
        className="flex flex-col rounded-xl flex-shrink-0 cursor-pointer transition-all duration-150"
        style={{
          width: 110,
          backgroundColor: node.isFirst && node.type === 'internet'
            ? 'rgba(239,68,68,0.07)'
            : sevColor ? `${sevColor}07` : `${cfg.color}07`,
          border: `1.5px solid ${pinned ? '#60a5fa' : borderColor}`,
          boxShadow: pinned ? '0 0 0 2px #3b82f440'
            : sevColor ? `0 0 0 1px ${sevColor}18` : 'none',
          overflow: 'hidden',
        }}
      >
        {/* Severity accent bar */}
        <div className="h-0.5 w-full" style={{ backgroundColor: sevColor || cfg.color }} />

        <div className="flex flex-col items-center gap-2 px-2.5 pt-3 pb-2.5">
          {/* Icon circle */}
          <div className="relative">
            {node.threatCount > 0 && (
              <div className="absolute inset-0 rounded-full animate-ping"
                style={{ backgroundColor: SEV_COLOR[node.threatSeverity] || '#ef4444', opacity: 0.25, margin: -4 }} />
            )}
            <div className="w-10 h-10 rounded-xl flex items-center justify-center"
              style={{ backgroundColor: `${cfg.color}15`, border: `1.5px solid ${cfg.color}45` }}>
              <cfg.Icon style={{ width: 18, height: 18, color: cfg.color }} />
            </div>
            {/* Risk score badge */}
            {node.riskScore > 0 && (
              <div className="absolute -top-1.5 -right-1.5 w-5 h-5 rounded-full flex items-center justify-center font-bold text-white"
                style={{ backgroundColor: sevColor, fontSize: 8 }}>
                {node.riskScore}
              </div>
            )}
          </div>

          {/* Type label */}
          <span className="text-[9px] font-bold px-2 py-0.5 rounded-full tracking-wide"
            style={{ backgroundColor: `${cfg.color}18`, color: cfg.color }}>
            {cfg.label}
          </span>

          {/* Resource name */}
          <span className="text-[9px] font-medium text-center leading-tight w-full"
            style={{ color: 'rgba(255,255,255,0.85)', wordBreak: 'break-all' }}
            title={node.fullLabel}>
            {(node.label || '').slice(0, 16)}
          </span>

          {/* Finding + threat tags — or structural risk indicator */}
          <div className="flex items-center gap-1 flex-wrap justify-center">
            {node.findingCount > 0 && (
              <span className="flex items-center gap-0.5 text-[8px] font-semibold px-1.5 py-0.5 rounded-md"
                style={{ backgroundColor: 'rgba(249,115,22,0.15)', color: '#f97316', border: '1px solid rgba(249,115,22,0.3)' }}>
                <Bug style={{ width: 7, height: 7 }} />
                {node.findingCount}
              </span>
            )}
            {node.threatCount > 0 && (
              <span className="flex items-center gap-0.5 text-[8px] font-semibold px-1.5 py-0.5 rounded-md"
                style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}>
                <Zap style={{ width: 7, height: 7 }} />
                {node.threatCount}
              </span>
            )}
            {!node.findingCount && !node.threatCount && (
              <span className="flex items-center gap-0.5 text-[7px] font-medium px-1.5 py-0.5 rounded-md"
                title="This node is in the path due to topology — access relationship exists, no active findings"
                style={{ backgroundColor: 'rgba(100,116,139,0.15)', color: '#94a3b8', border: '1px solid rgba(100,116,139,0.25)' }}>
                <GitBranch style={{ width: 7, height: 7 }} />
                route
              </span>
            )}
          </div>
        </div>
      </div>

      {(hovered || pinned) && anchorRect && (
        <NodeTooltip node={node} anchorRect={anchorRect} />
      )}
    </>
  );
}

// ── Flow Edge Connector ───────────────────────────────────────────────────────

function FlowEdge({ edge }) {
  const relLabel = (edge.relationship || '').toUpperCase();
  const edgeColor = relLabel.includes('ASSUME') ? '#a855f7'
    : relLabel.includes('EXPOS') ? '#ef4444'
    : relLabel.includes('ACCESS') ? '#3b82f6'
    : relLabel.includes('STORE') ? '#22c55e'
    : relLabel.includes('CONNECT') ? '#0ea5e9'
    : relLabel.includes('RUN') ? '#f97316'
    : '#475569';

  return (
    <div className="flex flex-col items-center justify-center flex-shrink-0" style={{ width: 48, gap: 2 }}>
      {edge.relationship && (
        <span className="text-[7px] font-bold text-center uppercase tracking-wide leading-none"
          style={{ color: edgeColor, maxWidth: 46, wordBreak: 'break-word' }}>
          {edge.relationship.slice(0, 12)}
        </span>
      )}
      <div className="flex items-center w-full">
        <div className="flex-1" style={{ height: 1.5, backgroundColor: edgeColor, opacity: 0.6 }} />
        <svg width="8" height="8" viewBox="0 0 8 8" style={{ flexShrink: 0 }}>
          <polygon points="0,0 8,4 0,8" fill={edgeColor} opacity={0.7} />
        </svg>
      </div>
    </div>
  );
}

// ── Attack Path Card ──────────────────────────────────────────────────────────

function AttackPathCard({ path }) {
  const flowNodes = useMemo(() => buildFlowNodes(path), [path]);
  const flowEdges = useMemo(() => buildFlowEdges(path, flowNodes.length), [path, flowNodes.length]);

  const sevColor = SEV_COLOR[path.severity] || '#64748b';
  const chainColor = CHAIN_COLORS[path.chainType] || '#64748b';
  const chainLabel = CHAIN_LABELS[path.chainType] || (path.chainType || '').replace(/_/g, ' ');
  const techniques = path.mitreTechniques || [];

  // Per-path total findings + threats (sum across nodes)
  const totalFindings = flowNodes.reduce((s, n) => s + (n.findingCount || 0), 0);
  const totalThreats = flowNodes.reduce((s, n) => s + (n.threatCount || 0), 0);

  return (
    <div className="rounded-xl border overflow-hidden"
      style={{
        backgroundColor: 'var(--bg-card)',
        borderColor: 'rgba(255,255,255,0.07)',
        borderLeftWidth: 3,
        borderLeftColor: sevColor,
      }}>

      {/* Header */}
      <div className="px-4 py-3 flex items-center gap-3 border-b"
        style={{ borderColor: 'rgba(255,255,255,0.06)', backgroundColor: `${sevColor}06` }}>

        <SeverityBadge severity={path.severity} />

        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wide flex-shrink-0"
          style={{ backgroundColor: `${chainColor}18`, color: chainColor }}>
          {chainLabel}
        </span>

        {path.isInternetReachable && (
          <span className="flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded-full flex-shrink-0"
            style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#ef4444' }}>
            <Globe style={{ width: 9, height: 9 }} /> Internet
          </span>
        )}

        {/* Aggregate badges */}
        <div className="flex items-center gap-1.5 ml-1">
          {totalFindings > 0 && (
            <span className="flex items-center gap-1 text-[9px] font-semibold px-1.5 py-0.5 rounded-md"
              style={{ backgroundColor: 'rgba(249,115,22,0.12)', color: '#f97316', border: '1px solid rgba(249,115,22,0.2)' }}>
              <Bug style={{ width: 8, height: 8 }} /> {totalFindings} misconfig{totalFindings !== 1 ? 's' : ''}
            </span>
          )}
          {totalThreats > 0 && (
            <span className="flex items-center gap-1 text-[9px] font-semibold px-1.5 py-0.5 rounded-md"
              style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}>
              <Zap style={{ width: 8, height: 8 }} /> {totalThreats} threat{totalThreats !== 1 ? 's' : ''}
            </span>
          )}
          {totalFindings === 0 && totalThreats === 0 && (
            <span
              className="flex items-center gap-1 text-[9px] font-medium px-1.5 py-0.5 rounded-md"
              title="This path is a structural topology risk — the access relationships exist but no active findings or threats are detected on any node."
              style={{ backgroundColor: 'rgba(100,116,139,0.12)', color: '#94a3b8', border: '1px solid rgba(100,116,139,0.2)' }}>
              <GitBranch style={{ width: 8, height: 8 }} /> Structural risk
            </span>
          )}
        </div>

        {/* Right side */}
        <div className="ml-auto flex items-center gap-3 flex-shrink-0">
          <div className="flex items-center gap-1">
            <span className="text-[10px]" style={{ color: 'rgba(255,255,255,0.35)' }}>Score</span>
            <span className="text-lg font-bold tabular-nums leading-none"
              style={{ color: scoreColor(path.pathScore || 0) }}>
              {path.pathScore || 0}
            </span>
          </div>
          <div className="flex items-center gap-1 text-[10px]" style={{ color: 'rgba(255,255,255,0.35)' }}>
            <Target style={{ width: 10, height: 10 }} />
            {path.depth || flowNodes.length - 1} hop{path.depth !== 1 ? 's' : ''}
          </div>
        </div>
      </div>

      {/* Node flow */}
      <div className="px-4 py-4">
        {flowNodes.length > 0 ? (
          <div className="flex items-center overflow-x-auto pb-1" style={{ gap: 0 }}>
            {flowNodes.map((node, i) => (
              <span key={node.id} className="flex items-center">
                <FlowNode node={node} />
                {i < flowEdges.length && <FlowEdge edge={flowEdges[i]} />}
              </span>
            ))}
          </div>
        ) : (
          <div className="flex items-center gap-3 py-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
            <span className="font-medium" style={{ color: 'var(--text-primary)' }}>
              {path.entryPointName || 'Entry'}
            </span>
            <ArrowRight className="w-4 h-4 opacity-40" />
            <span className="font-medium" style={{ color: 'var(--text-primary)' }}>
              {path.targetName || 'Target'}
            </span>
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center flex-wrap gap-x-4 gap-y-1 mt-3 pt-3 border-t text-[10px]"
          style={{ borderColor: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.35)' }}>
          {path.provider && path.provider !== '--' && <span>{path.provider}</span>}
          {path.accountId && <span className="font-mono">{path.accountId.slice(0, 8)}…</span>}
          {path.region && <span>{path.region}</span>}
          {path.resourceType && <span>{path.resourceType}</span>}
          {path.source === 'neo4j' && (
            <span className="flex items-center gap-1 px-1.5 py-0.5 rounded"
              style={{ backgroundColor: 'rgba(99,102,241,0.12)', color: '#818cf8', border: '1px solid rgba(99,102,241,0.2)' }}>
              <GitBranch style={{ width: 8, height: 8 }} /> Graph
            </span>
          )}
          {techniques.length > 0 && (
            <div className="flex items-center gap-1.5 ml-auto flex-wrap">
              <span className="font-bold uppercase tracking-wide text-[9px]" style={{ color: 'rgba(255,255,255,0.25)' }}>MITRE</span>
              {techniques.map(t => (
                <span key={t} className="px-1.5 py-0.5 rounded font-bold font-mono text-[9px]"
                  style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)' }}>
                  {t}
                </span>
              ))}
            </div>
          )}
          {path.detectionId && (
            <a href={`/ui/threats/${path.detectionId}`}
              className="inline-flex items-center gap-1 hover:opacity-75 ml-auto"
              style={{ color: 'var(--accent-primary)' }}>
              View Detection <ArrowRight style={{ width: 9, height: 9 }} />
            </a>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Chain Type Filter Pills ───────────────────────────────────────────────────

function ChainTypePills({ chainTypes, activeType, onSelect }) {
  const entries = Object.entries(chainTypes || {}).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((s, [, v]) => s + v, 0);
  return (
    <div className="flex items-center gap-2 overflow-x-auto pb-1 flex-wrap">
      <button onClick={() => onSelect(null)}
        className="text-xs font-medium px-3 py-1.5 rounded-full border whitespace-nowrap"
        style={{
          backgroundColor: !activeType ? 'var(--accent-primary)' : 'var(--bg-secondary)',
          color: !activeType ? '#fff' : 'var(--text-secondary)',
          borderColor: !activeType ? 'var(--accent-primary)' : 'var(--border-primary)',
        }}>
        All ({total})
      </button>
      {entries.map(([type, count]) => {
        const col = CHAIN_COLORS[type] || '#64748b';
        const active = activeType === type;
        return (
          <button key={type} onClick={() => onSelect(active ? null : type)}
            className="text-xs font-medium px-3 py-1.5 rounded-full border whitespace-nowrap transition-all"
            style={{
              backgroundColor: active ? `${col}20` : 'var(--bg-secondary)',
              color: active ? col : 'var(--text-secondary)',
              borderColor: active ? col : 'var(--border-primary)',
            }}>
            {CHAIN_LABELS[type] || type} ({count})
          </button>
        );
      })}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function AttackPathsPage() {
  const { account } = useGlobalFilter();
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState(null);
  const [data, setData]               = useState(null);
  const [activeChainType, setChain]   = useState(null);
  const [scoreFilter, setScoreFilter] = useState('all');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      const result = await fetchView('threats/attack-paths');
      if (cancelled) return;
      result?.error ? setError(result.error) : setData(result);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [account]);

  const kpi         = data?.kpi ?? {};
  const chainTypes  = data?.chainTypes ?? {};

  const attackPaths = useMemo(() => {
    let items = data?.attackPaths ?? [];
    if (activeChainType) items = items.filter(p => p.chainType === activeChainType);
    if (scoreFilter === 'critical') items = items.filter(p => p.severity === 'critical');
    else if (scoreFilter === 'high') items = items.filter(p => p.severity === 'high');
    else if (scoreFilter === 'medium') items = items.filter(p => p.severity === 'medium');
    return [...items].sort((a, b) => (b.pathScore ?? 0) - (a.pathScore ?? 0));
  }, [data, activeChainType, scoreFilter]);

  const metricGroups = useMemo(() => [{
    label: 'ATTACK PATHS', color: 'var(--accent-danger)',
    cells: [
      { label: 'TOTAL', value: kpi.total ?? 0, noTrend: true },
      { label: 'CRITICAL', value: kpi.critical ?? 0, valueColor: '#ef4444', noTrend: true,
        onClick: () => setScoreFilter(f => f === 'critical' ? 'all' : 'critical') },
      { label: 'HIGH', value: kpi.high ?? 0, valueColor: '#f97316', noTrend: true,
        onClick: () => setScoreFilter(f => f === 'high' ? 'all' : 'high') },
      { label: 'INTERNET EXPOSED', value: kpi.internetReachable ?? 0, valueColor: '#ef4444', noTrend: true },
    ],
  }], [kpi]);

  const hasFilter = activeChainType || scoreFilter !== 'all';

  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-center gap-2 text-xs mb-2" style={{ color: 'var(--text-muted)' }}>
          <a href="/ui/threats" className="hover:underline" style={{ color: 'var(--text-secondary)' }}>Threats</a>
          <ChevronRight className="w-3 h-3" />
          <span style={{ color: 'var(--text-primary)' }}>Attack Paths</span>
        </div>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Attack Paths</h1>
            <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
              Multi-step attack chains through your cloud infrastructure — entry to critical targets.
            </p>
          </div>
          {hasFilter && (
            <button onClick={() => { setChain(null); setScoreFilter('all'); }}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg border text-xs font-medium hover:opacity-80"
              style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
              <RotateCcw className="w-3.5 h-3.5" /> Reset Filters
            </button>
          )}
        </div>
      </div>

      <ThreatsSubNav />

      {loading && (
        <div className="space-y-4">
          <div className="h-[100px] rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
          <LoadingSkeleton rows={3} cols={4} />
        </div>
      )}

      {!loading && error && (
        <div className="rounded-xl p-5 border" style={{ backgroundColor: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.3)' }}>
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: '#ef4444' }} />
            <div>
              <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Failed to load attack paths</p>
              <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{error}</p>
            </div>
          </div>
        </div>
      )}

      {!loading && !error && (
        <>
          <MetricStrip groups={metricGroups} />

          {Object.keys(chainTypes).length > 0 && (
            <ChainTypePills chainTypes={chainTypes} activeType={activeChainType} onSelect={setChain} />
          )}

          {hasFilter && (
            <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
              Showing <strong style={{ color: 'var(--text-primary)' }}>{attackPaths.length}</strong> of {data?.attackPaths?.length ?? 0} paths
            </p>
          )}

          {attackPaths.length === 0 ? (
            <EmptyState
              icon={<Network className="w-12 h-12" />}
              title={hasFilter ? 'No paths match these filters' : 'No Attack Paths'}
              description={hasFilter
                ? 'Try adjusting the chain type or severity filter.'
                : 'No attack paths detected. Run a threat scan to analyze your infrastructure.'}
            />
          ) : (
            <div className="space-y-3">
              {attackPaths.map(path => (
                <AttackPathCard key={path.id} path={path} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
