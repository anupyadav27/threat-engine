'use client';

/**
 * NodeBox — single hop in the attack path canvas (accordion version).
 *
 * Copied from threats/attack-paths/NodeBox.jsx and extended with:
 *   onEdgeHoverStart / onEdgeHoverEnd passthrough props for edge tooltip.
 *
 * Props:
 *   node              {object}    — step from steps[]
 *   isFirst           {boolean}   — entry point node
 *   isLast            {boolean}   — crown jewel node
 *   onClick           {function}  — called with node_uid when clicked
 *   selected          {boolean}   — true when this node is the selected node
 *   onEdgeHoverStart  {function}  — passthrough: not used on node itself, surfaced for parent
 *   onEdgeHoverEnd    {function}  — passthrough
 */

import { useRef, useState } from 'react';
import {
  Globe, Database, Server, Key, Lock, Shield,
  Network, Box, Cpu, HardDrive, Cloud, Activity,
  Bug, Zap, AlertCircle,
} from 'lucide-react';

// ── Resource type → icon + color ─────────────────────────────────────────────

const TYPE_MAP = {
  internet:          { Icon: Globe,     color: '#ef4444', label: 'Internet' },
  ec2:               { Icon: Server,    color: '#f97316', label: 'EC2' },
  s3:                { Icon: Database,  color: '#22c55e', label: 'S3' },
  rds:               { Icon: Database,  color: '#3b82f6', label: 'RDS' },
  lambda:            { Icon: Cpu,       color: '#f59e0b', label: 'Lambda' },
  iam:               { Icon: Key,       color: '#a855f7', label: 'IAM' },
  role:              { Icon: Key,       color: '#a855f7', label: 'IAM Role' },
  secretsmanager:    { Icon: Lock,      color: '#8b5cf6', label: 'Secrets' },
  kms:               { Icon: Shield,    color: '#6d28d9', label: 'KMS' },
  eks:               { Icon: Box,       color: '#3b82f6', label: 'EKS' },
  vpc:               { Icon: Network,   color: '#0ea5e9', label: 'VPC' },
  compute:           { Icon: Server,    color: '#f97316', label: 'Compute' },
  storage:           { Icon: HardDrive, color: '#22c55e', label: 'Storage' },
  secrets:           { Icon: Lock,      color: '#a855f7', label: 'Secrets' },
  identity:          { Icon: Key,       color: '#a855f7', label: 'Identity' },
  network:           { Icon: Network,   color: '#3b82f6', label: 'Network' },
  data:              { Icon: Database,  color: '#22c55e', label: 'Data' },
};

function resolveType(typeStr) {
  const t = (typeStr || '').toLowerCase();
  for (const [key, cfg] of Object.entries(TYPE_MAP)) {
    if (t.includes(key)) return cfg;
  }
  return { Icon: Cloud, color: '#64748b', label: (typeStr || '').split('.').pop() || 'Resource' };
}

// ── Tooltip ───────────────────────────────────────────────────────────────────

function NodeTooltip({ node, anchorRef }) {
  const cfg = resolveType(node.node_type);
  const rect = anchorRef.current?.getBoundingClientRect?.() ?? {};
  const left = Math.max(4, Math.min(
    (rect.left ?? 0) + (rect.width ?? 0) / 2 - 120,
    (typeof window !== 'undefined' ? window.innerWidth : 1200) - 244,
  ));

  // Worst finding for tooltip body
  const misconfigCount = node.misconfigs?.length ?? node.misconfig_count ?? 0;
  const worstCve = node.cves?.length > 0
    ? [...node.cves].sort((a, b) => (b.epss ?? b.epss_score ?? 0) - (a.epss ?? a.epss_score ?? 0))[0]
    : null;
  const worstCveId   = worstCve ? (worstCve.cve_id ?? worstCve.title) : null;
  const worstCveEpss = worstCve ? (worstCve.epss ?? worstCve.epss_score ?? null) : null;
  const worstMisconfig = node.misconfigs?.length > 0 ? node.misconfigs[0] : null;

  return (
    <div
      style={{
        position: 'fixed',
        top: (rect.top ?? 0) - 8,
        left,
        transform: 'translateY(-100%)',
        width: 240,
        zIndex: 9999,
        pointerEvents: 'none',
      }}
    >
      <div
        className="rounded-xl border text-[11px] overflow-hidden"
        style={{
          backgroundColor: '#0c111d',
          borderColor: `${cfg.color}40`,
          boxShadow: `0 12px 40px rgba(0,0,0,0.7), 0 0 0 1px ${cfg.color}20`,
        }}
      >
        {/* Header */}
        <div
          className="px-3 py-2 flex items-center gap-2 border-b"
          style={{ backgroundColor: `${cfg.color}12`, borderColor: `${cfg.color}25` }}
        >
          <cfg.Icon style={{ width: 13, height: 13, color: cfg.color, flexShrink: 0 }} />
          <span className="font-semibold truncate flex-1" style={{ color: cfg.color }}>
            {cfg.label}
          </span>
          {misconfigCount > 0 && (
            <span
              className="flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded"
              style={{ backgroundColor: 'rgba(249,115,22,0.18)', color: '#f97316' }}
            >
              <Bug style={{ width: 8, height: 8 }} />{misconfigCount}
            </span>
          )}
          {node.cves && node.cves.length > 0 && (
            <span
              className="flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded"
              style={{ backgroundColor: 'rgba(239,68,68,0.18)', color: '#ef4444' }}
            >
              <AlertCircle style={{ width: 8, height: 8 }} />{node.cves.length}
            </span>
          )}
        </div>

        {/* Body */}
        <div className="px-3 py-2.5 space-y-1.5">
          {/* Truncated UID */}
          <p
            className="break-all leading-snug text-[10px] font-mono"
            style={{ color: 'rgba(255,255,255,0.75)' }}
          >
            {(node.node_uid || node.node_name || '').slice(-40)}
          </p>

          {/* Worst finding */}
          {worstCve && (
            <p className="text-[9px]" style={{ color: '#f87171' }}>
              {worstCveId} — EPSS {worstCveEpss != null ? `${(worstCveEpss * 100).toFixed(1)}%` : '—'}
            </p>
          )}
          {!worstCve && worstMisconfig && (
            <p className="text-[9px]" style={{ color: 'rgba(255,255,255,0.5)' }}>
              {worstMisconfig.title || worstMisconfig.rule_id}
            </p>
          )}

          {node.traversal_reason && (
            <p className="text-[9px] italic" style={{ color: 'rgba(255,255,255,0.35)' }}>
              {node.traversal_reason.slice(0, 80)}
            </p>
          )}

          {node.cdr_actor_active && (
            <div
              className="flex items-center gap-1.5 text-[9px] font-bold animate-pulse"
              style={{ color: '#ef4444' }}
            >
              <Zap style={{ width: 9, height: 9 }} /> LIVE CDR threat active
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── NodeBox ───────────────────────────────────────────────────────────────────

export default function NodeBox({
  node,
  isFirst,
  isLast,
  onClick,
  selected,
  // passthrough props — not used by node itself
  onEdgeHoverStart,
  onEdgeHoverEnd,
}) {
  const [showTip, setShowTip] = useState(false);
  const ref = useRef(null);

  const cfg = resolveType(node.node_type);
  const misconfigCount = node.misconfigs?.length ?? node.misconfig_count ?? 0;

  const SEV_ORDER     = { critical: 0, high: 1, medium: 2, low: 3 };
  const SEV_COLOR_MAP = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#6b7280' };
  const RISK_SCORE_MAP = { critical: 90, high: 70, medium: 50, low: 30 };
  const derivedSeverity = (() => {
    const sevs = [
      ...(node.misconfigs || []).map(m => m.severity),
      ...(node.cves || []).map(c => c.severity),
    ].filter(Boolean).sort((a, b) => (SEV_ORDER[a] ?? 9) - (SEV_ORDER[b] ?? 9));
    return sevs[0] || null;
  })();
  const severityAccentColor = derivedSeverity ? SEV_COLOR_MAP[derivedSeverity] : cfg.color;
  const nodeRiskScore = derivedSeverity ? RISK_SCORE_MAP[derivedSeverity] : null;

  const crownBorder = isLast
    ? `2px solid ${cfg.color}`
    : `1.5px solid ${cfg.color}50`;

  const bgAlpha = selected
    ? `${cfg.color}18`
    : node.cdr_actor_active
    ? 'rgba(239,68,68,0.07)'
    : isFirst && (node.node_type || '').toLowerCase().includes('internet')
    ? 'rgba(239,68,68,0.05)'
    : `${cfg.color}06`;

  const label = (node.node_name || node.node_uid || '').split('/').pop().split(':').pop();

  return (
    <>
      <button
        ref={ref}
        onClick={() => onClick && onClick(node)}
        onMouseEnter={() => setShowTip(true)}
        onMouseLeave={() => setShowTip(false)}
        className="flex flex-col items-center rounded-xl flex-shrink-0 transition-all duration-150 focus:outline-none"
        style={{
          width: 100,
          backgroundColor: bgAlpha,
          border: crownBorder,
          boxShadow: selected
            ? `0 0 0 2px ${cfg.color}60`
            : node.cdr_actor_active
            ? '0 0 0 2px rgba(239,68,68,0.25)'
            : 'none',
        }}
        title={node.node_uid}
      >
        {/* Severity accent bar — color reflects worst finding severity, falls back to resource-type color */}
        <div className="h-0.5 w-full rounded-t-xl" style={{ backgroundColor: severityAccentColor }} />

        <div className="flex flex-col items-center gap-1.5 px-2 pt-3 pb-2.5">
          {/* Icon */}
          <div className="relative">
            {node.cdr_actor_active && (
              <div
                className="absolute inset-0 rounded-full animate-ping"
                style={{ backgroundColor: '#ef4444', opacity: 0.22, margin: -4 }}
              />
            )}
            <div
              className="w-9 h-9 rounded-lg flex items-center justify-center"
              style={{ backgroundColor: `${cfg.color}15`, border: `1.5px solid ${cfg.color}40` }}
            >
              <cfg.Icon style={{ width: 16, height: 16, color: cfg.color }} />
            </div>
            {isLast && (
              <div
                className="absolute -top-1.5 -right-1.5 w-4 h-4 rounded-full flex items-center justify-center"
                style={{ backgroundColor: '#a855f7', border: '2px solid #0c111d' }}
                title="Crown Jewel"
              >
                <span style={{ fontSize: 8, color: '#fff', fontWeight: 700 }}>CJ</span>
              </div>
            )}
          </div>

          {/* Type chip */}
          <span
            className="text-[8px] font-bold px-1.5 py-0.5 rounded-full tracking-wide"
            style={{ backgroundColor: `${cfg.color}18`, color: cfg.color }}
          >
            {cfg.label}
          </span>

          {/* Short name */}
          <span
            className="text-[8px] font-medium text-center leading-tight w-full"
            style={{ color: 'rgba(255,255,255,0.85)', wordBreak: 'break-all' }}
          >
            {label.slice(0, 14)}
          </span>

          {/* Badges */}
          <div className="flex items-center gap-1 flex-wrap justify-center">
            {misconfigCount > 0 && (
              <span
                className="flex items-center gap-0.5 text-[7px] font-semibold px-1 py-0.5 rounded"
                style={{ backgroundColor: 'rgba(249,115,22,0.15)', color: '#f97316', border: '1px solid rgba(249,115,22,0.3)' }}
              >
                <Bug style={{ width: 6, height: 6 }} />{misconfigCount}
              </span>
            )}
            {node.cves && node.cves.length > 0 && (
              <span
                className="flex items-center gap-0.5 text-[7px] font-semibold px-1 py-0.5 rounded"
                style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)' }}
              >
                <AlertCircle style={{ width: 6, height: 6 }} />{node.cves.length}
              </span>
            )}
            {node.cdr_actor_active && (
              <span
                className="text-[7px] font-bold px-1 py-0.5 rounded animate-pulse"
                style={{ backgroundColor: '#ef4444', color: '#fff' }}
              >
                LIVE
              </span>
            )}
            {nodeRiskScore !== null && !node.cdr_actor_active && !misconfigCount && !node.cves?.length && (
              <span
                className="text-[7px] font-semibold px-1 py-0.5 rounded"
                style={{ backgroundColor: `${severityAccentColor}18`, color: severityAccentColor, border: `1px solid ${severityAccentColor}40` }}
              >
                {nodeRiskScore}
              </span>
            )}
          </div>
        </div>
      </button>

      {showTip && <NodeTooltip node={node} anchorRef={ref} />}
    </>
  );
}
