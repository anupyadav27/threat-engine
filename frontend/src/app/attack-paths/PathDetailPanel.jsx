'use client';

/**
 * PathDetailPanel — right slide-in panel shown when a canvas node is clicked.
 *
 * Props:
 *   node    {object}    — step data from attack path steps[] (with injected fields)
 *   onClose {function}  — close the panel
 *
 * Shows: resource type + name, region/account pills, choke-point badge,
 *        traversal reason, next-hop vector, misconfigs, CVEs, threat detections,
 *        full resource ID, and a "View in Inventory" link.
 *
 * Security: policy_statement never rendered. credential_ref never rendered.
 */

import { useRouter } from 'next/navigation';
import {
  Globe, Database, Server, Key, Lock, Shield,
  Network, Box, Cpu, HardDrive, Cloud,
  X, ExternalLink, AlertCircle, Bug, Zap,
} from 'lucide-react';
import { resolveEdgeColor } from './AttackPathCanvas';

// ── Type → icon + color (mirrors NodeBox / Canvas) ───────────────────────────

const TYPE_MAP = {
  internet:       { Icon: Globe,     color: '#ef4444', label: 'Internet' },
  ec2:            { Icon: Server,    color: '#f97316', label: 'EC2' },
  s3:             { Icon: Database,  color: '#22c55e', label: 'S3' },
  rds:            { Icon: Database,  color: '#3b82f6', label: 'RDS' },
  lambda:         { Icon: Cpu,       color: '#f59e0b', label: 'Lambda' },
  iam:            { Icon: Key,       color: '#a855f7', label: 'IAM' },
  role:           { Icon: Key,       color: '#a855f7', label: 'IAM Role' },
  secretsmanager: { Icon: Lock,      color: '#8b5cf6', label: 'Secrets' },
  kms:            { Icon: Shield,    color: '#6d28d9', label: 'KMS' },
  eks:            { Icon: Box,       color: '#3b82f6', label: 'EKS' },
  vpc:            { Icon: Network,   color: '#0ea5e9', label: 'VPC' },
  compute:        { Icon: Server,    color: '#f97316', label: 'Compute' },
  storage:        { Icon: HardDrive, color: '#22c55e', label: 'Storage' },
  secrets:        { Icon: Lock,      color: '#a855f7', label: 'Secrets' },
  identity:       { Icon: Key,       color: '#a855f7', label: 'Identity' },
  network:        { Icon: Network,   color: '#3b82f6', label: 'Network' },
  data:           { Icon: Database,  color: '#22c55e', label: 'Data' },
};

function resolveType(typeStr) {
  const t = (typeStr || '').toLowerCase();
  for (const [key, cfg] of Object.entries(TYPE_MAP)) {
    if (t.includes(key)) return cfg;
  }
  return { Icon: Cloud, color: '#64748b', label: (typeStr || '').split('.').pop() || 'Resource' };
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SevBadge({ severity }) {
  const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#6b7280' };
  const bgs    = { critical: 'rgba(239,68,68,0.15)', high: 'rgba(249,115,22,0.15)', medium: 'rgba(234,179,8,0.15)', low: 'rgba(107,114,128,0.15)' };
  const c  = colors[severity] || '#6b7280';
  const bg = bgs[severity]   || 'rgba(107,114,128,0.15)';
  return (
    <span style={{ fontSize: 8, fontWeight: 700, padding: '2px 5px', borderRadius: 4, backgroundColor: bg, color: c, textTransform: 'uppercase', flexShrink: 0 }}>
      {severity}
    </span>
  );
}

function SectionLabel({ children }) {
  return (
    <p style={{ fontSize: 9, fontWeight: 700, color: 'rgba(255,255,255,0.3)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
      {children}
    </p>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

export default function PathDetailPanel({ node, onClose }) {
  const router = useRouter();
  if (!node) return null;

  const cfg = resolveType(node.node_type);
  const misconfigCount = node.misconfigs?.length ?? 0;
  const cveCount = node.cves?.length ?? 0;
  const label = (node.node_name || node.node_uid || '').split('/').pop().split(':').pop();

  const misconfigs = (node.misconfigs || []).slice(0, 5);
  const cves = (node.cves || [])
    .slice()
    .sort((a, b) => (b.epss ?? b.epss_score ?? 0) - (a.epss ?? a.epss_score ?? 0))
    .slice(0, 5);
  const threats = (node.threat_detections || []).slice(0, 3);

  const edgeColor = resolveEdgeColor(node.edge_to_next);

  return (
    <div
      style={{
        width: 320,
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: '#0c111d',
        border: '1px solid rgba(255,255,255,0.09)',
        borderRadius: 12,
        overflow: 'hidden',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '12px 14px',
          borderBottom: '1px solid rgba(255,255,255,0.07)',
          backgroundColor: `${cfg.color}0d`,
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          gap: 8,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, minWidth: 0 }}>
          <div
            style={{
              width: 34,
              height: 34,
              borderRadius: 8,
              backgroundColor: `${cfg.color}18`,
              border: `1.5px solid ${cfg.color}40`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
            }}
          >
            <cfg.Icon style={{ width: 15, height: 15, color: cfg.color }} />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <p style={{ fontSize: 9, fontWeight: 700, color: cfg.color, textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>
              {cfg.label}
            </p>
            <p style={{ fontSize: 12, fontWeight: 600, color: 'rgba(255,255,255,0.92)', wordBreak: 'break-all', lineHeight: 1.3 }}>
              {label.slice(0, 28)}
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          style={{ padding: 4, borderRadius: 6, color: 'rgba(255,255,255,0.35)', flexShrink: 0, cursor: 'pointer', background: 'none', border: 'none', lineHeight: 0 }}
          aria-label="Close panel"
        >
          <X style={{ width: 14, height: 14 }} />
        </button>
      </div>

      {/* Scrollable body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 14 }}>

        {/* Meta pills row */}
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
          {node.is_choke_point && (
            <span style={{ fontSize: 8, fontWeight: 700, padding: '2px 7px', borderRadius: 20, backgroundColor: 'rgba(168,85,247,0.18)', color: '#a855f7', border: '1px solid rgba(168,85,247,0.35)' }}>
              ⬡ Choke Point
            </span>
          )}
          {node.cdr_actor_active && (
            <span style={{ fontSize: 8, fontWeight: 700, padding: '2px 7px', borderRadius: 20, backgroundColor: 'rgba(239,68,68,0.22)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.4)' }}>
              ⚡ LIVE CDR
            </span>
          )}
          {node.region && (
            <span style={{ fontSize: 8, fontWeight: 500, padding: '2px 7px', borderRadius: 20, backgroundColor: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.45)', border: '1px solid rgba(255,255,255,0.1)' }}>
              {node.region}
            </span>
          )}
          {node.account_id && (
            <span style={{ fontSize: 8, fontWeight: 500, padding: '2px 7px', borderRadius: 20, backgroundColor: 'rgba(255,255,255,0.06)', color: 'rgba(255,255,255,0.4)', border: '1px solid rgba(255,255,255,0.1)', fontFamily: 'monospace' }}>
              {node.account_id.slice(-10)}
            </span>
          )}
          {node.provider && (
            <span style={{ fontSize: 8, fontWeight: 600, padding: '2px 7px', borderRadius: 20, backgroundColor: 'rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.35)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {node.provider.toUpperCase()}
            </span>
          )}
        </div>

        {/* Next hop vector */}
        {node.edge_to_next && (
          <div>
            <SectionLabel>Next Hop Vector</SectionLabel>
            <span
              style={{
                display: 'inline-block',
                fontSize: 10,
                fontWeight: 600,
                padding: '3px 10px',
                borderRadius: 6,
                backgroundColor: `${edgeColor}15`,
                color: edgeColor,
                border: `1px solid ${edgeColor}30`,
              }}
            >
              {(node.edge_to_next || '').replace(/_/g, ' ')}
            </span>
          </div>
        )}

        {/* Traversal reason */}
        {node.traversal_reason && (
          <div
            style={{
              padding: '8px 10px',
              borderRadius: 8,
              backgroundColor: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.07)',
            }}
          >
            <SectionLabel>Traversal Reason</SectionLabel>
            <p style={{ fontSize: 10, color: 'rgba(255,255,255,0.6)', lineHeight: 1.5, fontStyle: 'italic', margin: 0 }}>
              {node.traversal_reason}
            </p>
          </div>
        )}

        {/* Misconfigurations */}
        {misconfigs.length > 0 && (
          <div>
            <SectionLabel>Misconfigurations ({misconfigCount})</SectionLabel>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {misconfigs.map((m, i) => (
                <div
                  key={i}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 7,
                    padding: '6px 8px',
                    borderRadius: 6,
                    backgroundColor: 'rgba(249,115,22,0.06)',
                    border: '1px solid rgba(249,115,22,0.15)',
                  }}
                >
                  <Bug style={{ width: 10, height: 10, color: '#f97316', flexShrink: 0, marginTop: 1 }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: 10, color: 'rgba(255,255,255,0.8)', fontWeight: 500, lineHeight: 1.3, margin: 0 }}>
                      {m.title || m.rule_id || 'Misconfiguration'}
                    </p>
                    {m.rule_id && m.title && (
                      <p style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', fontFamily: 'monospace', margin: '2px 0 0' }}>
                        {m.rule_id}
                      </p>
                    )}
                  </div>
                  {m.severity && <SevBadge severity={m.severity} />}
                </div>
              ))}
              {misconfigCount > 5 && (
                <p style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', textAlign: 'center' }}>
                  +{misconfigCount - 5} more
                </p>
              )}
            </div>
          </div>
        )}

        {/* CVEs */}
        {cves.length > 0 && (
          <div>
            <SectionLabel>CVEs ({cveCount})</SectionLabel>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {cves.map((c, i) => {
                const epss = c.epss ?? c.epss_score ?? null;
                return (
                  <div
                    key={i}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 7,
                      padding: '6px 8px',
                      borderRadius: 6,
                      backgroundColor: 'rgba(239,68,68,0.06)',
                      border: '1px solid rgba(239,68,68,0.15)',
                    }}
                  >
                    <AlertCircle style={{ width: 10, height: 10, color: '#ef4444', flexShrink: 0, marginTop: 1 }} />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p style={{ fontSize: 10, fontWeight: 600, color: '#f87171', fontFamily: 'monospace', margin: 0, lineHeight: 1.3 }}>
                        {c.cve_id || c.title || 'CVE'}
                      </p>
                      {epss != null && (
                        <p style={{ fontSize: 9, color: 'rgba(255,255,255,0.35)', margin: '2px 0 0' }}>
                          EPSS {(epss * 100).toFixed(1)}%
                        </p>
                      )}
                    </div>
                    {c.severity && <SevBadge severity={c.severity} />}
                  </div>
                );
              })}
              {cveCount > 5 && (
                <p style={{ fontSize: 9, color: 'rgba(255,255,255,0.3)', textAlign: 'center' }}>
                  +{cveCount - 5} more
                </p>
              )}
            </div>
          </div>
        )}

        {/* Threat detections */}
        {threats.length > 0 && (
          <div>
            <SectionLabel>Threat Detections</SectionLabel>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {threats.map((t, i) => (
                <div
                  key={i}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 7,
                    padding: '6px 8px',
                    borderRadius: 6,
                    backgroundColor: 'rgba(239,68,68,0.08)',
                    border: '1px solid rgba(239,68,68,0.2)',
                  }}
                >
                  <Zap style={{ width: 10, height: 10, color: '#ef4444', flexShrink: 0, marginTop: 1 }} />
                  <p style={{ fontSize: 10, color: 'rgba(255,255,255,0.7)', flex: 1, lineHeight: 1.4, margin: 0 }}>
                    {t.title || t.detection_type || t.actor_principal || 'Threat detected'}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Empty state */}
        {misconfigCount === 0 && cveCount === 0 && threats.length === 0 && (
          <p style={{ fontSize: 11, color: 'rgba(255,255,255,0.25)', textAlign: 'center', padding: '8px 0' }}>
            No findings on this node
          </p>
        )}

        {/* Resource ID */}
        <div
          style={{
            padding: '7px 9px',
            borderRadius: 7,
            backgroundColor: 'rgba(255,255,255,0.03)',
            border: '1px solid rgba(255,255,255,0.06)',
          }}
        >
          <p style={{ fontSize: 9, fontWeight: 700, color: 'rgba(255,255,255,0.22)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
            Resource ID
          </p>
          <p style={{ fontSize: 9, fontFamily: 'monospace', color: 'rgba(255,255,255,0.4)', wordBreak: 'break-all', lineHeight: 1.4, margin: 0 }}>
            {node.node_uid}
          </p>
        </div>
      </div>

      {/* Footer */}
      <div style={{ padding: '10px 14px', borderTop: '1px solid rgba(255,255,255,0.07)' }}>
        <button
          onClick={() => router.push(`/inventory/${encodeURIComponent(node.node_uid)}`)}
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 6,
            padding: '8px 0',
            borderRadius: 8,
            fontSize: 11,
            fontWeight: 600,
            color: '#3b82f6',
            backgroundColor: 'rgba(59,130,246,0.08)',
            border: '1px solid rgba(59,130,246,0.2)',
            cursor: 'pointer',
            transition: 'opacity 0.15s',
            background: 'none',
          }}
        >
          <ExternalLink style={{ width: 12, height: 12 }} />
          View in Inventory
        </button>
      </div>
    </div>
  );
}
