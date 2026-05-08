'use client';

import { useState } from 'react';
import { ChevronDown, ChevronRight, Shield, AlertTriangle } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

// ── Resource category → icon + color ─────────────────────────────────────────
const CATEGORY_META = {
  internet:  { icon: '🌐', color: '#ef4444', label: 'Internet' },
  network:   { icon: '⚡', color: '#f59e0b', label: 'Network' },
  compute:   { icon: '💻', color: '#3b82f6', label: 'Compute' },
  identity:  { icon: '🔑', color: '#8b5cf6', label: 'Identity' },
  data_store:{ icon: '🗄️', color: '#10b981', label: 'Data Store' },
  secrets:   { icon: '🔐', color: '#ef4444', label: 'Secrets' },
  container: { icon: '📦', color: '#06b6d4', label: 'Container' },
  security:  { icon: '🛡️', color: '#6366f1', label: 'Security' },
  messaging: { icon: '📨', color: '#f97316', label: 'Messaging' },
  deployment:{ icon: '🚀', color: '#14b8a6', label: 'Deployment' },
  monitoring:{ icon: '📊', color: '#64748b', label: 'Monitoring' },
};

const HOP_CATEGORY_COLORS = {
  exposure:             { bg: 'rgba(239,68,68,0.12)', color: '#f87171', label: 'Exposure' },
  lateral_movement:     { bg: 'rgba(245,158,11,0.12)', color: '#fbbf24', label: 'Lateral Movement' },
  privilege_escalation: { bg: 'rgba(139,92,246,0.12)', color: '#a78bfa', label: 'Privilege Escalation' },
  data_access:          { bg: 'rgba(16,185,129,0.12)', color: '#34d399', label: 'Data Access' },
  execution:            { bg: 'rgba(59,130,246,0.12)', color: '#60a5fa', label: 'Execution' },
  data_flow:            { bg: 'rgba(99,102,241,0.12)', color: '#818cf8', label: 'Data Flow' },
};

function getResourceCategory(uid) {
  const u = (uid || '').toLowerCase();
  if (u === 'internet' || u.includes('internet')) return 'internet';
  if (u.includes(':s3:') || u.includes(':rds:') || u.includes(':dynamodb:') || u.includes(':redshift:')) return 'data_store';
  if (u.includes(':iam:') || u.includes(':role/') || u.includes(':user/')) return 'identity';
  if (u.includes(':ec2:') || u.includes(':lambda:') || u.includes(':instance/')) return 'compute';
  if (u.includes(':elasticloadbalancing:') || u.includes(':apigateway:') || u.includes(':cloudfront:')) return 'network';
  if (u.includes(':kms:') || u.includes(':secretsmanager:')) return 'secrets';
  if (u.includes(':eks:') || u.includes(':ecs:') || u.includes(':ecr:')) return 'container';
  return 'compute';
}

function shortName(uid) {
  if (!uid) return '?';
  const parts = uid.split('/');
  if (parts.length > 1) return parts[parts.length - 1];
  const colonParts = uid.split(':');
  return colonParts[colonParts.length - 1] || uid;
}

// ── Resource Node Card ───────────────────────────────────────────────────────
function ResourceNode({ uid, isTarget, isEntry }) {
  const cat = getResourceCategory(uid);
  const meta = CATEGORY_META[cat] || CATEGORY_META.compute;
  const name = shortName(uid);

  return (
    <div style={{
      display: 'inline-flex', flexDirection: 'column', alignItems: 'center',
      padding: '8px 12px', borderRadius: 10, minWidth: 80, maxWidth: 120,
      background: isTarget ? 'rgba(239,68,68,0.08)' : isEntry ? 'rgba(59,130,246,0.08)' : 'var(--bg-secondary)',
      border: `1.5px solid ${isTarget ? '#ef4444' : isEntry ? '#3b82f6' : 'var(--border-primary)'}`,
      position: 'relative',
    }}>
      <div style={{ fontSize: 20, marginBottom: 2 }}>{meta.icon}</div>
      <div style={{ fontSize: 10, fontWeight: 700, color: meta.color, textTransform: 'uppercase',
        letterSpacing: '0.04em' }}>{meta.label}</div>
      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)',
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        maxWidth: 100, textAlign: 'center' }} title={uid}>
        {name}
      </div>
      {isTarget && (
        <div style={{ fontSize: 9, fontWeight: 700, color: '#ef4444', marginTop: 2,
          textTransform: 'uppercase' }}>TARGET</div>
      )}
      {isEntry && (
        <div style={{ fontSize: 9, fontWeight: 700, color: '#3b82f6', marginTop: 2,
          textTransform: 'uppercase' }}>ENTRY</div>
      )}
    </div>
  );
}

// ── Arrow between nodes ──────────────────────────────────────────────────────
function HopArrow({ relationship, category }) {
  const catMeta = HOP_CATEGORY_COLORS[category] || { bg: 'var(--bg-tertiary)', color: 'var(--text-muted)', label: category };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', padding: '0 4px', minWidth: 60 }}>
      <div style={{ fontSize: 9, fontWeight: 700, padding: '1px 6px', borderRadius: 3,
        backgroundColor: catMeta.bg, color: catMeta.color, whiteSpace: 'nowrap',
        marginBottom: 2 }}>
        {catMeta.label}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <div style={{ width: 24, height: 1.5, backgroundColor: catMeta.color, opacity: 0.5 }} />
        <div style={{ width: 0, height: 0, borderTop: '4px solid transparent',
          borderBottom: '4px solid transparent', borderLeft: `6px solid ${catMeta.color}`, opacity: 0.7 }} />
      </div>
      <div style={{ fontSize: 9, color: 'var(--text-muted)', whiteSpace: 'nowrap', marginTop: 1 }}>
        {(relationship || '').replace(/_/g, ' ')}
      </div>
    </div>
  );
}

// ── Collapsed Path (icon chain) ──────────────────────────────────────────────
function CollapsedPathChain({ steps, entryPoint, target }) {
  if (!steps || steps.length === 0) return null;

  // Build unique node chain: entry → hop1.to → hop2.to → ... → target
  const nodes = [entryPoint];
  for (const step of steps) {
    if (step.to && !nodes.includes(step.to)) nodes.push(step.to);
  }
  if (target && !nodes.includes(target)) nodes.push(target);

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap',
      padding: '6px 0' }}>
      {nodes.map((uid, i) => {
        const cat = getResourceCategory(uid);
        const meta = CATEGORY_META[cat] || CATEGORY_META.compute;
        const isLast = i === nodes.length - 1;
        const name = shortName(uid);
        return (
          <div key={uid + i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 3,
              padding: '2px 8px', borderRadius: 6, backgroundColor: 'var(--bg-secondary)',
              border: '1px solid var(--border-primary)' }}>
              <span style={{ fontSize: 14 }}>{meta.icon}</span>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)',
                maxWidth: 80, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                title={uid}>
                {name}
              </span>
            </div>
            {!isLast && (
              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>→</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Expanded Path (full hop-by-hop) ──────────────────────────────────────────
function ExpandedPath({ steps, entryPoint, target, targetCategory, mitreTechniques }) {
  if (!steps || steps.length === 0) return null;

  return (
    <div style={{ padding: '12px 0' }}>
      {/* Hop-by-hop visualization */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {steps.map((step, i) => (
          <div key={i} style={{
            display: 'flex', alignItems: 'center', gap: 0,
            padding: '8px 12px', borderRadius: 10,
            background: 'var(--bg-secondary)', border: '1px solid var(--border-primary)',
          }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)',
              width: 55, flexShrink: 0 }}>HOP {i + 1}</div>
            <ResourceNode uid={step.from} isEntry={i === 0} />
            <HopArrow relationship={step.relationship} category={step.category} />
            <ResourceNode uid={step.to} isTarget={i === steps.length - 1} />
          </div>
        ))}
      </div>

      {/* MITRE */}
      {mitreTechniques && mitreTechniques.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)',
            textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 6 }}>
            MITRE ATT&CK
          </div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {mitreTechniques.map(t => (
              <span key={t} style={{ fontSize: 10, fontWeight: 600, padding: '2px 8px',
                borderRadius: 4, backgroundColor: 'rgba(96,165,250,0.15)', color: '#60a5fa',
                border: '1px solid rgba(96,165,250,0.3)' }}>{t}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Score Badge ──────────────────────────────────────────────────────────────
function ScoreBadge({ score }) {
  const col = score >= 70 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 30 ? '#eab308' : '#22c55e';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
      <div style={{ width: 32, height: 5, borderRadius: 3, backgroundColor: 'var(--bg-tertiary)',
        overflow: 'hidden' }}>
        <div style={{ width: `${score}%`, height: '100%', borderRadius: 3, backgroundColor: col }} />
      </div>
      <span style={{ fontSize: 13, fontWeight: 800, color: col, fontVariantNumeric: 'tabular-nums',
        minWidth: 20, textAlign: 'right' }}>{score}</span>
    </div>
  );
}

// ── Main Attack Path Card ────────────────────────────────────────────────────
export default function AttackPathCard({ path }) {
  const [expanded, setExpanded] = useState(false);

  if (!path) return null;

  const {
    id, title, severity, pathScore, depth, steps,
    entryPointName, targetName, targetCategory,
    chainType, isInternetReachable, mitreTechniques,
    entryPoint, target,
  } = path;

  const severityColor = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
  }[severity] || '#6b7280';

  return (
    <div
      style={{
        borderRadius: 12, overflow: 'hidden',
        border: `1px solid ${expanded ? severityColor + '44' : 'var(--border-primary)'}`,
        background: expanded ? `linear-gradient(135deg, ${severityColor}08, var(--bg-card))` : 'var(--bg-card)',
        transition: 'all 0.2s ease',
        marginBottom: 8,
      }}
    >
      {/* Header (always visible) */}
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '12px 16px', cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.background = 'var(--bg-secondary)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
      >
        {/* Expand icon */}
        <div style={{ flexShrink: 0, color: 'var(--text-muted)' }}>
          {expanded
            ? <ChevronDown style={{ width: 16, height: 16 }} />
            : <ChevronRight style={{ width: 16, height: 16 }} />}
        </div>

        {/* Severity + Title */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
            <SeverityBadge severity={severity} />
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
              {title}
            </span>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
              {id}
            </span>
          </div>

          {/* Collapsed chain */}
          {!expanded && (
            <CollapsedPathChain steps={steps} entryPoint={entryPoint} target={target} />
          )}
        </div>

        {/* Meta badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600,
              textTransform: 'uppercase' }}>Hops</div>
            <div style={{ fontSize: 14, fontWeight: 800, color: 'var(--text-primary)' }}>{depth}</div>
          </div>
          {isInternetReachable && (
            <span style={{ fontSize: 9, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
              backgroundColor: 'rgba(239,68,68,0.12)', color: '#f87171' }}>
              🌐 INTERNET
            </span>
          )}
          <ScoreBadge score={pathScore} />
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ padding: '0 16px 16px 44px', borderTop: '1px solid var(--border-primary)' }}>
          <ExpandedPath
            steps={steps}
            entryPoint={entryPoint}
            target={target}
            targetCategory={targetCategory}
            mitreTechniques={mitreTechniques}
          />
        </div>
      )}
    </div>
  );
}

// ── Attack Path List (export for use in threats page) ────────────────────────
export function AttackPathList({ paths, loading }) {
  if (loading) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
        Loading attack paths...
      </div>
    );
  }

  if (!paths || paths.length === 0) {
    return (
      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
        No attack paths detected. Run a scan with inventory relationships to discover paths.
      </div>
    );
  }

  return (
    <div>
      {/* Summary strip */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
        {(() => {
          const counts = {};
          for (const p of paths) {
            const sev = p.severity || 'medium';
            counts[sev] = (counts[sev] || 0) + 1;
          }
          return Object.entries(counts)
            .sort((a, b) => {
              const order = { critical: 0, high: 1, medium: 2, low: 3 };
              return (order[a[0]] ?? 9) - (order[b[0]] ?? 9);
            })
            .map(([sev, count]) => {
              const col = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }[sev] || '#6b7280';
              return (
                <span key={sev} style={{ fontSize: 11, fontWeight: 700, padding: '3px 10px',
                  borderRadius: 4, backgroundColor: `${col}18`, color: col }}>
                  {sev}: {count}
                </span>
              );
            });
        })()}
      </div>

      {/* Path cards */}
      {paths.map(p => <AttackPathCard key={p.id} path={p} />)}
    </div>
  );
}
