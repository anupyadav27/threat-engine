'use client';

import { X, Shield, Clock, User, Zap, AlertTriangle, ExternalLink, ChevronRight } from 'lucide-react';
import SeverityBadge from './SeverityBadge';

const SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
const CAT_LABELS = {
  initial_access:       'Initial Access',
  privilege_escalation: 'Privilege Escalation',
  credential_access:    'Credential Access',
  exfiltration:         'Exfiltration',
  defense_evasion:      'Defense Evasion',
  persistence:          'Persistence',
  execution:            'Execution',
  lateral_movement:     'Lateral Movement',
  impact:               'Impact',
  data_exposure:        'Data Exposure',
  reconnaissance:       'Reconnaissance',
};

// ── Tiny helpers ───────────────────────────────────────────────────────────────
function Field({ label, value, mono, copy }) {
  if (!value && value !== 0) return null;
  const v = String(value);
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
      padding: '5px 0', borderBottom: '1px solid var(--border-primary)', gap: 8 }}>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0, minWidth: 90 }}>{label}</span>
      <span style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: mono ? 'monospace' : 'inherit',
        wordBreak: 'break-all', textAlign: 'right' }}>{v}</span>
    </div>
  );
}

function RiskBar({ score }) {
  const s = score || 0;
  const col = s >= 80 ? SEV_COLOR.critical : s >= 60 ? SEV_COLOR.high : s >= 40 ? SEV_COLOR.medium : SEV_COLOR.low;
  return (
    <div style={{ padding: '10px 14px', borderRadius: 8, background: 'var(--bg-secondary)',
      border: '1px solid var(--border-primary)', marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase',
          letterSpacing: '0.05em' }}>Risk Score</span>
        <span style={{ fontSize: 18, fontWeight: 900, color: col }}>{s}<span style={{ fontSize: 12,
          color: 'var(--text-muted)', fontWeight: 400 }}> / 100</span></span>
      </div>
      <div style={{ height: 6, borderRadius: 3, background: 'var(--bg-tertiary)', overflow: 'hidden' }}>
        <div style={{ width: `${s}%`, height: '100%', borderRadius: 3, background: col }} />
      </div>
    </div>
  );
}

function StatusBadge({ status }) {
  const s = (status || 'active').toLowerCase();
  const map = {
    active:        { bg: 'rgba(239,68,68,0.15)',   color: '#f87171', label: 'Active' },
    investigating: { bg: 'rgba(245,158,11,0.15)',  color: '#fbbf24', label: 'Investigating' },
    resolved:      { bg: 'rgba(34,197,94,0.15)',   color: '#4ade80', label: 'Resolved' },
    suppressed:    { bg: 'rgba(148,163,184,0.15)', color: '#94a3b8', label: 'Suppressed' },
  };
  const { bg, color, label } = map[s] || map.active;
  return (
    <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
      backgroundColor: bg, color }}>{label}</span>
  );
}

function MitreBadge({ label, color = '#60a5fa' }) {
  return (
    <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
      backgroundColor: `${color}22`, color, border: `1px solid ${color}44` }}>{label}</span>
  );
}

function SectionHeader({ label }) {
  return (
    <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase',
      letterSpacing: '0.06em', marginBottom: 8, marginTop: 16 }}>{label}</div>
  );
}

// ── Contributing Findings table (grouped by rule_id) ──────────────────────────
function ContributingFindings({ findings }) {
  if (!findings || findings.length === 0) return (
    <div style={{ padding: '10px 0', fontSize: 12, color: 'var(--text-muted)' }}>
      No atomic findings linked to this detection.
    </div>
  );

  // Group by rule_id — one row per unique rule with resource count + regions
  const grouped = Object.values(
    findings.reduce((acc, f) => {
      const key = f.rule_id || f.finding_id || '';
      if (!acc[key]) {
        acc[key] = {
          rule_id:       f.rule_id || '—',
          severity:      f.severity,
          status:        f.status,
          resource_type: f.resource_type,
          regions:       new Set(),
          accounts:      new Set(),
          count:         0,
          last_seen_at:  f.last_seen_at || '',
        };
      }
      acc[key].count += 1;
      if (f.region)     acc[key].regions.add(f.region);
      if (f.account_id) acc[key].accounts.add(f.account_id);
      // keep latest last_seen_at
      if (f.last_seen_at > acc[key].last_seen_at) acc[key].last_seen_at = f.last_seen_at;
      return acc;
    }, {})
  ).sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
  });

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid var(--border-primary)' }}>
            {['Rule ID', 'Severity', 'Service', 'Resources', 'Regions', 'Last Seen'].map(h => (
              <th key={h} style={{ padding: '4px 8px', textAlign: 'left', fontWeight: 700,
                color: 'var(--text-muted)', whiteSpace: 'nowrap', fontSize: 10,
                textTransform: 'uppercase', letterSpacing: '0.05em' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {grouped.map((g, i) => {
            const sev = (g.severity || 'medium').toLowerCase();
            const col = SEV_COLOR[sev] || SEV_COLOR.medium;
            const regionList = [...g.regions].join(', ') || '—';
            return (
              <tr key={g.rule_id + i} style={{
                borderBottom: '1px solid var(--border-primary)',
                backgroundColor: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)',
              }}>
                <td style={{ padding: '6px 8px', fontFamily: 'monospace',
                  color: 'var(--accent-primary)', whiteSpace: 'nowrap' }}>
                  {g.rule_id}
                </td>
                <td style={{ padding: '6px 8px' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, color: col,
                    textTransform: 'uppercase' }}>{sev}</span>
                </td>
                <td style={{ padding: '6px 8px' }}>
                  <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3,
                    backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>
                    {g.resource_type || '—'}
                  </span>
                </td>
                <td style={{ padding: '6px 8px', textAlign: 'center' }}>
                  <span style={{ fontSize: 12, fontWeight: 800, color: col,
                    fontVariantNumeric: 'tabular-nums' }}>{g.count}</span>
                </td>
                <td style={{ padding: '6px 8px', color: 'var(--text-muted)',
                  fontSize: 10, maxWidth: 140, overflow: 'hidden',
                  textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                  title={regionList}>
                  {regionList}
                </td>
                <td style={{ padding: '6px 8px', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                  {g.last_seen_at ? g.last_seen_at.slice(0, 10) : '—'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Main Panel ─────────────────────────────────────────────────────────────────
export default function ThreatDetailPanel({ threat, relatedFindings = [], open, onClose }) {
  if (!open || !threat) return null;

  const sev = (threat.severity || 'medium').toLowerCase();
  const sevColor = SEV_COLOR[sev] || SEV_COLOR.medium;
  const title = threat.title || threat.threat_name || threat.id || 'Threat Detection';
  const catLabel = CAT_LABELS[threat.threat_category] || threat.threat_category || '';
  const tactics = threat.mitreTactics || (threat.mitreTactic ? [threat.mitreTactic] : []);
  const techniques = threat.mitreTechniques || (threat.mitreTechnique ? [threat.mitreTechnique] : []);
  const steps = threat.remediationSteps || threat.recommendations || [];
  const detectedDate = (threat.detected || threat.detected_at || '').slice(0, 10);
  const lastSeenDate = (threat.lastSeen || threat.last_seen_at || '').slice(0, 10);

  // Severity breakdown of related findings
  const findingSevCounts = relatedFindings.reduce((acc, f) => {
    const s = (f.severity || 'medium').toLowerCase();
    acc[s] = (acc[s] || 0) + 1;
    return acc;
  }, {});

  return (
    <>
      {/* Backdrop */}
      <div
        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.45)', zIndex: 49 }}
        onClick={onClose}
      />

      {/* Panel */}
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0, width: 560,
        background: 'var(--bg-primary)', borderLeft: '1px solid var(--border-primary)',
        zIndex: 50, overflowY: 'auto', display: 'flex', flexDirection: 'column',
      }}>
        {/* Header */}
        <div style={{
          padding: '14px 18px', borderBottom: '1px solid var(--border-primary)',
          display: 'flex', alignItems: 'flex-start', gap: 10, flexShrink: 0,
          background: 'var(--bg-secondary)',
        }}>
          <Shield style={{ width: 18, height: 18, color: sevColor, marginTop: 2, flexShrink: 0 }} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 4 }}>
              <SeverityBadge severity={sev} />
              <StatusBadge status={threat.status} />
              {threat.provider && (
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                  backgroundColor: 'rgba(99,102,241,0.15)', color: '#818cf8' }}>
                  {threat.provider}
                </span>
              )}
              {catLabel && (
                <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
                  backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
                  {catLabel}
                </span>
              )}
            </div>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)',
              lineHeight: 1.35 }}>{title}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2,
              fontFamily: 'monospace' }}>{threat.id || threat.detection_id}</div>
          </div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', cursor: 'pointer', padding: 4, borderRadius: 4,
            color: 'var(--text-muted)', flexShrink: 0,
          }}>
            <X style={{ width: 16, height: 16 }} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '16px 18px', flex: 1 }}>

          {/* Risk Score */}
          <RiskBar score={threat.riskScore || threat.risk_score} />

          {/* Quick stats */}
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8, marginBottom: 16,
          }}>
            {[
              { label: 'Unique Rules', value: new Set(relatedFindings.map(f => f.rule_id).filter(Boolean)).size || threat.finding_count || 0, icon: '📋' },
              { label: 'Blast Radius', value: threat.blast_radius || '—', icon: '💥' },
              { label: 'Attack Path', value: threat.hasAttackPath ? 'Yes ⚡' : 'No', icon: '🔗' },
            ].map(({ label, value, icon }) => (
              <div key={label} style={{
                padding: '8px 10px', borderRadius: 8, background: 'var(--bg-secondary)',
                border: '1px solid var(--border-primary)', textAlign: 'center',
              }}>
                <div style={{ fontSize: 16, marginBottom: 2 }}>{icon}</div>
                <div style={{ fontSize: 15, fontWeight: 800, color: 'var(--text-primary)',
                  fontVariantNumeric: 'tabular-nums' }}>{value}</div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase',
                  letterSpacing: '0.05em' }}>{label}</div>
              </div>
            ))}
          </div>

          {/* Resource */}
          <SectionHeader label="Resource" />
          <div style={{ padding: '10px 14px', borderRadius: 8, background: 'var(--bg-secondary)',
            border: '1px solid var(--border-primary)', marginBottom: 4 }}>
            <Field label="Resource ID"  value={threat.resource_uid}  mono />
            <Field label="Type"         value={threat.resourceType || threat.resource_type} />
            <Field label="Region"       value={threat.region} />
            <Field label="Account"      value={threat.account || threat.account_id} mono />
            <Field label="Provider"     value={threat.provider} />
            {detectedDate && <Field label="First Detected" value={detectedDate} />}
            {lastSeenDate  && <Field label="Last Seen"      value={lastSeenDate} />}
            {threat.assignee && <Field label="Assignee"    value={threat.assignee} />}
          </div>

          {/* MITRE ATT&CK */}
          {(tactics.length > 0 || techniques.length > 0) && (
            <>
              <SectionHeader label="MITRE ATT&CK" />
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 4 }}>
                {tactics.map(t => (
                  <MitreBadge key={t} label={t} color="#a78bfa" />
                ))}
                {techniques.map(t => (
                  <MitreBadge key={t} label={t} color="#60a5fa" />
                ))}
              </div>
            </>
          )}

          {/* Remediation */}
          {steps.length > 0 && (
            <>
              <SectionHeader label="Remediation Steps" />
              <div style={{ padding: '10px 14px', borderRadius: 8, background: 'var(--bg-secondary)',
                border: '1px solid var(--border-primary)', marginBottom: 4 }}>
                <ol style={{ margin: 0, padding: '0 0 0 16px' }}>
                  {steps.map((step, i) => (
                    <li key={i} style={{ fontSize: 12, color: 'var(--text-secondary)',
                      lineHeight: 1.6, marginBottom: 4 }}>{step}</li>
                  ))}
                </ol>
              </div>
            </>
          )}

          {/* Contributing Findings */}
          {(()=>{
            const uniqueRules = new Set(relatedFindings.map(f=>f.rule_id).filter(Boolean)).size;
            const totalInstances = relatedFindings.length;
            const label = uniqueRules
              ? `Contributing Rules (${uniqueRules} rules · ${totalInstances} resources)`
              : `Contributing Findings (${totalInstances})`;
            return <SectionHeader label={label} />;
          })()}

          {/* Severity breakdown bar */}
          {relatedFindings.length > 0 && (
            <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
              {Object.entries(findingSevCounts).sort((a, b) => {
                const order = { critical: 0, high: 1, medium: 2, low: 3 };
                return (order[a[0]] ?? 9) - (order[b[0]] ?? 9);
              }).map(([sev, count]) => (
                <span key={sev} style={{
                  fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                  backgroundColor: `${SEV_COLOR[sev]}22`, color: SEV_COLOR[sev],
                }}>
                  {sev}: {count}
                </span>
              ))}
            </div>
          )}

          <div style={{ padding: '10px 14px', borderRadius: 8, background: 'var(--bg-secondary)',
            border: '1px solid var(--border-primary)' }}>
            <ContributingFindings findings={relatedFindings} />
          </div>

        </div>
      </div>
    </>
  );
}
