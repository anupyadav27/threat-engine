'use client';

/**
 * IncidentDetailPanelV1 — 9-section detail drawer for a threat_v1 incident.
 *
 * Sections:
 *   1. Incident header (ID, pattern, tier, class, severity, status)
 *   2. Kill-chain narrative (story_text)
 *   3. Attack path (entry → hops → target resource UIDs)
 *   4. Misconfig findings (HAS_MISCONFIG edges from Neo4j via engine)
 *   5. Vulnerability findings (HAS_CVE edges)
 *   6. CDR events (TRIGGERED_ON edges — requires cdr:sensitive, empty if not held)
 *   7. Pattern metadata (matched_patterns list, tier rationale)
 *   8. Timeline (first_seen_at, last_seen_at, resolved_at)
 *   9. Analyst feedback (true_positive / false_positive verdict)
 *
 * Data: fetched directly from engine-threat-v1 via gateway proxy.
 * CDR fields: shown only if server returns them (controlled by cdr:sensitive perm).
 */

import { useState, useEffect } from 'react';

const GATEWAY_BASE = '/gateway/api/v1';

// ── Attack Path visualisation helpers ────────────────────────────────────────

const SERVICE_META = {
  cloudtrail:      { label: 'CloudTrail',   icon: '📋' },
  s3:              { label: 'S3 Bucket',    icon: '🪣' },
  iam:             { label: 'IAM',          icon: '👤' },
  ec2:             { label: 'EC2',          icon: '🖥' },
  ecs:             { label: 'ECS',          icon: '🐳' },
  ecr:             { label: 'ECR',          icon: '📦' },
  lambda:          { label: 'Lambda',       icon: 'λ'  },
  rds:             { label: 'RDS',          icon: '🗄' },
  kms:             { label: 'KMS',          icon: '🔑' },
  'cognito-idp':   { label: 'Cognito',      icon: '🔒' },
  cloudwatch:      { label: 'CloudWatch',   icon: '📊' },
  sns:             { label: 'SNS',          icon: '📣' },
  sqs:             { label: 'SQS',          icon: '📬' },
  secretsmanager:  { label: 'Secrets Mgr', icon: '🔐' },
  eks:             { label: 'EKS',          icon: '⎈'  },
  dynamodb:        { label: 'DynamoDB',     icon: '⚡' },
  elasticache:     { label: 'ElastiCache',  icon: '⚙️' },
  es:              { label: 'OpenSearch',   icon: '🔍' },
  glue:            { label: 'Glue',         icon: '🔗' },
  athena:          { label: 'Athena',       icon: '🔭' },
};

function parseResourceUid(uid = '') {
  if (uid.startsWith('arn:aws:')) {
    const parts = uid.split(':');
    const service = parts[2] || 'resource';
    const region  = parts[3] || '';
    const resourcePart = parts.slice(5).join(':');
    const name = resourcePart.split('/').pop() || resourcePart || uid.slice(-24);
    const svc = SERVICE_META[service] || { label: service.toUpperCase(), icon: '☁️' };
    return { service, label: svc.label, icon: svc.icon, name, region, fullUid: uid };
  }
  if (uid.startsWith('arn:azure:') || uid.includes('/providers/')) {
    const parts = uid.split('/');
    const name = parts.pop() || uid.slice(-24);
    return { service: 'azure', label: 'Azure Resource', icon: '☁️', name, region: '', fullUid: uid };
  }
  const parts = uid.split('/');
  return { service: parts[0] || 'resource', label: parts[0] || 'Resource', icon: '☁️', name: parts.slice(1).join('/') || uid, region: '', fullUid: uid };
}

function AttackPathViz({ detail, sevColor }) {
  const entry  = detail.entry_resource_uid;
  const target = detail.target_resource_uid;
  const hops   = Array.isArray(detail.hop_resource_uids) ? detail.hop_resource_uids : [];

  const pathNodes = [];
  if (entry) pathNodes.push({ uid: entry, role: 'entry' });
  hops.forEach(uid => {
    if (uid && uid !== entry && uid !== target) pathNodes.push({ uid, role: 'hop' });
  });
  if (target && target !== entry) pathNodes.push({ uid: target, role: 'target' });

  if (!pathNodes.length) {
    return <span style={{ fontSize: 12, color: 'var(--text-muted, #64748b)' }}>No path data available</span>;
  }

  const isSingleNode = pathNodes.length === 1;

  const ROLE_STYLE = {
    entry:  { border: '#22c55e', bg: 'rgba(34,197,94,0.07)',  label: isSingleNode ? 'AFFECTED RESOURCE' : 'ENTRY',  labelColor: '#22c55e' },
    hop:    { border: '#3b82f6', bg: 'rgba(59,130,246,0.07)', label: 'LATERAL MOVE', labelColor: '#3b82f6' },
    target: { border: sevColor,  bg: `${sevColor}12`,         label: 'TARGET',       labelColor: sevColor  },
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {pathNodes.map((node, i) => {
        const parsed = parseResourceUid(node.uid);
        const rs     = ROLE_STYLE[node.role] || ROLE_STYLE.hop;
        const isLast = i === pathNodes.length - 1;

        return (
          <div key={node.uid + i}>
            {/* Node card */}
            <div style={{
              border:       `1px solid ${rs.border}44`,
              borderLeft:   `3px solid ${rs.border}`,
              borderRadius: '0 6px 6px 0',
              backgroundColor: rs.bg,
              padding: '8px 10px',
            }}>
              {/* Role + service line */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
                <span style={{
                  fontSize: 9, fontWeight: 700, letterSpacing: '0.07em',
                  color: rs.labelColor,
                  backgroundColor: rs.labelColor + '22',
                  padding: '1px 5px', borderRadius: 3,
                }}>
                  {rs.label}
                </span>
                <span style={{ fontSize: 11, color: 'var(--text-secondary, #94a3b8)' }}>
                  {parsed.icon}&nbsp;{parsed.label}
                </span>
                {parsed.region && (
                  <span style={{ fontSize: 10, color: 'var(--text-muted, #64748b)', marginLeft: 'auto' }}>
                    {parsed.region}
                  </span>
                )}
              </div>

              {/* Resource name */}
              <div style={{
                fontSize: 11, fontFamily: 'monospace',
                color: 'var(--text-primary, #e2e8f0)',
                lineHeight: 1.45, wordBreak: 'break-all',
              }}>
                {parsed.name.length > 52 ? parsed.name.slice(0, 52) + '…' : parsed.name}
              </div>

              {/* Truncated full UID */}
              {parsed.fullUid !== parsed.name && (
                <div style={{
                  fontSize: 10, fontFamily: 'monospace',
                  color: 'var(--text-muted, #64748b)',
                  marginTop: 3, wordBreak: 'break-all',
                }}>
                  {parsed.fullUid.length > 60 ? parsed.fullUid.slice(0, 60) + '…' : parsed.fullUid}
                </div>
              )}
            </div>

            {/* Arrow connector between nodes */}
            {!isLast && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', paddingLeft: 14, margin: '0 0' }}>
                <div style={{ width: 1, height: 8, backgroundColor: 'var(--border-primary, #334155)' }} />
                <span style={{ fontSize: 10, color: 'var(--text-muted, #64748b)', lineHeight: 1 }}>▼</span>
                <div style={{ width: 1, height: 8, backgroundColor: 'var(--border-primary, #334155)' }} />
              </div>
            )}
          </div>
        );
      })}

      {/* Path length annotation */}
      {pathNodes.length > 1 && (
        <div style={{ marginTop: 6, fontSize: 10, color: 'var(--text-muted, #64748b)' }}>
          {pathNodes.length}-step attack path · {pathNodes.length - 1} lateral move{pathNodes.length > 2 ? 's' : ''}
        </div>
      )}
    </div>
  );
}

const sectionStyle = {
    borderBottom: '1px solid var(--border-primary, #1e293b)',
    paddingBottom: 14,
    marginBottom: 14,
};

const labelStyle = {
    fontSize: 11,
    color: 'var(--text-muted, #64748b)',
    textTransform: 'uppercase',
    letterSpacing: '0.07em',
    marginBottom: 6,
};

function SectionTitle({ children }) {
    return <div style={labelStyle}>{children}</div>;
}

function ChipRow({ items, color }) {
    if (!items?.length) return <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>None</span>;
    return (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {items.map((item, i) => (
                <span key={i} style={{
                    fontSize: 11,
                    fontFamily: 'monospace',
                    padding: '2px 7px',
                    borderRadius: 4,
                    backgroundColor: 'var(--bg-surface, #1e293b)',
                    color: color || 'var(--text-secondary, #94a3b8)',
                }}>
                    {item}
                </span>
            ))}
        </div>
    );
}

function FindingRow({ icon, label, value, mono }) {
    return (
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 4 }}>
            <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{icon}</span>
            <span style={{ fontSize: 12, color: 'var(--text-muted)', minWidth: 80 }}>{label}</span>
            <span style={{
                fontSize: 12,
                color: 'var(--text-secondary, #94a3b8)',
                fontFamily: mono ? 'monospace' : undefined,
            }}>
                {value ?? '—'}
            </span>
        </div>
    );
}

export default function IncidentDetailPanelV1({ incidentId, onClose, severityColors }) {
    const [detail, setDetail] = useState(null);
    const [loading, setLoading] = useState(true);
    const [feedbackVerdict, setFeedbackVerdict] = useState(null);
    const [feedbackSent, setFeedbackSent] = useState(false);

    useEffect(() => {
        if (!incidentId) return;
        setLoading(true);
        setDetail(null);
        setFeedbackSent(false);
        setFeedbackVerdict(null);

        fetch(`${GATEWAY_BASE}/incidents/${incidentId}`, { credentials: 'include' })
            .then(r => r.json())
            .then(setDetail)
            .catch(console.error)
            .finally(() => setLoading(false));
    }, [incidentId]);

    const submitFeedback = async () => {
        if (!feedbackVerdict) return;
        await fetch(`${GATEWAY_BASE}/incidents/${incidentId}/feedback`, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ verdict: feedbackVerdict }),
        });
        setFeedbackSent(true);
    };

    const sevColor = severityColors[detail?.severity] || 'var(--text-primary)';

    return (
        <div style={{
            width: 380,
            flexShrink: 0,
            backgroundColor: 'var(--bg-card, #0f172a)',
            border: '1px solid var(--border-primary, #1e293b)',
            borderRadius: 8,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
        }}>
            {/* Panel header */}
            <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 14px',
                borderBottom: '1px solid var(--border-primary)',
                flexShrink: 0,
            }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                    Incident Detail
                </span>
                <button onClick={onClose} style={{
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--text-muted)', fontSize: 18, lineHeight: 1,
                }}>×</button>
            </div>

            {/* Scrollable content */}
            <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
                {loading ? (
                    [1, 2, 3, 4, 5, 6, 7, 8, 9].map(i => (
                        <div key={i} style={{
                            height: 48,
                            borderRadius: 6,
                            backgroundColor: 'var(--bg-surface)',
                            marginBottom: 10,
                            animation: 'pulse 1.5s ease-in-out infinite',
                        }} />
                    ))
                ) : !detail ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: 13, textAlign: 'center', paddingTop: 40 }}>
                        Failed to load incident.
                    </div>
                ) : (
                    <>
                        {/* 1. Header */}
                        <div style={sectionStyle}>
                            <SectionTitle>Incident</SectionTitle>
                            <div style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)', marginBottom: 6 }}>
                                {detail.incident_id || incidentId}
                            </div>
                            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                                <span style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                                    {detail.primary_pattern_id}
                                </span>
                                <span style={{ fontSize: 11, padding: '1px 7px', borderRadius: 4,
                                    backgroundColor: `${sevColor}22`, color: sevColor, fontWeight: 700,
                                    textTransform: 'uppercase' }}>
                                    {detail.severity}
                                </span>
                                <span style={{ fontSize: 11, padding: '1px 7px', borderRadius: 4,
                                    backgroundColor: 'var(--bg-surface)', color: 'var(--text-secondary)' }}>
                                    Tier {detail.tier}
                                </span>
                                <span style={{ fontSize: 11, padding: '1px 7px', borderRadius: 4,
                                    backgroundColor: 'var(--bg-surface)', color: 'var(--text-secondary)' }}>
                                    {detail.incident_class}
                                </span>
                                <span style={{ fontSize: 11, padding: '1px 7px', borderRadius: 4,
                                    backgroundColor: 'var(--bg-surface)', color: 'var(--text-muted)' }}>
                                    {detail.status}
                                </span>
                            </div>
                        </div>

                        {/* 2. Kill-chain narrative */}
                        {detail.story_text && (
                            <div style={sectionStyle}>
                                <SectionTitle>Kill-Chain Narrative</SectionTitle>
                                <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                    {detail.story_text}
                                </div>
                            </div>
                        )}

                        {/* 3. Attack path */}
                        <div style={sectionStyle}>
                            <SectionTitle>Attack Path</SectionTitle>
                            <AttackPathViz detail={detail} sevColor={sevColor} />
                        </div>

                        {/* 4. Misconfig findings */}
                        <div style={sectionStyle}>
                            <SectionTitle>Misconfigurations ({detail.misconfig_findings?.length || 0})</SectionTitle>
                            {!detail.misconfig_findings?.length ? (
                                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>None</span>
                            ) : detail.misconfig_findings.map((f, i) => (
                                <div key={i} style={{ marginBottom: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
                                    <span style={{ fontFamily: 'monospace', color: 'var(--text-muted)', marginRight: 6 }}>
                                        [{f.severity?.toUpperCase()}]
                                    </span>
                                    {f.rule_id} — {f.title || f.rule_id}
                                </div>
                            ))}
                        </div>

                        {/* 5. Vulnerability findings */}
                        <div style={sectionStyle}>
                            <SectionTitle>Vulnerabilities ({detail.vuln_findings?.length || 0})</SectionTitle>
                            {!detail.vuln_findings?.length ? (
                                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>None</span>
                            ) : detail.vuln_findings.map((v, i) => (
                                <div key={i} style={{ marginBottom: 4, fontSize: 12, color: 'var(--text-secondary)', display: 'flex', gap: 8 }}>
                                    <span style={{ fontFamily: 'monospace', color: '#f97316' }}>{v.cve_id}</span>
                                    <span style={{ color: 'var(--text-muted)' }}>CVSS {v.cvss_score?.toFixed(1)}</span>
                                    {v.has_known_exploit && <span style={{ color: '#dc2626', fontSize: 11 }}>⚠ KEV</span>}
                                </div>
                            ))}
                        </div>

                        {/* 6. CDR events */}
                        <div style={sectionStyle}>
                            <SectionTitle>CDR Events ({detail.cdr_events?.length || 0})</SectionTitle>
                            {!detail.cdr_events?.length ? (
                                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                                    {detail.incident_class === 'posture' ? 'No behavioral signals detected' : 'Requires cdr:sensitive permission'}
                                </span>
                            ) : detail.cdr_events.map((e, i) => (
                                <div key={i} style={{ marginBottom: 6, fontSize: 12, color: 'var(--text-secondary)' }}>
                                    <span style={{ fontFamily: 'monospace', color: '#a78bfa' }}>{e.mitre_technique}</span>
                                    <span style={{ color: 'var(--text-muted)', marginLeft: 6 }}>
                                        anomaly: {e.anomaly_score?.toFixed(2)}
                                    </span>
                                </div>
                            ))}
                        </div>

                        {/* 7. Pattern metadata */}
                        <div style={sectionStyle}>
                            <SectionTitle>Matched Patterns</SectionTitle>
                            <ChipRow items={detail.matched_patterns} />
                        </div>

                        {/* 8. Timeline */}
                        <div style={sectionStyle}>
                            <SectionTitle>Timeline</SectionTitle>
                            <FindingRow icon="●" label="First seen" value={detail.first_seen_at ? new Date(detail.first_seen_at).toLocaleString() : null} />
                            <FindingRow icon="●" label="Last seen"  value={detail.last_seen_at  ? new Date(detail.last_seen_at).toLocaleString()  : null} />
                            {detail.resolved_at && (
                                <FindingRow icon="✓" label="Resolved"   value={new Date(detail.resolved_at).toLocaleString()} />
                            )}
                        </div>

                        {/* 9. Analyst feedback */}
                        <div>
                            <SectionTitle>Analyst Verdict</SectionTitle>
                            {feedbackSent ? (
                                <div style={{ fontSize: 13, color: '#22c55e' }}>✓ Verdict submitted</div>
                            ) : (
                                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                    {['true_positive', 'false_positive'].map(v => (
                                        <button key={v} onClick={() => setFeedbackVerdict(v)} style={{
                                            padding: '5px 12px', borderRadius: 6, fontSize: 12,
                                            border: `1px solid ${feedbackVerdict === v ? 'var(--accent-blue)' : 'var(--border-primary)'}`,
                                            backgroundColor: feedbackVerdict === v ? 'rgba(59,130,246,0.15)' : 'transparent',
                                            color: feedbackVerdict === v ? 'var(--accent-blue, #3b82f6)' : 'var(--text-muted)',
                                            cursor: 'pointer',
                                        }}>
                                            {v === 'true_positive' ? '✓ True Positive' : '✗ False Positive'}
                                        </button>
                                    ))}
                                    <button onClick={submitFeedback} disabled={!feedbackVerdict} style={{
                                        padding: '5px 12px', borderRadius: 6, fontSize: 12,
                                        border: '1px solid var(--accent-blue, #3b82f6)',
                                        backgroundColor: 'var(--accent-blue, #3b82f6)',
                                        color: '#fff', cursor: feedbackVerdict ? 'pointer' : 'not-allowed',
                                        opacity: feedbackVerdict ? 1 : 0.4,
                                    }}>
                                        Submit
                                    </button>
                                </div>
                            )}
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}
