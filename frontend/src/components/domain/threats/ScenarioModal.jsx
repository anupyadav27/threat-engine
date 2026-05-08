'use client';

import { createPortal } from 'react-dom';
import Link from 'next/link';

const WRITE_ROLES = ['tenant_admin', 'org_admin', 'platform_admin'];

const SEV_COLORS = {
    critical: { text: '#DC2626', bg: 'rgba(220,38,38,0.12)' },
    high:     { text: '#EA580C', bg: 'rgba(234,88,12,0.12)' },
    medium:   { text: '#D97706', bg: 'rgba(217,119,6,0.12)' },
    low:      { text: '#64748B', bg: 'rgba(100,116,139,0.12)' },
    info:     { text: '#6B7280', bg: 'rgba(107,114,128,0.12)' },
};

// ── Layout helpers ─────────────────────────────────────────────────────────────

function Divider() {
    return <div style={{ height: 1, backgroundColor: 'var(--border-primary)', margin: '16px 0' }} />;
}

function SectionTitle({ children }) {
    return (
        <p style={{
            fontSize: 11, fontWeight: 700, color: 'var(--text-muted)',
            textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 10,
        }}>
            {children}
        </p>
    );
}

// ── Severity badge ─────────────────────────────────────────────────────────────

function SeverityBadge({ severity }) {
    const key = (severity || 'info').toLowerCase();
    const { text, bg } = SEV_COLORS[key] || SEV_COLORS.info;
    return (
        <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            backgroundColor: bg, border: `1px solid ${text}40`,
            borderRadius: 9999, color: text, fontSize: 11, fontWeight: 700,
            padding: '2px 10px', textTransform: 'uppercase', letterSpacing: '0.05em',
        }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: text, flexShrink: 0 }} />
            {severity}
        </span>
    );
}

// ── Attack chain — Orca-style full-detail cards + satellite boxes ───────────────

const RTYPE_COLOR = {
    iam: '#7C3AED', s3: '#2563EB', ec2: '#059669', lambda: '#D97706',
    rds: '#DC2626', vpc: '#0891B2', sg: '#0891B2', kms: '#9333EA',
    eks: '#4F46E5', sqs: '#EA580C', sns: '#EA580C', generic: '#475569',
};
const RTYPE_ABBR = {
    iam: 'IAM', s3: 'S3', ec2: 'EC2', lambda: 'λ',
    rds: 'RDS', vpc: 'VPC', sg: 'SG', kms: 'KMS',
    eks: 'EKS', sqs: 'SQS', sns: 'SNS', generic: '?',
};
const RTYPE_LABEL = {
    iam: 'IAM Role', s3: 'S3 Bucket', ec2: 'EC2', lambda: 'Lambda',
    rds: 'Database', vpc: 'VPC', sg: 'Sec Group', kms: 'KMS',
    eks: 'Container', sqs: 'Queue', sns: 'Topic', generic: 'Resource',
};

// Layout constants — must be identical in every row so columns stay aligned
const CARD_W = 152;  // resource card width (px)
const SAT_H  = 52;   // satellite box height (px)
const WIRE_H = 14;   // vertical connector height (px)
const EDGE_W = 68;   // horizontal arrow slot width (px)

function _detectRtype(resource, action) {
    const r = String(resource || '').toLowerCase();
    const a = String(action || '').toLowerCase();
    if (r.includes('iam') || r.includes(':user/') || r.includes(':role/') || a.includes('assum')) return 'iam';
    if (r.includes('s3') || r.includes('bucket')) return 's3';
    if (r.includes('ec2') || r.includes('instance') || /^i-[0-9a-f]+/.test(r)) return 'ec2';
    if (r.includes('lambda') || r.includes(':function:') || r.includes('function')) return 'lambda';
    if (r.includes('rds') || r.includes(':db:') || r.includes('postgres') || r.includes('mysql')) return 'rds';
    if (r.includes('vpc') || r.includes('subnet') || r.includes(':vpc/')) return 'vpc';
    if (r.includes('sg-') || r.includes('security-group') || r.includes(':security-group/')) return 'sg';
    if (r.includes('kms') || r.includes(':key/')) return 'kms';
    if (r.includes('eks') || r.includes('pod') || r.includes('cluster') || r.includes('container')) return 'eks';
    if (r.includes('sqs') || r.includes(':queue/')) return 'sqs';
    if (r.includes('sns') || r.includes(':topic/')) return 'sns';
    return 'generic';
}

function _shortName(resource, description) {
    const s = String(resource || '');
    if (!s || /^\d+$/.test(s)) return description ? String(description).slice(0, 28) : `Step ${s}`;
    if (s.includes('/')) return s.split('/').pop().slice(0, 26);
    if (s.includes(':')) return s.split(':').pop().slice(0, 26);
    return s.length > 26 ? s.slice(0, 24) + '…' : s;
}

// Satellite node — dashed-border box shown above (config) or below (vuln)
function SatelliteNode({ kind, count, severity }) {
    const isConfig = kind === 'config';
    const color = isConfig ? '#DC2626' : '#EA580C';
    const bg    = isConfig ? 'rgba(220,38,38,0.06)' : 'rgba(234,88,12,0.06)';
    const bdr   = isConfig ? 'rgba(220,38,38,0.45)' : 'rgba(234,88,12,0.45)';
    const title = isConfig ? 'Misconfiguration' : 'Vulnerability';
    const value = isConfig ? `${count} issue${count !== 1 ? 's' : ''}` : `${count} CVE${count !== 1 ? 's' : ''}`;
    const sev   = severity ? String(severity).toUpperCase() : null;

    return (
        <div style={{
            width: '100%', height: SAT_H, boxSizing: 'border-box',
            backgroundColor: bg,
            border: `1.5px dashed ${bdr}`,
            borderRadius: 7,
            display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: 2,
            padding: '4px 8px',
        }}>
            <span style={{
                fontSize: 8, fontWeight: 800, color,
                textTransform: 'uppercase', letterSpacing: '0.07em',
            }}>
                {title}
            </span>
            <span style={{ fontSize: 13, fontWeight: 800, color, lineHeight: 1.1 }}>
                {value}
            </span>
            {sev && (
                <span style={{
                    fontSize: 7, fontWeight: 700, color, opacity: 0.75,
                    textTransform: 'uppercase', letterSpacing: '0.06em',
                }}>
                    {sev}
                </span>
            )}
        </div>
    );
}

// Full-detail resource card — type chip, icon circle, name, description, MITRE pills
function ResourceCard({ step, isFirst, isLast }) {
    const rtype  = _detectRtype(step.resource, step.action);
    const color  = RTYPE_COLOR[rtype];
    const abbr   = RTYPE_ABBR[rtype];
    const label  = RTYPE_LABEL[rtype];
    const name   = _shortName(step.resource, step.description);
    const techs  = Array.isArray(step.mitre_techniques) ? step.mitre_techniques : [];
    const desc   = step.description && String(step.description) !== String(step.resource)
        ? String(step.description).slice(0, 52) + (step.description.length > 52 ? '…' : '')
        : null;
    const borderColor = isFirst ? '#DC2626' : isLast ? '#EA580C' : 'var(--border-primary)';
    const glow        = isFirst
        ? '0 0 0 3px rgba(220,38,38,0.08)'
        : isLast ? '0 0 0 3px rgba(234,88,12,0.08)' : 'none';

    return (
        <div style={{
            width: '100%', borderRadius: 8, padding: '8px 10px 8px',
            backgroundColor: 'var(--bg-secondary)',
            border: `1.5px solid ${borderColor}`,
            boxShadow: glow,
            boxSizing: 'border-box',
        }}>
            {/* Type chip + step number */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{
                    fontSize: 8, fontWeight: 800, padding: '1px 6px',
                    letterSpacing: '0.07em', textTransform: 'uppercase',
                    backgroundColor: `${color}15`, border: `1px solid ${color}30`,
                    borderRadius: 3, color,
                }}>
                    {label}
                </span>
                <span style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600 }}>
                    #{step.step ?? '?'}
                </span>
            </div>

            {/* Icon circle + resource name */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: desc ? 5 : 4 }}>
                <div style={{
                    flexShrink: 0, width: 26, height: 26, borderRadius: '50%',
                    backgroundColor: `${color}15`, border: `1.5px solid ${color}35`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                    <span style={{
                        fontSize: 8, fontWeight: 800, color,
                        textTransform: 'uppercase', letterSpacing: '0.03em',
                    }}>
                        {abbr}
                    </span>
                </div>
                <span style={{
                    fontSize: 11, fontWeight: 700, color: 'var(--text-primary)',
                    wordBreak: 'break-all', lineHeight: 1.25,
                }}>
                    {name}
                </span>
            </div>

            {/* Description */}
            {desc && (
                <p style={{
                    fontSize: 9, color: 'var(--text-muted)',
                    lineHeight: 1.35, margin: '0 0 5px',
                }}>
                    {desc}
                </p>
            )}

            {/* MITRE technique pills */}
            {techs.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                    {techs.slice(0, 2).map((t, i) => (
                        <span key={i} style={{
                            fontSize: 8, fontWeight: 700, padding: '1px 5px',
                            backgroundColor: 'rgba(234,88,12,0.09)',
                            border: '1px solid rgba(234,88,12,0.25)',
                            borderRadius: 3, color: '#EA580C', letterSpacing: '0.03em',
                        }}>
                            {t}
                        </span>
                    ))}
                    {techs.length > 2 && (
                        <span style={{ fontSize: 8, color: 'var(--text-muted)', alignSelf: 'center' }}>
                            +{techs.length - 2}
                        </span>
                    )}
                </div>
            )}
        </div>
    );
}

// Horizontal arrow — lives in the card row so it always aligns to card center
function AttackEdge({ action }) {
    return (
        <div style={{
            width: EDGE_W, flexShrink: 0,
            display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: 3,
        }}>
            {action && (
                <span style={{
                    fontSize: 8, fontWeight: 600, color: 'var(--text-muted)',
                    textAlign: 'center', lineHeight: 1.3, maxWidth: EDGE_W - 8,
                }}>
                    {String(action).length > 16 ? String(action).slice(0, 14) + '…' : action}
                </span>
            )}
            <div style={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                <div style={{ flex: 1, height: 1.5, backgroundColor: 'rgba(234,88,12,0.35)' }} />
                <svg width={9} height={9} viewBox="0 0 10 10" style={{ flexShrink: 0, marginLeft: -1 }}>
                    <path d="M2 1.5 L8.5 5 L2 8.5 Z" fill="#EA580C" />
                </svg>
            </div>
        </div>
    );
}

// 5-row layout:
//   [config satellite row]  ← hidden if no node has config
//   [config wire row]       ← hidden if no node has config
//   [resource card row]     ← always shown; arrows sit here → always aligned
//   [cve wire row]          ← hidden if no node has CVE
//   [cve satellite row]     ← hidden if no node has CVE
function AttackChainViz({ steps = [], configCount = 0, configSeverity, cveCount = 0 }) {
    if (!steps.length) return null;
    const n = steps.length;

    const nodes = steps.map((step, i) => ({
        step,
        cfg:    step.config_count    ?? (i === 0     ? configCount  : 0),
        cfgSev: step.config_severity ?? configSeverity,
        cve:    step.cve_count       ?? (i === n - 1 ? cveCount     : 0),
        isFirst: i === 0,
        isLast:  i === n - 1,
    }));

    const showConfigRow = nodes.some((nd) => nd.cfg > 0);
    const showCveRow    = nodes.some((nd) => nd.cve > 0);

    // Each map item wraps [COL cell + optional GAP] in one flex div so no Fragment key needed
    function nodeRow(renderCell, alignItems = 'stretch') {
        return (
            <div style={{ display: 'flex', alignItems }}>
                {nodes.map((nd, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center' }}>
                        <div style={{ width: CARD_W, display: 'flex', justifyContent: 'center' }}>
                            {renderCell(nd)}
                        </div>
                        {i < n - 1 && <div style={{ width: EDGE_W }} />}
                    </div>
                ))}
            </div>
        );
    }

    return (
        <div style={{ overflowX: 'auto', paddingBottom: 4 }}>
            <div style={{ display: 'inline-flex', flexDirection: 'column', gap: 0, width: 'max-content' }}>

                {/* Row 1: Config satellite boxes */}
                {showConfigRow && nodeRow((nd) =>
                    nd.cfg > 0
                        ? <SatelliteNode kind="config" count={nd.cfg} severity={nd.cfgSev} />
                        : <div style={{ height: SAT_H }} />
                , 'flex-end')}

                {/* Row 2: Config → card vertical wires */}
                {showConfigRow && nodeRow((nd) => (
                    <div style={{
                        width: 2, height: WIRE_H, borderRadius: 1,
                        backgroundColor: nd.cfg > 0 ? 'rgba(220,38,38,0.4)' : 'transparent',
                    }} />
                ))}

                {/* Row 3: Resource cards + horizontal arrows (always shown, arrows always aligned) */}
                <div style={{ display: 'flex', alignItems: 'center' }}>
                    {nodes.map((nd, i) => (
                        <div key={i} style={{ display: 'flex', alignItems: 'center' }}>
                            <div style={{ width: CARD_W }}>
                                <ResourceCard step={nd.step} isFirst={nd.isFirst} isLast={nd.isLast} />
                            </div>
                            {i < n - 1 && (
                                <AttackEdge action={steps[i + 1]?.action || nd.step.action} />
                            )}
                        </div>
                    ))}
                </div>

                {/* Row 4: Card → CVE vertical wires */}
                {showCveRow && nodeRow((nd) => (
                    <div style={{
                        width: 2, height: WIRE_H, borderRadius: 1,
                        backgroundColor: nd.cve > 0 ? 'rgba(234,88,12,0.4)' : 'transparent',
                    }} />
                ))}

                {/* Row 5: CVE satellite boxes */}
                {showCveRow && nodeRow((nd) =>
                    nd.cve > 0
                        ? <SatelliteNode kind="vuln" count={nd.cve} />
                        : <div style={{ height: SAT_H }} />
                , 'flex-start')}

            </div>
        </div>
    );
}


// ── Misconfig row ──────────────────────────────────────────────────────────────

function MisconfigRow({ finding }) {
    const sevKey = (finding.severity || 'info').toLowerCase();
    const { text } = SEV_COLORS[sevKey] || SEV_COLORS.info;
    return (
        <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '6px 0', borderBottom: '1px solid var(--border-primary)', fontSize: 12,
        }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: text, flexShrink: 0 }} />
            <span style={{ flex: 1, color: 'var(--text-secondary)', fontWeight: 500 }}>
                {finding.rule_id || finding.check_title || 'Unknown'}
            </span>
            <span style={{ fontSize: 10, fontWeight: 700, color: text, textTransform: 'uppercase' }}>
                {finding.severity}
            </span>
        </div>
    );
}

// ── Button styles ──────────────────────────────────────────────────────────────

const primaryBtn = {
    backgroundColor: '#EA580C', color: '#fff', border: 'none',
    borderRadius: 6, padding: '8px 18px', fontSize: 13, fontWeight: 700, cursor: 'pointer',
};

const secondaryBtn = {
    backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)',
    border: '1px solid var(--border-primary)',
    borderRadius: 6, padding: '8px 18px', fontSize: 13, fontWeight: 600, cursor: 'pointer',
};

// ── ScenarioModal ──────────────────────────────────────────────────────────────

export function ScenarioModal({ scenario, onClose, userRole }) {
    if (typeof document === 'undefined') return null;

    const canWrite = WRITE_ROLES.includes(userRole);
    const modalWidth = typeof window !== 'undefined' ? Math.min(800, window.innerWidth - 40) : 800;

    return createPortal(
        <>
            {/* Backdrop */}
            <div
                onClick={onClose}
                style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.55)', zIndex: 200 }}
            />

            {/* Modal */}
            <div
                role="dialog"
                aria-modal="true"
                aria-label={scenario.title}
                style={{
                    position: 'fixed', top: '50%', left: '50%',
                    transform: 'translate(-50%, -50%)',
                    width: modalWidth, maxHeight: '80vh', overflowY: 'auto',
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 10, boxShadow: '0 24px 48px rgba(0,0,0,0.35)',
                    zIndex: 201, padding: 24,
                }}
            >
                {/* Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                    <div style={{ flex: 1, marginRight: 12 }}>
                        <h2 style={{
                            fontSize: 18, fontWeight: 700, color: 'var(--text-primary)',
                            marginBottom: 8, lineHeight: 1.3,
                        }}>
                            {scenario.title}
                        </h2>
                        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                            <SeverityBadge severity={scenario.severity} />
                            <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                                Risk: <strong style={{ color: 'var(--text-primary)' }}>{scenario.risk_score}</strong>
                            </span>
                            {scenario.csp && (
                                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                                    {scenario.csp.toUpperCase()}{scenario.region ? `/${scenario.region}` : ''}
                                </span>
                            )}
                        </div>
                    </div>
                    <button
                        onClick={onClose}
                        aria-label="Close"
                        style={{
                            background: 'none', border: 'none', cursor: 'pointer',
                            fontSize: 20, color: 'var(--text-muted)', padding: 4, lineHeight: 1, flexShrink: 0,
                        }}
                    >
                        {'✕'}
                    </button>
                </div>

                <Divider />

                {/* Attack chain */}
                {scenario.attack_chain?.length > 0 && (
                    <>
                        <SectionTitle>
                            Attack Chain — {scenario.attack_chain.length} hop{scenario.attack_chain.length !== 1 ? 's' : ''}
                        </SectionTitle>
                        <AttackChainViz
                            steps={scenario.attack_chain}
                            configCount={scenario.top_findings?.length || 0}
                            cveCount={scenario.cve_count || 0}
                        />
                        <Divider />
                    </>
                )}

                {/* Top misconfigurations */}
                {scenario.top_findings?.length > 0 && (
                    <>
                        <SectionTitle>Top Misconfigurations ({scenario.top_findings.length})</SectionTitle>
                        {scenario.top_findings.map((f, i) => <MisconfigRow key={i} finding={f} />)}
                        <Divider />
                    </>
                )}

                {/* Resource */}
                {scenario.resource_name && (
                    <div style={{ marginBottom: 16 }}>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)', marginRight: 6 }}>Resource:</span>
                        <span style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 500 }}>
                            {scenario.resource_name}
                        </span>
                    </div>
                )}

                {/* Role-gated actions */}
                {canWrite && (
                    <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
                        <button style={primaryBtn}>Assign</button>
                        <button style={secondaryBtn}>Suppress</button>
                    </div>
                )}

                {/* Footer links */}
                <div style={{
                    display: 'flex', gap: 10,
                    borderTop: canWrite ? '1px solid var(--border-primary)' : 'none',
                    marginTop: canWrite ? 8 : 0,
                    paddingTop: canWrite ? 8 : 0,
                }}>
                    <Link
                        href={`/threats/graph?highlight_path=${encodeURIComponent(scenario.scenario_id)}`}
                        style={{
                            flex: 1, display: 'block', textAlign: 'center',
                            color: 'var(--text-secondary)', fontWeight: 600, fontSize: 13,
                            textDecoration: 'none', padding: '8px 0',
                            border: '1px solid var(--border-primary)',
                            borderRadius: 6, backgroundColor: 'var(--bg-secondary)',
                        }}
                    >
                        View in Graph
                    </Link>
                    <Link
                        href={`/threats/${scenario.scenario_id}`}
                        style={{
                            flex: 1, display: 'block', textAlign: 'center',
                            color: 'var(--accent-primary, #EA580C)', fontWeight: 600, fontSize: 13,
                            textDecoration: 'none', padding: '8px 0',
                            border: '1px solid rgba(234,88,12,0.3)', borderRadius: 6,
                        }}
                    >
                        View Full Details
                    </Link>
                </div>
            </div>
        </>,
        document.body
    );
}
