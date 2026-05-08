'use client';

/**
 * Chapter2Anatomy — "The Anatomy" chapter of the Scenario Detail Panel.
 *
 * Renders contributing_findings as signal-typed cards with lane accents,
 * expandable Raw Evidence (inline JSON syntax highlight — NO external lib),
 * expandable Fix Guidance, CIEM permissions bar, vulnerability exploit badge,
 * and a Signal Interaction Map at the bottom.
 *
 * @param {Object}   props
 * @param {Object}   props.data                  - Full scenario detail object from BFF
 * @param {string}   props.highlightedFindingId   - finding_id to scroll+highlight
 * @param {Function} props.onJumpToFinding         - Set parent highlight state
 */

import { useEffect, useRef, useState } from 'react';
import SignalInteractionMap from './SignalInteractionMap';

// Lane accent colours by signal type (story spec §Chapter2)
const LANE_COLORS = {
    misconfig:     '#F97316',
    identity:      '#8B5CF6',
    vulnerability: '#DC2626',
    network:       '#3B82F6',
    ai_security:   '#EC4899',
};

const SEV_COLORS = {
    critical: '#DC2626',
    high:     '#EA580C',
    medium:   '#D97706',
    low:      '#64748B',
    info:     '#6B7280',
};

// Sort order for signal types
const SIGNAL_ORDER = ['misconfig', 'identity', 'vulnerability', 'network', 'ai_security'];

// ── Inline minimal JSON syntax highlighter ────────────────────────────────────
// Only uses CSS colour tokens — NO external libraries (AC8)

function JsonHighlight({ value }) {
    /**
     * Tokenise a JSON string into coloured spans.
     * Keys → #7DD3FC  Strings → #86EFAC  Numbers/booleans → #FCD34D
     */
    function tokenise(json) {
        const tokens = [];
        const re = /("(?:[^"\\]|\\.)*")\s*:|(\"(?:[^\"\\]|\\.)*\")|([-+]?(?:\d*\.?\d+(?:[eE][+-]?\d+)?)|\b(?:true|false|null)\b)/g;
        let lastIndex = 0;
        let m;
        while ((m = re.exec(json)) !== null) {
            if (m.index > lastIndex) {
                tokens.push({ type: 'plain', text: json.slice(lastIndex, m.index) });
            }
            if (m[1] !== undefined) {
                // Key
                tokens.push({ type: 'key', text: m[1] + json.slice(m.index + m[1].length, re.lastIndex) });
            } else if (m[2] !== undefined) {
                tokens.push({ type: 'string', text: m[2] });
            } else if (m[3] !== undefined) {
                tokens.push({ type: 'number', text: m[3] });
            }
            lastIndex = re.lastIndex;
        }
        if (lastIndex < json.length) {
            tokens.push({ type: 'plain', text: json.slice(lastIndex) });
        }
        return tokens;
    }

    let formatted;
    try {
        formatted = JSON.stringify(
            typeof value === 'string' ? JSON.parse(value) : value,
            null,
            2
        );
    } catch {
        formatted = String(value);
    }

    const tokens = tokenise(formatted);

    return (
        <pre
            style={{
                backgroundColor: '#0F172A',
                borderRadius: 6,
                padding: '10px 12px',
                fontSize: 11,
                lineHeight: 1.6,
                margin: 0,
                overflowX: 'auto',
                fontFamily: 'monospace',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
            }}
        >
            {tokens.map((tok, i) => {
                let color = '#94A3B8';
                if (tok.type === 'key') color = '#7DD3FC';
                else if (tok.type === 'string') color = '#86EFAC';
                else if (tok.type === 'number') color = '#FCD34D';
                return (
                    <span key={i} style={{ color }}>
                        {tok.text}
                    </span>
                );
            })}
        </pre>
    );
}

// ── Accordion section ─────────────────────────────────────────────────────────

function Accordion({ label, children, defaultOpen = false }) {
    const [open, setOpen] = useState(defaultOpen);
    const innerRef = useRef(null);

    return (
        <div>
            <button
                onClick={() => setOpen((v) => !v)}
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    padding: '6px 0',
                    fontSize: 11,
                    fontWeight: 700,
                    color: 'var(--text-secondary)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    width: '100%',
                    textAlign: 'left',
                }}
                aria-expanded={open}
            >
                <span
                    style={{
                        display: 'inline-block',
                        transition: 'transform 300ms ease',
                        transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
                        fontSize: 10,
                    }}
                    aria-hidden="true"
                >
                    &#9654;
                </span>
                {label}
            </button>
            <div
                style={{
                    overflow: 'hidden',
                    maxHeight: open ? 800 : 0,
                    transition: 'max-height 300ms ease',
                }}
            >
                <div ref={innerRef} style={{ paddingTop: 4, paddingBottom: 4 }}>
                    {children}
                </div>
            </div>
        </div>
    );
}

// ── AWS console link builder ──────────────────────────────────────────────────

function buildConsoleUrl(resourceType, resourceUid, region) {
    if (!resourceUid) return null;
    const rt = (resourceType || '').toLowerCase();

    // S3
    if (rt.includes('s3bucket') || rt.includes('s3')) {
        const bucketName = resourceUid.split(':::').pop() || resourceUid.split('/').pop();
        return `https://s3.console.aws.amazon.com/s3/buckets/${bucketName}${region ? `?region=${region}` : ''}`;
    }
    // IAM role
    if (rt.includes('iamrole')) {
        const roleName = resourceUid.split('/').pop();
        return `https://console.aws.amazon.com/iam/home#/roles/${roleName}`;
    }
    // EC2 instance
    if (rt.includes('ec2') || rt.includes('instance')) {
        const instanceId = resourceUid.split('/').pop();
        return `https://console.aws.amazon.com/ec2/v2/home?region=${region || 'us-east-1'}#Instances:instanceId=${instanceId}`;
    }
    // RDS
    if (rt.includes('rds') || rt.includes('dbinstance')) {
        const dbId = resourceUid.split(':').pop();
        return `https://console.aws.amazon.com/rds/home?region=${region || 'us-east-1'}#database:id=${dbId}`;
    }
    return null;
}

// ── CIEM permissions bar (identity signal type) ───────────────────────────────

function CiemPermissionsBar({ used, granted }) {
    if (used === null || used === undefined || !granted) return null;
    const pct = Math.min(100, Math.round((used / granted) * 100));
    return (
        <div style={{ marginTop: 8 }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                Used {used} of {granted} permissions in 30 days ({pct}%)
            </div>
            <div
                style={{
                    height: 6,
                    borderRadius: 3,
                    backgroundColor: '#0D943815',
                    overflow: 'hidden',
                    position: 'relative',
                }}
            >
                <div
                    style={{
                        width: `${pct}%`,
                        height: '100%',
                        backgroundColor: '#0D9488',
                        borderRadius: 3,
                        transition: 'width 400ms ease',
                    }}
                />
            </div>
            <div style={{ fontSize: 10, color: '#0D9488', marginTop: 2, textAlign: 'right' }}>
                {used} / {granted}
            </div>
        </div>
    );
}

// ── Exploit availability badge (vulnerability signal type) ────────────────────

function ExploitBadge({ availability }) {
    if (!availability || availability === 'None') {
        return (
            <span
                style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    fontSize: 10,
                    fontWeight: 600,
                    padding: '2px 8px',
                    borderRadius: 9999,
                    backgroundColor: '#1E293B',
                    border: '1px solid #334155',
                    color: '#94A3B8',
                }}
            >
                No public exploit
            </span>
        );
    }
    if (availability === 'PoC') {
        return (
            <span
                style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: 9999,
                    backgroundColor: '#D9770615',
                    border: '1px solid #D9770650',
                    color: '#D97706',
                }}
            >
                PoC Available
            </span>
        );
    }
    if (availability === 'Weaponized') {
        return (
            <span
                style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: 9999,
                    backgroundColor: '#DC262615',
                    border: '1px solid #DC262650',
                    color: '#DC2626',
                }}
            >
                &#9888; Weaponized
            </span>
        );
    }
    return null;
}

// ── Empty signal type placeholder ─────────────────────────────────────────────

function EmptySignalSlot({ signalType }) {
    const labels = {
        misconfig:     'Misconfiguration',
        identity:      'Identity',
        vulnerability: 'Vulnerability',
        network:       'Network',
    };
    const linkHrefs = {
        misconfig:     '/misconfig',
        identity:      '/iam',
        vulnerability: '/vulnerability',
        network:       '/network-security',
    };
    const label = labels[signalType] || signalType;
    const href = linkHrefs[signalType] || '/';
    return (
        <div
            style={{
                border: '1px dashed #334155',
                borderRadius: 8,
                padding: '12px 14px',
                display: 'flex',
                alignItems: 'center',
                gap: 10,
            }}
        >
            <span
                style={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    border: '2px solid #475569',
                    flexShrink: 0,
                    display: 'inline-block',
                }}
            />
            <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#475569' }}>
                    {label} signal — not present
                </div>
                <div style={{ fontSize: 11, color: '#64748B', marginTop: 2 }}>
                    No {label.toLowerCase()} findings contributed to this scenario.{' '}
                    <a href={href} style={{ color: '#EA580C', textDecoration: 'none', fontWeight: 600 }}>
                        Check {label.toLowerCase()} posture &#8594;
                    </a>
                </div>
            </div>
        </div>
    );
}

// ── Finding card ──────────────────────────────────────────────────────────────

function FindingCard({ finding, isHighlighted, onJumpToFinding, region }) {
    const cardRef = useRef(null);
    const laneColor = LANE_COLORS[finding.signal_type] || '#64748B';
    const sevColor = SEV_COLORS[finding.severity] || SEV_COLORS.info;

    // Scroll into view when highlighted
    useEffect(() => {
        if (isHighlighted && cardRef.current) {
            cardRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }, [isHighlighted]);

    const idShort = (finding.finding_id || '').slice(0, 8);
    const consoleUrl = buildConsoleUrl(finding.resource_type, finding.resource_uid || finding.resource_name, region);

    function copyId() {
        if (navigator?.clipboard && idShort) {
            navigator.clipboard.writeText(finding.finding_id || idShort);
        }
    }

    function copyEvidence() {
        if (navigator?.clipboard) {
            navigator.clipboard.writeText(
                JSON.stringify(finding.raw_evidence || {}, null, 2)
            );
        }
    }

    return (
        <div
            ref={cardRef}
            style={{
                borderLeft: `4px solid ${laneColor}`,
                backgroundColor: isHighlighted ? `${laneColor}08` : 'var(--bg-card)',
                border: `1px solid ${isHighlighted ? laneColor + '60' : 'var(--border-primary)'}`,
                borderLeft: `4px solid ${laneColor}`,
                borderRadius: 8,
                padding: '12px 14px',
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                transition: 'background-color 200ms ease, border-color 200ms ease',
            }}
        >
            {/* Row 1: signal type badge + rule_name / CVE */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span
                        style={{
                            fontSize: 9,
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: 9999,
                            backgroundColor: `${laneColor}20`,
                            border: `1px solid ${laneColor}50`,
                            color: laneColor,
                            textTransform: 'uppercase',
                            letterSpacing: '0.05em',
                        }}
                    >
                        {finding.signal_type}
                    </span>
                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
                        {finding.cve_id || finding.rule_name || finding.rule_id || '—'}
                    </span>
                </div>

                {/* Severity chip */}
                <span
                    style={{
                        fontSize: 9,
                        fontWeight: 700,
                        padding: '2px 6px',
                        borderRadius: 9999,
                        backgroundColor: `${sevColor}18`,
                        border: `1px solid ${sevColor}40`,
                        color: sevColor,
                        textTransform: 'uppercase',
                        flexShrink: 0,
                    }}
                >
                    {finding.severity}
                </span>
            </div>

            {/* Row 2: finding_id (copyable) + resource + MITRE */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                {idShort && (
                    <button
                        onClick={copyId}
                        title="Click to copy finding ID"
                        style={{
                            fontFamily: 'monospace',
                            fontSize: 10,
                            color: '#94A3B8',
                            backgroundColor: 'var(--bg-tertiary)',
                            border: '1px solid var(--border-primary)',
                            borderRadius: 3,
                            padding: '1px 5px',
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 3,
                        }}
                    >
                        {idShort}
                        <svg width={8} height={8} viewBox="0 0 16 16" aria-hidden="true">
                            <path d="M13 0H6a2 2 0 0 0-2 2 2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h7a2 2 0 0 0 2-2 2 2 0 0 0 2-2V2a2 2 0 0 0-2-2zm0 13H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h7a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1zM3 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h7a1 1 0 0 0 1-1v-1H5a2 2 0 0 1-2-2V5z" fill="currentColor" />
                        </svg>
                    </button>
                )}
                {finding.resource_name && (
                    <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                        {finding.resource_name}
                    </span>
                )}
                {finding.mitre_technique?.id && (
                    <span
                        style={{
                            fontSize: 10,
                            fontWeight: 700,
                            fontFamily: 'monospace',
                            padding: '1px 6px',
                            borderRadius: 4,
                            backgroundColor: '#334155',
                            color: '#CBD5E1',
                        }}
                        title={finding.mitre_technique.name}
                    >
                        {finding.mitre_technique.id}
                    </span>
                )}
            </div>

            {/* Plain English */}
            {finding.plain_english && (
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6, margin: 0 }}>
                    {finding.plain_english}
                </p>
            )}

            {/* CIEM-specific: permissions bar */}
            {finding.signal_type === 'identity' && (
                <CiemPermissionsBar
                    used={finding.permissions_used}
                    granted={finding.permissions_granted}
                />
            )}

            {/* Vulnerability-specific: exploit badge */}
            {finding.signal_type === 'vulnerability' && (
                <div>
                    <ExploitBadge availability={finding.exploit_availability} />
                </div>
            )}

            {/* Accordion: Raw Evidence */}
            {finding.raw_evidence && Object.keys(finding.raw_evidence).length > 0 && (
                <Accordion label="Raw Evidence">
                    <div style={{ position: 'relative' }}>
                        <button
                            onClick={copyEvidence}
                            title="Copy JSON to clipboard"
                            style={{
                                position: 'absolute',
                                top: 6,
                                right: 6,
                                background: '#1E293B',
                                border: '1px solid #334155',
                                borderRadius: 4,
                                padding: '2px 6px',
                                fontSize: 9,
                                color: '#94A3B8',
                                cursor: 'pointer',
                                zIndex: 1,
                            }}
                        >
                            Copy
                        </button>
                        <JsonHighlight value={finding.raw_evidence} />
                    </div>
                </Accordion>
            )}

            {/* Accordion: Fix Guidance */}
            {finding.fix_guidance && (
                <Accordion label="Fix Guidance">
                    <p
                        style={{
                            fontSize: 12,
                            color: 'var(--text-secondary)',
                            lineHeight: 1.6,
                            margin: 0,
                            padding: '4px 0',
                        }}
                    >
                        {finding.fix_guidance}
                    </p>
                </Accordion>
            )}

            {/* Footer links */}
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 2 }}>
                {finding.finding_id && (
                    <a
                        href={`/compliance?finding_id=${finding.finding_id}`}
                        style={{ fontSize: 11, color: '#EA580C', textDecoration: 'none', fontWeight: 600 }}
                    >
                        View in Compliance &#8594;
                    </a>
                )}
                {consoleUrl && (
                    <a
                        href={consoleUrl}
                        target="_blank"
                        rel="noreferrer noopener"
                        style={{ fontSize: 11, color: '#3B82F6', textDecoration: 'none', fontWeight: 600 }}
                    >
                        Open in AWS Console &#8599;
                    </a>
                )}
            </div>
        </div>
    );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Chapter2Anatomy({ data = {}, highlightedFindingId, onJumpToFinding }) {
    const {
        contributing_findings = [],
        region = '',
    } = data;

    // Sort findings by signal type priority (misconfig first, etc.)
    const sorted = [...contributing_findings].sort((a, b) => {
        const oa = SIGNAL_ORDER.indexOf(a.signal_type);
        const ob = SIGNAL_ORDER.indexOf(b.signal_type);
        return (oa < 0 ? 99 : oa) - (ob < 0 ? 99 : ob);
    });

    // Determine which signal types are present
    const presentSignals = new Set(sorted.map((f) => f.signal_type));

    // Signal types to show placeholders for (not ai_security by default)
    const placeholderTypes = SIGNAL_ORDER.filter(
        (st) => st !== 'ai_security' && !presentSignals.has(st)
    );

    if (!sorted.length) {
        return (
            <div style={{ padding: '20px 0', textAlign: 'center' }}>
                <p style={{ fontSize: 13, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    No contributing findings available for this scenario.
                </p>
            </div>
        );
    }

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Finding cards */}
            {sorted.map((finding) => (
                <FindingCard
                    key={finding.finding_id || finding.rule_id}
                    finding={finding}
                    isHighlighted={highlightedFindingId === finding.finding_id}
                    onJumpToFinding={onJumpToFinding}
                    region={region}
                />
            ))}

            {/* Empty signal type placeholders */}
            {placeholderTypes.length > 0 && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 4 }}>
                    {placeholderTypes.map((st) => (
                        <EmptySignalSlot key={st} signalType={st} />
                    ))}
                </div>
            )}

            {/* Signal Interaction Map (2+ findings only) */}
            <SignalInteractionMap
                findings={sorted}
                onJumpToFinding={onJumpToFinding}
            />
        </div>
    );
}
