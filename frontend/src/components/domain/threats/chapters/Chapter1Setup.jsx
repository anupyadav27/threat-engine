'use client';

/**
 * Chapter1Setup — "The Setup" chapter of the Scenario Detail Panel.
 *
 * Renders:
 *  1. Vertical timeline — one dot per contributing_finding (ordered by
 *     first_seen_at ascending) plus a final "Scenario assembled" dot.
 *  2. Resource Context block — resource metadata, tags, owner, data classes.
 *  3. Risk Narrative — stakes_narrative prose or generated fallback.
 *
 * @param {Object}   props
 * @param {Object}   props.data                  - Full scenario detail object from BFF
 * @param {Function} props.onJumpToFinding        - Called with finding_id to highlight in Ch2
 */

import { useMemo, useState } from 'react';

// Signal type dot colours (story spec §Chapter1)
const SIGNAL_DOT_COLORS = {
    misconfig:     '#3B82F6',
    identity:      '#0D9488',
    vulnerability: '#8B5CF6',
    network:       '#F97316',
    ai_security:   '#EC4899',
};

const DATA_CLASS_COLORS = {
    PII:       '#DC2626',
    SENSITIVE: '#D97706',
    FINANCIAL: '#7C3AED',
    INTERNAL:  '#64748B',
};

// ── Timeline dot tooltip ──────────────────────────────────────────────────────

function TimelineDot({ color, tooltip, onClick, isAssembled = false }) {
    const [showTip, setShowTip] = useState(false);

    return (
        <div
            style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}
            onMouseEnter={() => setShowTip(true)}
            onMouseLeave={() => setShowTip(false)}
        >
            {isAssembled ? (
                /* Star-like assembled dot */
                <div
                    onClick={onClick}
                    style={{
                        width: 18,
                        height: 18,
                        borderRadius: 4,
                        backgroundColor: '#EA580C',
                        border: '2px solid #EA580C',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexShrink: 0,
                    }}
                >
                    <svg width={10} height={10} viewBox="0 0 10 10" aria-hidden="true">
                        <polygon
                            points="5,1 6.2,4 9.5,4 7,6.2 8,9.5 5,7.5 2,9.5 3,6.2 0.5,4 3.8,4"
                            fill="#fff"
                        />
                    </svg>
                </div>
            ) : (
                <div
                    onClick={onClick}
                    style={{
                        width: 14,
                        height: 14,
                        borderRadius: '50%',
                        backgroundColor: color,
                        border: `2px solid ${color}`,
                        cursor: onClick ? 'pointer' : 'default',
                        flexShrink: 0,
                        transition: 'transform 150ms ease',
                    }}
                    onMouseEnter={(e) => { if (onClick) e.currentTarget.style.transform = 'scale(1.3)'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.transform = 'scale(1)'; }}
                />
            )}

            {/* Tooltip */}
            {showTip && tooltip && (
                <div
                    style={{
                        position: 'absolute',
                        left: 24,
                        top: '50%',
                        transform: 'translateY(-50%)',
                        backgroundColor: '#1E293B',
                        border: '1px solid #334155',
                        borderRadius: 6,
                        padding: '6px 10px',
                        fontSize: 11,
                        color: '#CBD5E1',
                        whiteSpace: 'nowrap',
                        maxWidth: 260,
                        whiteSpace: 'normal',
                        lineHeight: 1.5,
                        zIndex: 50,
                        pointerEvents: 'none',
                        boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
                    }}
                >
                    {tooltip}
                </div>
            )}
        </div>
    );
}

// ── Vertical timeline ─────────────────────────────────────────────────────────

function Timeline({ findings, scenarioFirstSeenAt, onJumpToFinding }) {
    const sorted = useMemo(() => {
        return [...findings].sort((a, b) => {
            const ta = a.first_seen_at || '';
            const tb = b.first_seen_at || '';
            return ta.localeCompare(tb);
        });
    }, [findings]);

    // Compute "window of opportunity" from first finding to scenario assembly
    const windowLabel = useMemo(() => {
        if (!sorted.length || !scenarioFirstSeenAt) return null;
        try {
            const first = new Date(sorted[0].first_seen_at || scenarioFirstSeenAt);
            const last = new Date(scenarioFirstSeenAt);
            const diff = Math.abs(last - first);
            const hours = Math.round(diff / 3_600_000);
            if (hours === 0) return null;
            if (hours < 24) return `${hours}-hour window of opportunity`;
            return `${Math.round(hours / 24)}-day window of opportunity`;
        } catch {
            return null;
        }
    }, [sorted, scenarioFirstSeenAt]);

    if (!sorted.length) {
        return (
            <p style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                No contributing findings available for timeline.
            </p>
        );
    }

    return (
        <div style={{ position: 'relative', paddingLeft: 28 }}>
            {/* Vertical line */}
            <div
                style={{
                    position: 'absolute',
                    left: 6,
                    top: 7,
                    bottom: 7,
                    width: 2,
                    backgroundColor: 'var(--border-primary)',
                    borderRadius: 2,
                }}
            />

            {sorted.map((finding, idx) => {
                const color = SIGNAL_DOT_COLORS[finding.signal_type] || '#64748B';
                const isLast = idx === sorted.length - 1;
                const label = finding.rule_name || finding.rule_id || finding.signal_type || 'Finding';
                const ts = finding.first_seen_at
                    ? new Date(finding.first_seen_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
                    : '—';

                return (
                    <div key={finding.finding_id || idx} style={{ marginBottom: isLast && windowLabel ? 0 : 16, display: 'flex', alignItems: 'center', gap: 10 }}>
                        <TimelineDot
                            color={color}
                            tooltip={finding.plain_english || label}
                            onClick={() => onJumpToFinding && onJumpToFinding(finding.finding_id)}
                        />
                        <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {label}
                            </div>
                            <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{ts}</div>
                        </div>
                    </div>
                );
            })}

            {/* Window of opportunity annotation */}
            {windowLabel && (
                <div style={{ marginTop: 0, marginBottom: 16, paddingLeft: 24, marginLeft: -14 }}>
                    <div
                        style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 5,
                            fontSize: 10,
                            color: '#D97706',
                            backgroundColor: '#D9770615',
                            border: '1px dashed #D9770650',
                            borderRadius: 4,
                            padding: '2px 8px',
                        }}
                    >
                        <span aria-hidden="true">&#9679;</span>
                        {windowLabel}
                    </div>
                </div>
            )}

            {/* Scenario assembled dot */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <TimelineDot
                    isAssembled
                    tooltip="Scenario assembled by threat engine"
                    onClick={null}
                />
                <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#EA580C' }}>Scenario assembled</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                        {scenarioFirstSeenAt
                            ? new Date(scenarioFirstSeenAt).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
                            : '—'}
                    </div>
                </div>
            </div>
        </div>
    );
}

// ── Resource context block ────────────────────────────────────────────────────

function ResourceContext({ resourceMetadata, resourceUid }) {
    const {
        name = '',
        type = '',
        region = '',
        account_id = '',
        tags = {},
        data_classification = [],
        estimated_record_count = null,
    } = resourceMetadata || {};

    const owner = tags?.owner || '—';

    function formatRecordCount(n) {
        if (!n) return null;
        if (n >= 1_000_000) return `~${(n / 1_000_000).toFixed(1)}M records`;
        if (n >= 1_000) return `~${Math.round(n / 1_000)}k records`;
        return `${n} records`;
    }

    return (
        <div
            style={{
                backgroundColor: 'var(--bg-tertiary)',
                border: '1px solid var(--border-primary)',
                borderRadius: 8,
                padding: '12px 14px',
                display: 'flex',
                flexDirection: 'column',
                gap: 10,
            }}
        >
            {/* Resource name + type */}
            <div>
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>{name || resourceUid || '—'}</span>
                {type && (
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 6 }}>{type}</span>
                )}
            </div>

            {/* Region + account */}
            {(region || account_id) && (
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', display: 'flex', gap: 10 }}>
                    {region && <span>Region: <strong>{region}</strong></span>}
                    {account_id && <span>Account: <strong>{account_id}</strong></span>}
                </div>
            )}

            {/* Owner */}
            <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                Owner: <strong>{owner}</strong>
            </div>

            {/* Data classification badges */}
            {data_classification.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                    {data_classification.map((cls) => {
                        const color = DATA_CLASS_COLORS[cls] || '#64748B';
                        return (
                            <span
                                key={cls}
                                style={{
                                    fontSize: 10,
                                    fontWeight: 700,
                                    padding: '2px 8px',
                                    borderRadius: 9999,
                                    backgroundColor: `${color}18`,
                                    border: `1px solid ${color}50`,
                                    color,
                                    textTransform: 'uppercase',
                                    letterSpacing: '0.04em',
                                }}
                            >
                                {cls}
                            </span>
                        );
                    })}
                    {estimated_record_count && (
                        <span style={{ fontSize: 10, color: 'var(--text-muted)', alignSelf: 'center' }}>
                            {formatRecordCount(estimated_record_count)}
                        </span>
                    )}
                </div>
            )}

            {/* Tags */}
            {Object.keys(tags).length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {Object.entries(tags).map(([k, v]) => (
                        <span
                            key={k}
                            style={{
                                fontSize: 10,
                                padding: '1px 6px',
                                borderRadius: 4,
                                backgroundColor: 'var(--bg-card)',
                                border: '1px solid var(--border-primary)',
                                color: 'var(--text-muted)',
                                fontFamily: 'monospace',
                            }}
                        >
                            {k}={v}
                        </span>
                    ))}
                </div>
            )}
        </div>
    );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Chapter1Setup({ data = {}, onJumpToFinding }) {
    const {
        contributing_findings = [],
        resource_metadata = {},
        resource_uid = '',
        resource_type = '',
        resource_name = '',
        stakes_narrative = '',
        first_seen_at = '',
    } = data;

    // Build fallback narrative
    const narrativeText = stakes_narrative && stakes_narrative.trim()
        ? stakes_narrative
        : contributing_findings.length > 0
            ? `This scenario combines ${contributing_findings.length} signal${contributing_findings.length > 1 ? 's' : ''} into a multi-stage attack path. ` +
              `The primary entry point is via ${contributing_findings[0]?.rule_name || 'a misconfiguration'}. ` +
              `Once exploited, the attacker gains access to ${resource_type || 'resource'} ${resource_name || resource_uid}.`
            : `This threat scenario involves ${resource_type || 'a resource'} and requires investigation.`;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, paddingBottom: 12 }}>
            {/* Section: Timeline */}
            <div>
                <div
                    style={{
                        fontSize: 11,
                        fontWeight: 700,
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.07em',
                        marginBottom: 14,
                    }}
                >
                    Attack Timeline
                </div>
                <Timeline
                    findings={contributing_findings}
                    scenarioFirstSeenAt={first_seen_at}
                    onJumpToFinding={onJumpToFinding}
                />
            </div>

            {/* Section: Resource Context */}
            <div>
                <div
                    style={{
                        fontSize: 11,
                        fontWeight: 700,
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.07em',
                        marginBottom: 10,
                    }}
                >
                    Resource Context
                </div>
                <ResourceContext
                    resourceMetadata={resource_metadata}
                    resourceUid={resource_uid}
                />
            </div>

            {/* Section: Risk Narrative */}
            <div>
                <div
                    style={{
                        fontSize: 11,
                        fontWeight: 700,
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.07em',
                        marginBottom: 10,
                    }}
                >
                    Risk Narrative
                </div>
                <p
                    style={{
                        fontSize: 13,
                        color: 'var(--text-secondary)',
                        lineHeight: 1.7,
                        margin: 0,
                        borderLeft: '3px solid var(--border-primary)',
                        paddingLeft: 12,
                    }}
                >
                    {narrativeText}
                </p>
            </div>
        </div>
    );
}
