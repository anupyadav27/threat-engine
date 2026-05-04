'use client';

/**
 * Chapter3Stakes — "The Stakes" chapter of the Scenario Detail Panel.
 *
 * Renders:
 *  1. Stat chips row (resources at risk, identities, accounts, regions)
 *  2. Data classification badges + estimated record count
 *  3. Chain of Consequence prose (or fallback template)
 *  4. Mini Blast Radius Graph (CSS flexbox, no D3)
 *  5. Compliance Impact list
 *
 * @param {Object} props
 * @param {Object} props.data - Full scenario detail object from BFF
 */

import Link from 'next/link';
import BlastRadiusGraph from './BlastRadiusGraph';

const DATA_CLASS_COLORS = {
    PII:       '#DC2626',
    SENSITIVE: '#D97706',
    FINANCIAL: '#7C3AED',
    INTERNAL:  '#64748B',
};

const FRAMEWORK_COLORS = {
    GDPR:     '#3B82F6',
    'PCI-DSS': '#DC2626',
    HIPAA:    '#8B5CF6',
    SOC2:     '#0D9488',
    'ISO27001': '#6366F1',
    NIST:     '#F97316',
    CIS:      '#64748B',
};

// ── Stat chip ─────────────────────────────────────────────────────────────────

function StatChip({ label, value, color = 'var(--text-primary)' }) {
    return (
        <div
            style={{
                backgroundColor: 'var(--bg-tertiary)',
                border: '1px solid var(--border-primary)',
                borderRadius: 8,
                padding: '10px 14px',
                display: 'flex',
                flexDirection: 'column',
                gap: 2,
            }}
        >
            <span style={{ fontSize: 22, fontWeight: 900, color, lineHeight: 1 }}>{value}</span>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                {label}
            </span>
        </div>
    );
}

// ── Compute stat counts from blast_radius + findings ─────────────────────────

function computeStats(blastRadius, contributingFindings) {
    const allNodes = [
        ...(blastRadius.first_hop || []),
        ...(blastRadius.second_hop || []),
        ...(blastRadius.root_node?.resource_uid ? [blastRadius.root_node] : []),
    ];

    const uniqueResources = new Set(allNodes.map((n) => n.resource_uid).filter(Boolean)).size;
    const identityNodes = allNodes.filter((n) =>
        (n.resource_type || '').toLowerCase().includes('role')
        || (n.resource_type || '').toLowerCase().includes('user')
        || (n.resource_type || '').toLowerCase().includes('identity')
    ).length;

    const uniqueAccounts = new Set(
        contributingFindings.map((f) => f.account_id).filter(Boolean)
    ).size;
    const uniqueRegions = new Set(
        contributingFindings.map((f) => f.region).filter(Boolean)
    ).size;

    return {
        resources: uniqueResources || 1,
        identities: identityNodes,
        accounts: uniqueAccounts || 1,
        regions: uniqueRegions || 1,
    };
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Chapter3Stakes({ data = {} }) {
    const {
        contributing_findings = [],
        resource_metadata = {},
        resource_uid = '',
        resource_type = '',
        resource_name = '',
        chain_of_consequence = '',
        compliance_violations = [],
        blast_radius = {},
    } = data;

    const {
        data_classification = [],
        estimated_record_count = null,
    } = resource_metadata;

    const stats = computeStats(blast_radius, contributing_findings);

    // Chain of Consequence fallback
    const chainText = chain_of_consequence && chain_of_consequence.trim()
        ? chain_of_consequence
        : (() => {
            const dataClass = data_classification[0] || 'sensitive';
            const framework = compliance_violations[0]?.framework || 'applicable frameworks';
            return `This scenario could allow an attacker to access ${resource_type || 'resource'} ${resource_name || resource_uid || 'resource'} containing ${dataClass} data, potentially violating ${framework}.`;
        })();

    function formatRecordCount(n) {
        if (!n) return null;
        if (n >= 1_000_000) return `~${(n / 1_000_000).toFixed(1)}M records`;
        if (n >= 1_000) return `~${Math.round(n / 1_000)}k records`;
        return `${n} records`;
    }

    const shownViolations = compliance_violations.slice(0, 3);
    const hiddenCount = compliance_violations.length - 3;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, paddingBottom: 12 }}>
            {/* Stat chips 2x2 grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <StatChip label="Resources at risk" value={stats.resources} color="#EA580C" />
                <StatChip label="Identities at risk" value={stats.identities} color="#8B5CF6" />
                <StatChip label="Accounts" value={stats.accounts} color="#3B82F6" />
                <StatChip label="Regions" value={stats.regions} color="#0D9488" />
            </div>

            {/* Data classification */}
            {data_classification.length > 0 && (
                <div>
                    <div
                        style={{
                            fontSize: 11,
                            fontWeight: 700,
                            color: 'var(--text-muted)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.07em',
                            marginBottom: 8,
                        }}
                    >
                        Data Classification
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                        {data_classification.map((cls) => {
                            const color = DATA_CLASS_COLORS[cls] || '#64748B';
                            return (
                                <span
                                    key={cls}
                                    style={{
                                        fontSize: 11,
                                        fontWeight: 700,
                                        padding: '3px 10px',
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
                            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 500 }}>
                                {formatRecordCount(estimated_record_count)}
                            </span>
                        )}
                    </div>
                </div>
            )}

            {/* Chain of Consequence */}
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
                    Chain of Consequence
                </div>
                <div
                    style={{
                        borderLeft: '3px solid #EA580C',
                        paddingLeft: 12,
                        paddingTop: 4,
                        paddingBottom: 4,
                    }}
                >
                    <p
                        style={{
                            fontSize: 13,
                            color: 'var(--text-secondary)',
                            lineHeight: 1.7,
                            margin: 0,
                        }}
                    >
                        {chainText}
                    </p>
                </div>
            </div>

            {/* Blast Radius Graph */}
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
                    Blast Radius
                </div>
                <BlastRadiusGraph
                    blastRadius={blast_radius}
                    seedResourceUid={resource_uid}
                />
            </div>

            {/* Compliance Impact */}
            {compliance_violations.length > 0 && (
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
                        Compliance Impact
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {shownViolations.map((v, i) => {
                            const color = FRAMEWORK_COLORS[v.framework] || '#64748B';
                            return (
                                <div
                                    key={i}
                                    style={{
                                        display: 'flex',
                                        alignItems: 'flex-start',
                                        gap: 8,
                                        padding: '8px 10px',
                                        borderRadius: 6,
                                        backgroundColor: 'var(--bg-tertiary)',
                                        border: '1px solid var(--border-primary)',
                                    }}
                                >
                                    <span
                                        style={{
                                            fontSize: 9,
                                            fontWeight: 700,
                                            padding: '2px 6px',
                                            borderRadius: 4,
                                            backgroundColor: `${color}20`,
                                            border: `1px solid ${color}50`,
                                            color,
                                            flexShrink: 0,
                                            textTransform: 'uppercase',
                                            letterSpacing: '0.04em',
                                        }}
                                    >
                                        {v.framework}
                                    </span>
                                    <div>
                                        {v.control_id && (
                                            <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>
                                                {v.control_id}
                                            </div>
                                        )}
                                        {v.description && (
                                            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                                                {v.description}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                        {hiddenCount > 0 && (
                            <Link
                                href="/compliance"
                                style={{
                                    fontSize: 11,
                                    color: '#EA580C',
                                    textDecoration: 'none',
                                    fontWeight: 600,
                                    paddingLeft: 4,
                                }}
                            >
                                View {hiddenCount} more &#8594;
                            </Link>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
