'use client';

/**
 * ScenarioCard — a single threat scenario card in Zone B of the Command Room.
 *
 * Displays severity, risk score, title, resource name, signal type badges,
 * MITRE technique chips, and CSP/region metadata.
 *
 * GRAPH-S3-01: clicking the graph icon navigates to /threats/graph?highlight_path=<scenario_id>
 * which pre-highlights that attack path in the security graph canvas.
 *
 * @param {Object}   props
 * @param {Object}   props.scenario       - Scenario object from BFF
 * @param {boolean}  props.isSelected     - Whether this card is currently selected
 * @param {boolean}  props.isHovered      - Whether this card is currently hovered (for Zone C)
 * @param {Function} props.onSelect       - Called when card is clicked
 * @param {Function} props.onHover        - Called when hover starts (after 50ms delay)
 * @param {Function} props.onHoverEnd     - Called when hover ends
 */

import { useState, useRef, useCallback } from 'react';
import Link from 'next/link';

// Signal type badge config — story spec §ScenarioCard
const SIGNAL_CONFIG = {
    misconfig:     { label: 'M', color: '#3B82F6' },
    vulnerability: { label: 'V', color: '#8B5CF6' },
    identity:      { label: 'I', color: '#0D9488' },
    network:       { label: 'N', color: '#F97316' },
    ai_security:   { label: 'A', color: '#EC4899' },
};

const SEV_COLORS = {
    critical: '#DC2626',
    high:     '#EA580C',
    medium:   '#D97706',
    low:      '#64748B',
    info:     '#6B7280',
};

function SignalBadge({ signalType }) {
    const cfg = SIGNAL_CONFIG[signalType];
    if (!cfg) return null;
    return (
        <span
            title={signalType}
            style={{
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: 20,
                height: 20,
                borderRadius: 4,
                backgroundColor: `${cfg.color}20`,
                border: `1px solid ${cfg.color}60`,
                color: cfg.color,
                fontSize: 10,
                fontWeight: 800,
                flexShrink: 0,
            }}
        >
            {cfg.label}
        </span>
    );
}

function MitreTechChip({ tech, onClick }) {
    return (
        <button
            onClick={(e) => { e.stopPropagation(); onClick && onClick(tech); }}
            style={{
                display: 'inline-block',
                padding: '1px 6px',
                borderRadius: 4,
                backgroundColor: '#334155',
                color: '#CBD5E1',
                fontSize: 10,
                fontWeight: 600,
                cursor: onClick ? 'pointer' : 'default',
                border: 'none',
            }}
        >
            {tech.id}
        </button>
    );
}

export default function ScenarioCard({
    scenario,
    isSelected = false,
    isHovered  = false,
    onSelect,
    onHover,
    onHoverEnd,
}) {
    const hoverTimer = useRef(null);
    const [showAllTech, setShowAllTech] = useState(false);

    const {
        scenario_id,
        title       = '',
        severity    = 'medium',
        risk_score  = 0,
        resource_name = '',
        resource_type = '',
        csp         = '',
        region      = '',
        signal_types = [],
        mitre_techniques = [],
    } = scenario || {};

    const sevColor = SEV_COLORS[severity] || SEV_COLORS.info;
    const visibleTech  = showAllTech ? mitre_techniques : mitre_techniques.slice(0, 3);
    const extraTech    = mitre_techniques.length - 3;

    const handleMouseEnter = useCallback(() => {
        hoverTimer.current = setTimeout(() => {
            onHover && onHover(scenario_id);
        }, 50);
    }, [scenario_id, onHover]);

    const handleMouseLeave = useCallback(() => {
        clearTimeout(hoverTimer.current);
        onHoverEnd && onHoverEnd();
    }, [onHoverEnd]);

    const handleClick = useCallback(() => {
        onSelect && onSelect(scenario);
    }, [onSelect, scenario]);

    return (
        <div
            onClick={handleClick}
            onMouseEnter={handleMouseEnter}
            onMouseLeave={handleMouseLeave}
            style={{
                backgroundColor: 'var(--bg-card)',
                border: '1px solid var(--border-primary)',
                borderLeft: isSelected ? '4px solid #EA580C' : '4px solid transparent',
                borderRadius: 8,
                padding: '12px 14px',
                cursor: 'pointer',
                minHeight: 80,
                transition: 'box-shadow 150ms ease, border-left-color 150ms ease',
                boxShadow: isSelected
                    ? '0 0 0 1px rgba(234,88,12,0.3), 0 4px 16px rgba(234,88,12,0.1)'
                    : isHovered
                        ? '0 4px 20px rgba(0,0,0,0.2)'
                        : '0 1px 4px rgba(0,0,0,0.08)',
            }}
        >
            {/* Row 1: severity + risk score + title */}
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 6 }}>
                {/* Severity dot + label */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0, marginTop: 2 }}>
                    <span
                        style={{
                            width: 8,
                            height: 8,
                            borderRadius: '50%',
                            backgroundColor: sevColor,
                            flexShrink: 0,
                        }}
                    />
                    <span style={{ fontSize: 10, fontWeight: 700, color: sevColor, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                        {severity}
                    </span>
                </div>

                {/* Risk score */}
                <span
                    style={{
                        fontSize: 20,
                        fontWeight: 900,
                        color: sevColor,
                        lineHeight: 1,
                        flexShrink: 0,
                    }}
                >
                    {risk_score}
                </span>

                {/* Title */}
                <p
                    style={{
                        fontSize: 13,
                        fontWeight: 600,
                        color: 'var(--text-primary)',
                        lineHeight: 1.4,
                        margin: 0,
                        flex: 1,
                    }}
                >
                    {title}
                </p>
            </div>

            {/* Row 2: resource name + signal badges + MITRE + CSP/region */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', paddingLeft: 22 }}>
                {/* Resource name */}
                {resource_name && (
                    <span
                        style={{
                            fontSize: 11,
                            fontWeight: 500,
                            color: 'var(--text-secondary)',
                            maxWidth: 160,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                        }}
                    >
                        {resource_name}
                    </span>
                )}

                {/* Signal type badges */}
                {signal_types.map((st) => (
                    <SignalBadge key={st} signalType={st} />
                ))}

                {/* MITRE technique chips */}
                {visibleTech.map((t) => (
                    <MitreTechChip key={t.id} tech={t} />
                ))}
                {!showAllTech && extraTech > 0 && (
                    <button
                        onClick={(e) => { e.stopPropagation(); setShowAllTech(true); }}
                        style={{
                            fontSize: 10,
                            fontWeight: 600,
                            color: 'var(--text-muted)',
                            backgroundColor: 'var(--bg-tertiary)',
                            border: '1px solid var(--border-primary)',
                            borderRadius: 4,
                            padding: '1px 6px',
                            cursor: 'pointer',
                        }}
                    >
                        +{extraTech} more
                    </button>
                )}

                {/* CSP + region */}
                {(csp || region) && (
                    <span
                        style={{
                            marginLeft: 'auto',
                            fontSize: 10,
                            color: 'var(--text-muted)',
                            whiteSpace: 'nowrap',
                        }}
                    >
                        {csp.toUpperCase()}{region ? `/${region}` : ''}
                    </span>
                )}

                {/* GRAPH-S3-01: View in graph — stops click propagation so card modal
                    does not open when the user explicitly wants to go to the graph. */}
                <Link
                    href={`/threats/graph?highlight_path=${encodeURIComponent(scenario_id)}`}
                    onClick={(e) => e.stopPropagation()}
                    title="View attack path in security graph"
                    style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 3,
                        fontSize: 10,
                        fontWeight: 600,
                        color: 'var(--text-muted)',
                        textDecoration: 'none',
                        padding: '1px 5px',
                        borderRadius: 4,
                        border: '1px solid var(--border-primary)',
                        backgroundColor: 'var(--bg-tertiary)',
                        whiteSpace: 'nowrap',
                        flexShrink: 0,
                    }}
                >
                    Graph
                </Link>
            </div>
        </div>
    );
}
