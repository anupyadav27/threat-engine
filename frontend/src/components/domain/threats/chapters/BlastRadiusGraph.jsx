'use client';

/**
 * BlastRadiusGraph — static CSS flexbox read-only blast radius snapshot.
 *
 * Layout: root node (amber) → first-hop ring → second-hop ring → +N more node.
 * No D3, no external graph library — pure CSS flexbox + inline SVG connectors.
 *
 * @param {Object} props
 * @param {Object} props.blastRadius   - blast_radius object from BFF response
 * @param {string} props.seedResourceUid - resource_uid used for "Open in Graph Explorer" link
 */

import { useState } from 'react';
import Link from 'next/link';

const ENV_BADGE_COLORS = {
    prod:    '#22C55E',
    staging: '#F59E0B',
    dev:     '#3B82F6',
    test:    '#8B5CF6',
};

function envColor(tags) {
    if (!tags || typeof tags !== 'object') return '#64748B';
    const envVal = (tags.env || tags.environment || '').toLowerCase();
    for (const [key, color] of Object.entries(ENV_BADGE_COLORS)) {
        if (envVal.includes(key)) return color;
    }
    return '#64748B';
}

function NodeTooltip({ node, visible }) {
    if (!visible) return null;
    const color = envColor(node.tags);
    const envLabel = (node.tags?.env || node.tags?.environment || '').toUpperCase() || '—';

    return (
        <div
            style={{
                position: 'absolute',
                bottom: '110%',
                left: '50%',
                transform: 'translateX(-50%)',
                backgroundColor: '#1E293B',
                border: '1px solid #334155',
                borderRadius: 6,
                padding: '8px 10px',
                fontSize: 11,
                color: '#CBD5E1',
                whiteSpace: 'nowrap',
                zIndex: 100,
                pointerEvents: 'none',
                boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
                minWidth: 160,
            }}
        >
            <div style={{ fontWeight: 700, marginBottom: 3, color: '#F8FAFC', fontSize: 12 }}>
                {node.resource_name || (node.resource_uid || '').split('/').pop() || '—'}
            </div>
            <div style={{ color: '#94A3B8', fontSize: 10, marginBottom: 2 }}>{node.resource_type || '—'}</div>
            {node.data_class && (
                <div style={{ color: '#F59E0B', fontSize: 10, marginBottom: 2 }}>Data: {node.data_class}</div>
            )}
            <span
                style={{
                    display: 'inline-block',
                    fontSize: 9,
                    fontWeight: 700,
                    padding: '1px 5px',
                    borderRadius: 3,
                    backgroundColor: `${color}20`,
                    border: `1px solid ${color}60`,
                    color,
                }}
            >
                {envLabel}
            </span>
        </div>
    );
}

function GraphNode({ node, size = 32, color = '#64748B', label, onClick }) {
    const [showTip, setShowTip] = useState(false);
    const initials = (label || node.resource_type || '?').slice(0, 2).toUpperCase();

    return (
        <div
            style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, position: 'relative' }}
            onMouseEnter={() => setShowTip(true)}
            onMouseLeave={() => setShowTip(false)}
        >
            <NodeTooltip node={node} visible={showTip} />
            <div
                onClick={onClick}
                style={{
                    width: size,
                    height: size,
                    borderRadius: '50%',
                    backgroundColor: `${color}20`,
                    border: `2px solid ${color}`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: size > 40 ? 13 : 10,
                    fontWeight: 700,
                    color,
                    cursor: 'default',
                    flexShrink: 0,
                }}
            >
                {initials}
            </div>
            {label && (
                <span
                    style={{
                        fontSize: 9,
                        color: 'var(--text-muted)',
                        maxWidth: 70,
                        textAlign: 'center',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                        lineHeight: 1.3,
                    }}
                    title={label}
                >
                    {label}
                </span>
            )}
        </div>
    );
}

function ThirdHopNode({ count }) {
    const [showList, setShowList] = useState(false);

    return (
        <div style={{ position: 'relative', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
            <div
                onClick={() => setShowList((v) => !v)}
                title={`${count} more affected resources`}
                style={{
                    width: 32,
                    height: 32,
                    borderRadius: '50%',
                    border: '2px dashed #64748B',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: 9,
                    fontWeight: 700,
                    color: '#64748B',
                    cursor: 'pointer',
                    flexShrink: 0,
                }}
            >
                +{count}
            </div>
            <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>more</span>
            {showList && (
                <div
                    style={{
                        position: 'absolute',
                        top: '110%',
                        left: '50%',
                        transform: 'translateX(-50%)',
                        backgroundColor: '#1E293B',
                        border: '1px solid #334155',
                        borderRadius: 6,
                        padding: '8px 10px',
                        fontSize: 10,
                        color: '#CBD5E1',
                        zIndex: 50,
                        whiteSpace: 'nowrap',
                        boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
                    }}
                >
                    <div style={{ fontWeight: 700, marginBottom: 4, fontSize: 11 }}>+{count} additional resources</div>
                    <div style={{ color: '#94A3B8', fontSize: 10 }}>Open Graph Explorer for full view</div>
                </div>
            )}
        </div>
    );
}

// ── Connector line SVG between columns ───────────────────────────────────────

function ConnectorArrow() {
    return (
        <svg width="24" height="16" viewBox="0 0 24 16" aria-hidden="true" style={{ flexShrink: 0, alignSelf: 'center', marginTop: -20 }}>
            <defs>
                <marker id="gr-arrow" markerWidth="6" markerHeight="5" refX="5" refY="2.5" orient="auto">
                    <polygon points="0 0, 6 2.5, 0 5" fill="#475569" />
                </marker>
            </defs>
            <line x1="0" y1="8" x2="20" y2="8" stroke="#475569" strokeWidth="1.5" markerEnd="url(#gr-arrow)" />
        </svg>
    );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function BlastRadiusGraph({ blastRadius = {}, seedResourceUid = '' }) {
    const {
        root_node = {},
        first_hop = [],
        second_hop = [],
        third_hop_count = 0,
    } = blastRadius;

    const hasContent = root_node.resource_uid || root_node.resource_type;
    const graphLink = `/threats/graph?seed=${encodeURIComponent(seedResourceUid || root_node.resource_uid || '')}`;

    if (!hasContent) {
        return (
            <div
                style={{
                    backgroundColor: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 8,
                    padding: '20px',
                    textAlign: 'center',
                    fontSize: 12,
                    color: 'var(--text-muted)',
                    fontStyle: 'italic',
                }}
            >
                Blast radius data not available.
            </div>
        );
    }

    const rootLabel = root_node.resource_name
        || (root_node.resource_uid || '').split('/').pop()
        || root_node.resource_type
        || 'Root';

    return (
        <div
            style={{
                backgroundColor: 'var(--bg-tertiary)',
                border: '1px solid var(--border-primary)',
                borderRadius: 8,
                padding: '16px',
                minHeight: 160,
                maxHeight: 420,
                overflow: 'hidden',
            }}
        >
            {/* Graph layout: root → first hop → second hop → +N */}
            <div
                style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 4,
                    overflowX: 'auto',
                    paddingBottom: 4,
                }}
            >
                {/* Root node (amber) */}
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                    <GraphNode
                        node={root_node}
                        size={48}
                        color="#F59E0B"
                        label={rootLabel}
                    />
                    {root_node.data_class && (
                        <span style={{ fontSize: 9, color: '#F59E0B', fontWeight: 700 }}>
                            {root_node.data_class}
                        </span>
                    )}
                </div>

                {/* First hop */}
                {first_hop.length > 0 && (
                    <>
                        <ConnectorArrow />
                        <div
                            style={{
                                display: 'flex',
                                flexDirection: 'column',
                                gap: 8,
                                flexShrink: 0,
                            }}
                        >
                            {first_hop.slice(0, 5).map((node, i) => (
                                <GraphNode
                                    key={node.resource_uid || i}
                                    node={node}
                                    size={32}
                                    color="#3B82F6"
                                    label={
                                        node.resource_name
                                        || (node.resource_uid || '').split('/').pop()
                                        || node.resource_type
                                    }
                                />
                            ))}
                            {first_hop.length > 5 && (
                                <span style={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center' }}>
                                    +{first_hop.length - 5} more
                                </span>
                            )}
                        </div>
                    </>
                )}

                {/* Second hop */}
                {second_hop.length > 0 && (
                    <>
                        <ConnectorArrow />
                        <div
                            style={{
                                display: 'flex',
                                flexDirection: 'column',
                                gap: 8,
                                flexShrink: 0,
                            }}
                        >
                            {second_hop.slice(0, 4).map((node, i) => (
                                <GraphNode
                                    key={node.resource_uid || i}
                                    node={node}
                                    size={24}
                                    color="#8B5CF6"
                                    label={
                                        node.resource_name
                                        || (node.resource_uid || '').split('/').pop()
                                        || node.resource_type
                                    }
                                />
                            ))}
                            {second_hop.length > 4 && (
                                <span style={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center' }}>
                                    +{second_hop.length - 4} more
                                </span>
                            )}
                        </div>
                    </>
                )}

                {/* Third hop count */}
                {third_hop_count > 0 && (
                    <>
                        <ConnectorArrow />
                        <div style={{ flexShrink: 0, alignSelf: 'center', marginTop: -8 }}>
                            <ThirdHopNode count={third_hop_count} />
                        </div>
                    </>
                )}
            </div>

            {/* Graph explorer link */}
            <div style={{ marginTop: 12, textAlign: 'right' }}>
                <Link
                    href={graphLink}
                    style={{
                        fontSize: 11,
                        color: '#EA580C',
                        textDecoration: 'none',
                        fontWeight: 600,
                    }}
                >
                    Open in Graph Explorer &#8599;
                </Link>
            </div>
        </div>
    );
}
