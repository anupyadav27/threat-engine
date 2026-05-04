'use client';

/**
 * SignalInteractionMap — inline SVG arrow chain showing how signals chain together.
 *
 * Rendered inside Chapter2Anatomy below the finding cards.
 * Uses only inline SVG + CSS — no D3, no external graph library.
 *
 * Only renders when contributing_findings has 2 or more entries.
 *
 * @param {Object}   props
 * @param {Array}    props.findings        - contributing_findings array from BFF
 * @param {Function} props.onJumpToFinding - Called with finding_id on node click
 */

const SIGNAL_COLORS = {
    misconfig:     '#F97316',
    identity:      '#8B5CF6',
    vulnerability: '#DC2626',
    network:       '#3B82F6',
    ai_security:   '#EC4899',
};

// Node dimensions
const NODE_W = 110;
const NODE_H = 48;
const ARROW_GAP = 36;
const PADDING_X = 16;
const PADDING_Y = 16;

export default function SignalInteractionMap({ findings = [], onJumpToFinding }) {
    if (!findings || findings.length < 2) {
        return null;
    }

    const nodes = findings.slice(0, 6); // Cap at 6 nodes for readability
    const totalW = PADDING_X * 2 + nodes.length * NODE_W + (nodes.length - 1) * ARROW_GAP;
    const totalH = PADDING_Y * 2 + NODE_H + 32; // extra for technique label below

    return (
        <div style={{ marginTop: 20 }}>
            <div
                style={{
                    fontSize: 11,
                    fontWeight: 700,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.07em',
                    marginBottom: 12,
                }}
            >
                Signal Interaction Map
            </div>

            <div style={{ overflowX: 'auto', paddingBottom: 4 }}>
                <svg
                    width={totalW}
                    height={totalH}
                    viewBox={`0 0 ${totalW} ${totalH}`}
                    aria-label={`${nodes.length}-step attack chain`}
                    style={{ display: 'block' }}
                >
                    {/* Arrow marker definition */}
                    <defs>
                        <marker
                            id="arrowhead"
                            markerWidth="8"
                            markerHeight="6"
                            refX="7"
                            refY="3"
                            orient="auto"
                        >
                            <polygon points="0 0, 8 3, 0 6" fill="#64748B" />
                        </marker>
                    </defs>

                    {nodes.map((finding, idx) => {
                        const x = PADDING_X + idx * (NODE_W + ARROW_GAP);
                        const y = PADDING_Y;
                        const color = SIGNAL_COLORS[finding.signal_type] || '#64748B';
                        const label = finding.cve_id
                            ? finding.cve_id
                            : finding.rule_name
                                ? finding.rule_name.length > 14
                                    ? finding.rule_name.slice(0, 13) + '…'
                                    : finding.rule_name
                                : finding.signal_type || '';
                        const techId = finding.mitre_technique?.id || '';

                        return (
                            <g key={finding.finding_id || idx}>
                                {/* Arrow between nodes */}
                                {idx > 0 && (
                                    <line
                                        x1={x - ARROW_GAP}
                                        y1={y + NODE_H / 2}
                                        x2={x}
                                        y2={y + NODE_H / 2}
                                        stroke="#64748B"
                                        strokeWidth="1.5"
                                        markerEnd="url(#arrowhead)"
                                    />
                                )}

                                {/* Node box */}
                                <rect
                                    x={x}
                                    y={y}
                                    width={NODE_W}
                                    height={NODE_H}
                                    rx={6}
                                    fill={`${color}12`}
                                    stroke={color}
                                    strokeWidth="1.5"
                                    style={{ cursor: 'pointer' }}
                                    onClick={() => onJumpToFinding && onJumpToFinding(finding.finding_id)}
                                />

                                {/* Label inside node */}
                                <text
                                    x={x + NODE_W / 2}
                                    y={y + 18}
                                    textAnchor="middle"
                                    fontSize="11"
                                    fontWeight="600"
                                    fill={color}
                                    style={{ userSelect: 'none', pointerEvents: 'none' }}
                                >
                                    {label}
                                </text>

                                {/* Signal type sub-label */}
                                <text
                                    x={x + NODE_W / 2}
                                    y={y + 32}
                                    textAnchor="middle"
                                    fontSize="9"
                                    fill="#94A3B8"
                                    style={{ userSelect: 'none', pointerEvents: 'none' }}
                                >
                                    {finding.signal_type}
                                </text>

                                {/* MITRE technique below node */}
                                {techId && (
                                    <text
                                        x={x + NODE_W / 2}
                                        y={y + NODE_H + 18}
                                        textAnchor="middle"
                                        fontSize="9"
                                        fontWeight="700"
                                        fill="#CBD5E1"
                                        fontFamily="monospace"
                                        style={{ userSelect: 'none', pointerEvents: 'none' }}
                                    >
                                        {techId}
                                    </text>
                                )}
                            </g>
                        );
                    })}
                </svg>
            </div>

            {/* Caption */}
            <p
                style={{
                    fontSize: 11,
                    color: 'var(--text-muted)',
                    marginTop: 8,
                    fontStyle: 'italic',
                }}
            >
                This is a {nodes.length}-step attack chain. Fixing any one link breaks the chain.
            </p>
        </div>
    );
}
