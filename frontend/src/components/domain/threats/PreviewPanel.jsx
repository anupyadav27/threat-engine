'use client';

/**
 * PreviewPanel — Zone C of the Threat Command Room.
 *
 * Shows an inline radar SVG illustration in the empty state.
 * When a scenario is hovered, fades in a quick-preview card showing
 * setup_summary, signal type chips, MITRE technique chips, and an
 * "Open Full Story" CTA.  No additional network calls are made —
 * all data comes from the already-loaded scenarios array.
 *
 * @param {Object}   props
 * @param {Object|null} props.hoveredScenario  - The scenario currently being hovered, or null
 * @param {Function} props.onOpenDetail        - Called with scenario when user clicks "Open Full Story"
 */

// Signal type colours (mirrors ScenarioCard)
const SIGNAL_CONFIG = {
    misconfig:     { label: 'Misconfiguration', color: '#3B82F6' },
    vulnerability: { label: 'Vulnerability',    color: '#8B5CF6' },
    identity:      { label: 'Identity',         color: '#0D9488' },
    network:       { label: 'Network',          color: '#F97316' },
    ai_security:   { label: 'AI Security',      color: '#EC4899' },
};

const SEV_COLORS = {
    critical: '#DC2626',
    high:     '#EA580C',
    medium:   '#D97706',
    low:      '#64748B',
    info:     '#6B7280',
};

// ── Inline radar SVG illustration (no external asset) ────────────────────────
function RadarIllustration({ size = 120 }) {
    const c = size / 2;
    const r1 = size * 0.45;
    const r2 = size * 0.30;
    const r3 = size * 0.15;

    // Build hexagonal radar rings using 6 points
    function hexPoints(radius) {
        return Array.from({ length: 6 }, (_, i) => {
            const angle = (Math.PI / 3) * i - Math.PI / 2;
            return `${c + radius * Math.cos(angle)},${c + radius * Math.sin(angle)}`;
        }).join(' ');
    }

    // Blip positions for decorative effect
    const blips = [
        { x: c + r1 * 0.55, y: c - r1 * 0.40, r: 3, opacity: 0.9 },
        { x: c - r1 * 0.60, y: c + r1 * 0.20, r: 2, opacity: 0.6 },
        { x: c + r1 * 0.10, y: c + r1 * 0.70, r: 2.5, opacity: 0.75 },
    ];

    // Spoke lines
    const spokes = Array.from({ length: 6 }, (_, i) => {
        const angle = (Math.PI / 3) * i - Math.PI / 2;
        return {
            x2: c + r1 * Math.cos(angle),
            y2: c + r1 * Math.sin(angle),
        };
    });

    return (
        <svg
            width={size}
            height={size}
            viewBox={`0 0 ${size} ${size}`}
            aria-hidden="true"
            style={{ display: 'block', opacity: 0.6 }}
        >
            {/* Rings */}
            <polygon points={hexPoints(r1)} fill="none" stroke="var(--accent-primary)" strokeWidth="1" opacity="0.25" />
            <polygon points={hexPoints(r2)} fill="none" stroke="var(--accent-primary)" strokeWidth="1" opacity="0.20" />
            <polygon points={hexPoints(r3)} fill="none" stroke="var(--accent-primary)" strokeWidth="1" opacity="0.15" />

            {/* Spokes */}
            {spokes.map((s, i) => (
                <line key={i} x1={c} y1={c} x2={s.x2} y2={s.y2} stroke="var(--accent-primary)" strokeWidth="0.5" opacity="0.2" />
            ))}

            {/* Sweep arc (decorative) */}
            <path
                d={`M ${c} ${c} L ${c} ${c - r1} A ${r1} ${r1} 0 0 1 ${c + r1 * Math.cos(Math.PI / 6 - Math.PI / 2)} ${c + r1 * Math.sin(Math.PI / 6 - Math.PI / 2)} Z`}
                fill="var(--accent-primary)"
                opacity="0.06"
            />

            {/* Blips */}
            {blips.map((b, i) => (
                <circle key={i} cx={b.x} cy={b.y} r={b.r} fill="#EA580C" opacity={b.opacity} />
            ))}

            {/* Centre dot */}
            <circle cx={c} cy={c} r={3} fill="var(--accent-primary)" opacity="0.7" />
        </svg>
    );
}

// ── Green shield SVG — "No threats" state ────────────────────────────────────
function ShieldIllustration({ size = 80 }) {
    return (
        <svg width={size} height={size} viewBox="0 0 80 80" aria-hidden="true" style={{ display: 'block' }}>
            <path
                d="M40 8 L68 20 L68 44 C68 58 56 70 40 76 C24 70 12 58 12 44 L12 20 Z"
                fill="rgba(34,197,94,0.12)"
                stroke="#22C55E"
                strokeWidth="2"
            />
            <polyline
                points="26,41 36,52 54,32"
                fill="none"
                stroke="#22C55E"
                strokeWidth="3"
                strokeLinecap="round"
                strokeLinejoin="round"
            />
        </svg>
    );
}

export default function PreviewPanel({ hoveredScenario = null, onOpenDetail }) {
    const hasScenario = !!hoveredScenario;

    const {
        title          = '',
        severity       = 'medium',
        risk_score     = 0,
        setup_summary  = '',
        signal_types   = [],
        mitre_techniques = [],
    } = hoveredScenario || {};

    const sevColor = SEV_COLORS[severity] || SEV_COLORS.info;
    const summaryText = setup_summary.length > 300
        ? setup_summary.slice(0, 297) + '...'
        : setup_summary;

    return (
        <div
            style={{
                height: '100%',
                backgroundColor: 'var(--bg-card)',
                border: '1px solid var(--border-primary)',
                borderRadius: 10,
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden',
            }}
        >
            {/* Header strip */}
            <div
                style={{
                    padding: '10px 16px',
                    borderBottom: '1px solid var(--border-primary)',
                    fontSize: 11,
                    fontWeight: 700,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.07em',
                }}
            >
                Scenario Preview
            </div>

            {/* Content area */}
            <div
                style={{
                    flex: 1,
                    padding: '20px 18px',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: hasScenario ? 'flex-start' : 'center',
                    justifyContent: hasScenario ? 'flex-start' : 'center',
                    gap: 14,
                    opacity: hasScenario ? 1 : 1,
                    transition: 'opacity 150ms ease',
                }}
            >
                {!hasScenario ? (
                    /* Empty state */
                    <div style={{ textAlign: 'center', maxWidth: 200 }}>
                        <RadarIllustration size={120} />
                        <p
                            style={{
                                marginTop: 16,
                                fontSize: 13,
                                color: 'var(--text-muted)',
                                lineHeight: 1.5,
                            }}
                        >
                            Select a scenario to preview its story.
                        </p>
                    </div>
                ) : (
                    /* Hover state */
                    <>
                        {/* Severity + score */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span
                                style={{
                                    backgroundColor: `${sevColor}18`,
                                    border: `1px solid ${sevColor}40`,
                                    color: sevColor,
                                    borderRadius: 9999,
                                    fontSize: 10,
                                    fontWeight: 800,
                                    padding: '2px 10px',
                                    textTransform: 'uppercase',
                                    letterSpacing: '0.05em',
                                }}
                            >
                                {severity}
                            </span>
                            <span style={{ fontSize: 20, fontWeight: 900, color: sevColor, lineHeight: 1 }}>
                                {risk_score}
                            </span>
                            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>/100</span>
                        </div>

                        {/* Title */}
                        <p
                            style={{
                                fontSize: 14,
                                fontWeight: 600,
                                color: 'var(--text-primary)',
                                lineHeight: 1.45,
                                margin: 0,
                            }}
                        >
                            {title}
                        </p>

                        {/* Setup summary */}
                        {summaryText && (
                            <p
                                style={{
                                    fontSize: 12,
                                    color: 'var(--text-secondary)',
                                    lineHeight: 1.6,
                                    margin: 0,
                                    borderLeft: '2px solid var(--border-primary)',
                                    paddingLeft: 10,
                                }}
                            >
                                {summaryText}
                            </p>
                        )}

                        {/* Signal type chips */}
                        {signal_types.length > 0 && (
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                                {signal_types.map((st) => {
                                    const cfg = SIGNAL_CONFIG[st];
                                    if (!cfg) return null;
                                    return (
                                        <span
                                            key={st}
                                            style={{
                                                fontSize: 10,
                                                fontWeight: 600,
                                                padding: '2px 8px',
                                                borderRadius: 9999,
                                                backgroundColor: `${cfg.color}18`,
                                                border: `1px solid ${cfg.color}40`,
                                                color: cfg.color,
                                            }}
                                        >
                                            {cfg.label}
                                        </span>
                                    );
                                })}
                            </div>
                        )}

                        {/* MITRE technique chips */}
                        {mitre_techniques.length > 0 && (
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                                {mitre_techniques.slice(0, 6).map((t) => (
                                    <span
                                        key={t.id}
                                        title={t.name}
                                        style={{
                                            fontSize: 10,
                                            fontWeight: 700,
                                            padding: '1px 6px',
                                            borderRadius: 4,
                                            backgroundColor: '#334155',
                                            color: '#CBD5E1',
                                            fontFamily: 'monospace',
                                        }}
                                    >
                                        {t.id}
                                    </span>
                                ))}
                            </div>
                        )}

                        {/* Open Full Story CTA */}
                        <button
                            onClick={() => onOpenDetail && onOpenDetail(hoveredScenario)}
                            style={{
                                marginTop: 4,
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 4,
                                backgroundColor: '#EA580C',
                                color: '#fff',
                                border: 'none',
                                borderRadius: 6,
                                fontSize: 12,
                                fontWeight: 700,
                                padding: '8px 14px',
                                cursor: 'pointer',
                                transition: 'opacity 150ms ease',
                                alignSelf: 'flex-start',
                            }}
                            onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.85'; }}
                            onMouseLeave={(e) => { e.currentTarget.style.opacity = '1'; }}
                        >
                            Open Full Story &rarr;
                        </button>
                    </>
                )}
            </div>
        </div>
    );
}
