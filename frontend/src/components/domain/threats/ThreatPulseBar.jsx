'use client';

/**
 * ThreatPulseBar — Zone A of the Threat Command Room.
 *
 * Renders severity pill counts, a composite risk score gradient bar, and a
 * delta line showing scan-over-scan change.  All data comes from pulseStats
 * (already fetched by CommandRoom; no additional network calls here).
 *
 * @param {Object} props
 * @param {Object}   props.pulseStats          - BFF pulse_stats object
 * @param {Function} props.onFilterBySeverity  - Called with severity string when a pill is clicked
 */

import { useRef, useEffect, useState } from 'react';

// Severity colours — story spec §ThreatPulseBar
const SEV = {
    critical: { text: '#DC2626', bg: 'rgba(220,38,38,0.12)',  label: 'CRITICAL' },
    high:     { text: '#EA580C', bg: 'rgba(234,88,12,0.12)',  label: 'HIGH'     },
    medium:   { text: '#D97706', bg: 'rgba(217,119,6,0.12)',  label: 'MEDIUM'   },
    low:      { text: '#64748B', bg: 'rgba(100,116,139,0.12)', label: 'LOW'     },
};

// Delta indicator characters and colours
function DeltaIndicator({ direction, count }) {
    if (!count && direction === 'flat') return null;
    const map = {
        up:   { symbol: '↑', color: '#DC2626' },
        down: { symbol: '↓', color: '#22C55E' },
        flat: { symbol: '→', color: '#94A3B8' },
    };
    const { symbol, color } = map[direction] || map.flat;
    return (
        <span style={{ color, fontWeight: 700, fontSize: 13 }}>
            {symbol} {count > 0 ? `+${count}` : count}
        </span>
    );
}

export default function ThreatPulseBar({ pulseStats = {}, onFilterBySeverity }) {
    const barRef = useRef(null);
    const [barWidth, setBarWidth] = useState(200);

    useEffect(() => {
        if (!barRef.current) return;
        const observer = new ResizeObserver((entries) => {
            for (const entry of entries) {
                setBarWidth(entry.contentRect.width);
            }
        });
        observer.observe(barRef.current);
        return () => observer.disconnect();
    }, []);

    const {
        critical_count   = 0,
        high_count       = 0,
        medium_count     = 0,
        low_count        = 0,
        composite_score  = 0,
        delta_count      = 0,
        delta_direction  = 'flat',
        new_today        = 0,
        last_scan_age_human = null,
    } = pulseStats;

    const score = Math.max(0, Math.min(100, composite_score));
    const markerLeft = Math.round((score / 100) * barWidth);

    const severityPills = [
        { key: 'critical', count: critical_count },
        { key: 'high',     count: high_count     },
        { key: 'medium',   count: medium_count   },
        { key: 'low',      count: low_count      },
    ];

    return (
        <div
            style={{
                backgroundColor: 'var(--bg-card)',
                border: '1px solid var(--border-primary)',
                borderRadius: 10,
                padding: '12px 20px',
                display: 'flex',
                alignItems: 'center',
                gap: 20,
                flexWrap: 'wrap',
                minHeight: 72,
            }}
        >
            {/* Severity pills */}
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {severityPills.map(({ key, count }) => {
                    const { text, bg, label } = SEV[key];
                    return (
                        <button
                            key={key}
                            onClick={() => onFilterBySeverity && onFilterBySeverity(key)}
                            style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 6,
                                backgroundColor: bg,
                                color: text,
                                border: `1px solid ${text}40`,
                                borderRadius: 9999,
                                padding: '4px 12px',
                                fontSize: 12,
                                fontWeight: 700,
                                cursor: 'pointer',
                                transition: 'opacity 150ms ease',
                            }}
                            onMouseEnter={(e) => { e.currentTarget.style.opacity = '0.8'; }}
                            onMouseLeave={(e) => { e.currentTarget.style.opacity = '1'; }}
                        >
                            <span
                                style={{
                                    width: 6,
                                    height: 6,
                                    borderRadius: '50%',
                                    backgroundColor: text,
                                    flexShrink: 0,
                                }}
                            />
                            {label}
                            <span style={{ fontSize: 14, fontWeight: 900 }}>{count}</span>
                        </button>
                    );
                })}
            </div>

            {/* Divider */}
            <div style={{ width: 1, height: 32, backgroundColor: 'var(--border-primary)', flexShrink: 0 }} />

            {/* Composite score + gradient bar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: '0 0 auto' }}>
                <div>
                    <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                        Risk Score
                    </div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: 3 }}>
                        <span style={{ fontSize: 22, fontWeight: 900, color: 'var(--text-primary)', lineHeight: 1 }}>
                            {score}
                        </span>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>/100</span>
                    </div>
                </div>

                {/* Gradient bar with marker */}
                <div
                    ref={barRef}
                    style={{
                        position: 'relative',
                        width: 160,
                        height: 10,
                        borderRadius: 5,
                        background: 'linear-gradient(90deg, #22C55E 0%, #EAB308 50%, #DC2626 100%)',
                        flexShrink: 0,
                    }}
                >
                    {/* White triangle marker */}
                    <div
                        style={{
                            position: 'absolute',
                            top: '50%',
                            left: markerLeft,
                            transform: 'translate(-50%, -50%)',
                            width: 0,
                            height: 0,
                            borderLeft: '5px solid transparent',
                            borderRight: '5px solid transparent',
                            borderBottom: '9px solid #FFFFFF',
                            filter: 'drop-shadow(0 0 2px rgba(0,0,0,0.5))',
                        }}
                    />
                </div>
            </div>

            {/* Divider */}
            <div style={{ width: 1, height: 32, backgroundColor: 'var(--border-primary)', flexShrink: 0 }} />

            {/* Delta + scan meta */}
            <div style={{ fontSize: 12, color: 'var(--text-tertiary)', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <DeltaIndicator direction={delta_direction} count={delta_count} />
                {delta_count > 0 && (
                    <span>since last scan</span>
                )}
                {new_today > 0 && (
                    <>
                        <span style={{ color: 'var(--border-primary)' }}>·</span>
                        <span>
                            <strong style={{ color: 'var(--text-secondary)' }}>{new_today}</strong> new today
                        </span>
                    </>
                )}
                {last_scan_age_human && (
                    <>
                        <span style={{ color: 'var(--border-primary)' }}>·</span>
                        <span>Last scan: <strong style={{ color: 'var(--text-secondary)' }}>{last_scan_age_human}</strong></span>
                    </>
                )}
            </div>
        </div>
    );
}
