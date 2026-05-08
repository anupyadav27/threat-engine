'use client';

/**
 * /threats/attack-map — MITRE ATT&CK Heatmap (Attack Map page)
 *
 * Visualises which of the 14 canonical MITRE ATT&CK for Cloud tactics and
 * their techniques have active findings in the current scan.
 *
 * Data source: BFF GET /api/v1/views/threat-mitre-heatmap
 * RBAC: threats:read — viewer role can access.
 * Auth: forwarded via X-Auth-Context — no DEV_BYPASS_AUTH.
 */

import { useState } from 'react';
import { useViewFetch } from '@/lib/use-view-fetch';
import ThreatSubNav from '@/components/domain/threats/ThreatSubNav';

// ── Severity palette ──────────────────────────────────────────────────────────

const SEV_COLOR = {
    critical: '#DC2626',
    high:     '#EA580C',
    medium:   '#D97706',
    low:      '#3B82F6',
    info:     '#64748B',
    '':       '#334155',
};

const SEV_BG = {
    critical: '#DC262618',
    high:     '#EA580C18',
    medium:   '#D9770618',
    low:      '#3B82F618',
    info:     '#64748B18',
    '':       '#33415518',
};

function sevColor(s)  { return SEV_COLOR[(s || '').toLowerCase()] || SEV_COLOR['']; }
function sevBg(s)     { return SEV_BG[(s || '').toLowerCase()]    || SEV_BG['']; }

// ── Cell intensity: darker = more findings ────────────────────────────────────

function cellOpacity(count, maxCount) {
    if (!count || !maxCount) return 0.08;
    return 0.12 + (count / maxCount) * 0.78;
}

// ── Skeleton shimmer ──────────────────────────────────────────────────────────

function Shimmer({ width = '100%', height = 14, style = {} }) {
    return (
        <div style={{
            width, height,
            backgroundColor: 'var(--bg-tertiary)',
            borderRadius: 6,
            animation: 'pulse 1.5s ease-in-out infinite',
            ...style,
        }} />
    );
}

function HeatmapSkeleton() {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '12px 0' }}>
            {/* summary strip */}
            <div style={{ display: 'flex', gap: 12 }}>
                {[1, 2, 3, 4].map(i => <Shimmer key={i} height={56} style={{ flex: 1, borderRadius: 10 }} />)}
            </div>
            {/* heatmap grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 8 }}>
                {Array.from({ length: 14 }, (_, i) => (
                    <Shimmer key={i} height={120} style={{ borderRadius: 10 }} />
                ))}
            </div>
        </div>
    );
}

// ── Technique chip ────────────────────────────────────────────────────────────

function TechniqueChip({ tech, onClick, selected }) {
    const color = sevColor(tech.severity);
    return (
        <button
            onClick={() => onClick(tech)}
            title={`${tech.id} · ${tech.name} · ${tech.count} finding${tech.count !== 1 ? 's' : ''}`}
            style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                fontSize: 10,
                fontWeight: 700,
                padding: '2px 6px',
                borderRadius: 4,
                backgroundColor: selected ? color : `${color}22`,
                border: `1px solid ${color}55`,
                color: selected ? '#fff' : color,
                cursor: 'pointer',
                fontFamily: 'monospace',
                letterSpacing: '0.02em',
                transition: 'all 100ms',
            }}
        >
            {tech.id}
            {tech.count > 1 && (
                <span style={{
                    fontSize: 9,
                    fontWeight: 800,
                    backgroundColor: selected ? 'rgba(255,255,255,0.25)' : `${color}33`,
                    borderRadius: 3,
                    padding: '0 3px',
                }}>
                    {tech.count}
                </span>
            )}
        </button>
    );
}

// ── Tactic card ───────────────────────────────────────────────────────────────

function TacticCard({ tactic, maxCount, selectedTech, onTechClick }) {
    const active     = tactic.total_count > 0;
    const color      = active ? sevColor(tactic.severity) : 'var(--text-muted)';
    const opacity    = active ? cellOpacity(tactic.total_count, maxCount) : 0;
    const borderColor = active ? `${sevColor(tactic.severity)}55` : 'var(--border-primary)';

    return (
        <div
            style={{
                backgroundColor: active ? `rgba(${hexToRgb(sevColor(tactic.severity))},${opacity})` : 'var(--bg-card)',
                border: `1px solid ${borderColor}`,
                borderRadius: 10,
                padding: '10px 12px',
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                minHeight: 110,
                position: 'relative',
                opacity: active ? 1 : 0.5,
            }}
        >
            {/* Order badge */}
            <span style={{
                position: 'absolute', top: 8, right: 8,
                fontSize: 9, fontWeight: 700, color: 'var(--text-muted)',
                backgroundColor: 'var(--bg-tertiary)',
                borderRadius: 3, padding: '1px 5px',
            }}>
                T{tactic.order}
            </span>

            {/* Tactic name */}
            <div>
                <div style={{ fontSize: 11, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.3, paddingRight: 24 }}>
                    {tactic.short}
                </div>
                {active && (
                    <div style={{ fontSize: 10, color, fontWeight: 700, marginTop: 2 }}>
                        {tactic.total_count} finding{tactic.total_count !== 1 ? 's' : ''}
                    </div>
                )}
            </div>

            {/* Technique chips */}
            {active && tactic.techniques.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {tactic.techniques.slice(0, 6).map((tech) => (
                        <TechniqueChip
                            key={tech.id}
                            tech={tech}
                            onClick={onTechClick}
                            selected={selectedTech?.id === tech.id}
                        />
                    ))}
                    {tactic.techniques.length > 6 && (
                        <span style={{ fontSize: 9, color: 'var(--text-muted)', alignSelf: 'center' }}>
                            +{tactic.techniques.length - 6} more
                        </span>
                    )}
                </div>
            )}

            {!active && (
                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontStyle: 'italic', marginTop: 'auto' }}>
                    No findings
                </div>
            )}
        </div>
    );
}

// Hex to RGB helper for rgba() usage
function hexToRgb(hex) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `${r},${g},${b}`;
}

// ── Technique detail panel ────────────────────────────────────────────────────

function TechniqueDetail({ tech, onClose }) {
    if (!tech) return null;
    const color = sevColor(tech.severity);
    return (
        <div style={{
            position: 'fixed', right: 24, bottom: 24,
            backgroundColor: 'var(--bg-card)',
            border: `1px solid ${color}55`,
            borderRadius: 12,
            padding: '16px 20px',
            width: 280,
            zIndex: 40,
            boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
        }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 10 }}>
                <span style={{ fontSize: 11, fontWeight: 900, fontFamily: 'monospace', color }}>{tech.id}</span>
                <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16, lineHeight: 1 }}>&times;</button>
            </div>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>{tech.name}</div>
            <div style={{ display: 'flex', gap: 10 }}>
                <div style={{ flex: 1, textAlign: 'center', padding: '8px', backgroundColor: sevBg(tech.severity), borderRadius: 8 }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color }}>{tech.count}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Findings</div>
                </div>
                <div style={{ flex: 1, textAlign: 'center', padding: '8px', backgroundColor: 'var(--bg-tertiary)', borderRadius: 8 }}>
                    <div style={{ fontSize: 13, fontWeight: 800, color, textTransform: 'uppercase' }}>{tech.severity || 'medium'}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Severity</div>
                </div>
            </div>
        </div>
    );
}

// ── Summary KPI strip ─────────────────────────────────────────────────────────

function SummaryStrip({ summary }) {
    const kpis = [
        { label: 'Tactics Active',      value: `${summary.tactics_covered}/14`, color: summary.tactics_covered >= 8 ? '#DC2626' : summary.tactics_covered >= 4 ? '#EA580C' : '#22C55E' },
        { label: 'Techniques Detected', value: summary.techniques_detected,     color: '#3B82F6' },
        { label: 'Total Findings',       value: summary.total_findings,          color: '#EA580C' },
        { label: 'Critical Findings',    value: summary.critical_count,          color: '#DC2626' },
    ];

    return (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
            {kpis.map(({ label, value, color }) => (
                <div key={label} style={{
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 10,
                    padding: '12px 16px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 4,
                }}>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>{label}</span>
                    <span style={{ fontSize: 26, fontWeight: 900, color, lineHeight: 1 }}>{value}</span>
                </div>
            ))}
        </div>
    );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AttackCoveragePage() {
    const { data, loading, error } = useViewFetch('threat-mitre-heatmap');
    const [selectedTech, setSelectedTech] = useState(null);

    const tactics  = data?.tactics  || [];
    const summary  = data?.summary  || {};
    const maxCount = Math.max(...tactics.map(t => t.total_count || 0), 1);

    const handleTechClick = (tech) => {
        setSelectedTech(prev => prev?.id === tech.id ? null : tech);
    };

    return (
        <div className="space-y-0">
            <ThreatSubNav />

            <div style={{ padding: '0 0 32px' }}>
                {/* Header */}
                <div style={{ marginBottom: 20 }}>
                    <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 4 }}>
                        MITRE ATT&amp;CK Coverage
                    </h1>
                    <p style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                        Active findings mapped to the 14 MITRE ATT&amp;CK for Cloud tactics · Click a technique chip for details
                    </p>
                </div>

                {loading && <HeatmapSkeleton />}

                {error && (
                    <div style={{ padding: 40, textAlign: 'center', color: '#ef4444', fontSize: 14 }}>
                        Could not load MITRE heatmap: {error}
                    </div>
                )}

                {!loading && !error && (
                    <>
                        <SummaryStrip summary={summary} />

                        {/* Heatmap grid — 7 columns × 2 rows for 14 tactics */}
                        <div style={{
                            display: 'grid',
                            gridTemplateColumns: 'repeat(7, 1fr)',
                            gap: 10,
                        }}>
                            {tactics.map((tactic) => (
                                <TacticCard
                                    key={tactic.name}
                                    tactic={tactic}
                                    maxCount={maxCount}
                                    selectedTech={selectedTech}
                                    onTechClick={handleTechClick}
                                />
                            ))}
                        </div>

                        {/* Legend */}
                        <div style={{ display: 'flex', gap: 16, marginTop: 16, alignItems: 'center', flexWrap: 'wrap' }}>
                            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Severity:</span>
                            {['critical', 'high', 'medium', 'low'].map(s => (
                                <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                                    <div style={{ width: 10, height: 10, borderRadius: 2, backgroundColor: sevColor(s) }} />
                                    <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'capitalize' }}>{s}</span>
                                </div>
                            ))}
                            <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 8 }}>
                                Cell intensity = finding count (darker = more findings)
                            </span>
                        </div>

                        {/* No-data message */}
                        {tactics.every(t => t.total_count === 0) && (
                            <div style={{ marginTop: 24, padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13, maxWidth: 520, margin: '24px auto 0' }}>
                                <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8, fontSize: 14 }}>MITRE ATT&amp;CK data not yet available</div>
                                <div>MITRE technique mapping is populated after a full pipeline scan completes. If a scan has already run and this grid remains empty, the MITRE enrichment job may still be processing — check back after the next scan or contact support.</div>
                            </div>
                        )}
                    </>
                )}
            </div>

            <TechniqueDetail tech={selectedTech} onClose={() => setSelectedTech(null)} />

            <style>{`
                @keyframes pulse {
                    0%   { opacity: 1; }
                    50%  { opacity: 0.45; }
                    100% { opacity: 1; }
                }
            `}</style>
        </div>
    );
}
