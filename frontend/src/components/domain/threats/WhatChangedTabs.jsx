'use client';

/**
 * WhatChangedTabs — tabbed scenario lists for the posture delta page.
 *
 * 4 tabs: New | Resolved | Escalated | De-escalated
 * Each tab label shows count in parentheses. Zero-count tabs are shown
 * but dimmed (opacity 0.5, still clickable).
 *
 * Compact scenario cards (56px tall):
 *   - Severity dot + title (truncated at 60 chars) + CSP/region + risk score
 *   - Escalated: score delta badge "74 → 91 (+17)" in orange
 *   - Resolved: strikethrough title + green checkmark
 *   - [View →] navigates to /threats?scenario={id} (Next.js router)
 *
 * Props:
 *   newScenarios         {Array}   - scenarios not present in scan A
 *   resolvedScenarios    {Array}   - scenarios not present in scan B
 *   escalatedScenarios   {Array}   - both scans, risk_score increased
 *   deescalatedScenarios {Array}   - both scans, risk_score decreased
 *   loading              {boolean} - show skeleton
 *   scanBCompletedAt     {string}  - ISO timestamp used as resolution date
 */

import { useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';

// ── Severity dot color ─────────────────────────────────────────────────────────

const SEV_COLORS = {
    critical: '#DC2626',
    high: '#EA580C',
    medium: '#D97706',
    low: '#64748B',
};

function _sevColor(sev) {
    return SEV_COLORS[sev] || '#64748B';
}

// ── Date formatter (short) ─────────────────────────────────────────────────────

function _shortDate(ts) {
    if (!ts) return '';
    try {
        return new Date(ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch {
        return ts.slice(0, 10);
    }
}

// ── Compact scenario card ──────────────────────────────────────────────────────

function ScenarioCard({ scenario, variant = 'new', resolvedAt = '' }) {
    const router = useRouter();
    const title = (scenario.title || 'Threat scenario').slice(0, 60);
    const sev = (scenario.severity || 'medium').toLowerCase();
    const cspRegion = [scenario.csp, scenario.region].filter(Boolean).join(' / ');
    const sevColor = _sevColor(sev);

    const handleView = useCallback(() => {
        const id = scenario.scenario_id || scenario.id || '';
        if (id) {
            router.push(`/threats?scenario=${id}`);
        }
    }, [router, scenario]);

    return (
        <div
            style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 14px',
                minHeight: 56,
                borderBottom: '1px solid var(--border-primary)',
                backgroundColor: 'transparent',
                transition: 'background-color 100ms ease',
            }}
            onMouseEnter={(e) =>
                (e.currentTarget.style.backgroundColor = 'var(--bg-secondary)')
            }
            onMouseLeave={(e) =>
                (e.currentTarget.style.backgroundColor = 'transparent')
            }
        >
            {/* Severity dot */}
            <span
                style={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    backgroundColor: sevColor,
                    flexShrink: 0,
                }}
            />

            {/* Main info */}
            <div style={{ flex: 1, minWidth: 0 }}>
                <p
                    style={{
                        fontSize: 12,
                        fontWeight: 600,
                        color: variant === 'resolved' ? 'var(--text-muted)' : 'var(--text-primary)',
                        textDecoration: variant === 'resolved' ? 'line-through' : 'none',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        marginBottom: 2,
                    }}
                >
                    {variant === 'resolved' && (
                        <span style={{ color: '#22C55E', marginRight: 5 }}>✓</span>
                    )}
                    {title}
                </p>
                <p style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {cspRegion}
                    {variant === 'resolved' && resolvedAt && (
                        <span style={{ marginLeft: 6, color: '#22C55E' }}>
                            resolved {_shortDate(resolvedAt)}
                        </span>
                    )}
                </p>
            </div>

            {/* Score / delta badge */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                {variant === 'escalated' ? (
                    <span
                        style={{
                            fontSize: 11,
                            fontWeight: 700,
                            color: '#EA580C',
                            backgroundColor: 'rgba(234,88,12,0.1)',
                            border: '1px solid rgba(234,88,12,0.25)',
                            borderRadius: 4,
                            padding: '2px 7px',
                            whiteSpace: 'nowrap',
                        }}
                    >
                        {scenario.risk_score_a} → {scenario.risk_score_b}
                        {' '}(+{scenario.risk_score_delta})
                    </span>
                ) : (
                    <span
                        style={{
                            fontSize: 12,
                            fontWeight: 700,
                            color: sevColor,
                            minWidth: 28,
                            textAlign: 'right',
                        }}
                    >
                        {scenario.risk_score ?? '—'}
                    </span>
                )}

                {/* View button */}
                <button
                    onClick={handleView}
                    style={{
                        padding: '3px 9px',
                        fontSize: 11,
                        fontWeight: 600,
                        color: '#EA580C',
                        backgroundColor: 'rgba(234,88,12,0.08)',
                        border: '1px solid rgba(234,88,12,0.25)',
                        borderRadius: 4,
                        cursor: 'pointer',
                        whiteSpace: 'nowrap',
                    }}
                >
                    View →
                </button>
            </div>
        </div>
    );
}

// ── Empty tab state ────────────────────────────────────────────────────────────

function EmptyTabState({ tab }) {
    const MESSAGES = {
        new: { icon: '✓', color: '#22C55E', text: 'No new scenarios appeared in this period.' },
        resolved: { icon: '—', color: 'var(--text-muted)', text: 'No scenarios were resolved.' },
        escalated: { icon: '✓', color: '#22C55E', text: 'No scenarios escalated.' },
        deescalated: { icon: '✓', color: '#22C55E', text: 'No scenarios de-escalated.' },
    };
    const { icon, color, text } = MESSAGES[tab] || MESSAGES.new;
    return (
        <div
            style={{
                padding: '28px 20px',
                textAlign: 'center',
                color: 'var(--text-muted)',
                fontSize: 13,
            }}
        >
            <span style={{ fontSize: 20, color, display: 'block', marginBottom: 6 }}>{icon}</span>
            {text}
        </div>
    );
}

// ── Shimmer skeleton ──────────────────────────────────────────────────────────

function TabShimmer() {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {[1, 2, 3].map((i) => (
                <div
                    key={i}
                    style={{
                        height: 56,
                        backgroundColor: 'var(--bg-tertiary)',
                        borderRadius: 6,
                        animation: 'pulse 1.5s ease-in-out infinite',
                    }}
                />
            ))}
            <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.45} }`}</style>
        </div>
    );
}

// ── Main component ─────────────────────────────────────────────────────────────

const TAB_KEYS = ['new', 'resolved', 'escalated', 'deescalated'];

export default function WhatChangedTabs({
    newScenarios = [],
    resolvedScenarios = [],
    escalatedScenarios = [],
    deescalatedScenarios = [],
    loading = false,
    scanBCompletedAt = '',
}) {
    const [activeTab, setActiveTab] = useState('new');

    const counts = {
        new: newScenarios.length,
        resolved: resolvedScenarios.length,
        escalated: escalatedScenarios.length,
        deescalated: deescalatedScenarios.length,
    };

    const TAB_LABELS = {
        new: 'New',
        resolved: 'Resolved',
        escalated: 'Escalated',
        deescalated: 'De-escalated',
    };

    const scenariosMap = {
        new: newScenarios,
        resolved: resolvedScenarios,
        escalated: escalatedScenarios,
        deescalated: deescalatedScenarios,
    };

    const activeScenarios = scenariosMap[activeTab] || [];

    if (loading) return <TabShimmer />;

    return (
        <div>
            {/* Tab bar */}
            <div
                style={{
                    display: 'flex',
                    borderBottom: '1px solid var(--border-primary)',
                    marginBottom: 0,
                    gap: 0,
                    overflowX: 'auto',
                }}
            >
                {TAB_KEYS.map((tab) => {
                    const active = tab === activeTab;
                    const count = counts[tab];
                    const isEmpty = count === 0;
                    return (
                        <button
                            key={tab}
                            onClick={() => setActiveTab(tab)}
                            style={{
                                padding: '8px 16px',
                                fontSize: 12,
                                fontWeight: active ? 700 : 500,
                                color: active ? '#EA580C' : 'var(--text-muted)',
                                borderBottom: active ? '2px solid #EA580C' : '2px solid transparent',
                                marginBottom: -1,
                                backgroundColor: 'transparent',
                                border: 'none',
                                borderBottomStyle: 'solid',
                                borderBottomWidth: active ? 2 : 2,
                                borderBottomColor: active ? '#EA580C' : 'transparent',
                                cursor: 'pointer',
                                opacity: isEmpty ? 0.5 : 1,
                                whiteSpace: 'nowrap',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 5,
                            }}
                        >
                            {TAB_LABELS[tab]}
                            <span
                                style={{
                                    backgroundColor: active ? '#EA580C' : 'var(--bg-tertiary)',
                                    color: active ? '#fff' : 'var(--text-muted)',
                                    borderRadius: 9999,
                                    fontSize: 10,
                                    fontWeight: 700,
                                    padding: '1px 6px',
                                    lineHeight: '16px',
                                }}
                            >
                                {count}
                            </span>
                        </button>
                    );
                })}
            </div>

            {/* Tab content */}
            <div
                style={{
                    border: '1px solid var(--border-primary)',
                    borderTop: 'none',
                    borderRadius: '0 0 8px 8px',
                    overflow: 'hidden',
                    maxHeight: 420,
                    overflowY: 'auto',
                }}
            >
                {activeScenarios.length === 0 ? (
                    <EmptyTabState tab={activeTab} />
                ) : (
                    activeScenarios.map((s, i) => (
                        <ScenarioCard
                            key={s.scenario_id || s.id || i}
                            scenario={s}
                            variant={activeTab}
                            resolvedAt={scanBCompletedAt}
                        />
                    ))
                )}
            </div>
        </div>
    );
}
