'use client';

/**
 * CommandRoom — three-zone Threat Command Room layout container.
 *
 * Zone A: ThreatPulseBar (full width, 72px)
 * Zone B: ScenarioCardList (55% / scrollable)
 * Zone C: PreviewPanel   (45% / sticky)
 *
 * All data is fetched once via useViewFetch('threat-command-room').
 * Filtering is entirely client-side (no re-fetch on filter changes).
 * The live badge count is written into ThreatBadgeContext so the Sidebar
 * can display a pill next to the "Threats" nav item.
 *
 * Poll interval: 30 seconds when scan_status === 'running'.
 */

import { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import Link from 'next/link';
import { useViewFetch } from '@/lib/use-view-fetch';
import { useThreatBadge } from '@/lib/threat-badge-context';
import ThreatPulseBar from './ThreatPulseBar';
import ThreatSubNav from './ThreatSubNav';
import ScenarioCardList from './ScenarioCardList';
import PreviewPanel from './PreviewPanel';
import ScenarioDetailPanel from './ScenarioDetailPanel';

// ── Skeleton loader ───────────────────────────────────────────────────────────
function SkeletonRow({ width = '100%', height = 16 }) {
    return (
        <div
            style={{
                width,
                height,
                backgroundColor: 'var(--bg-tertiary)',
                borderRadius: 6,
                animation: 'pulse 1.5s ease-in-out infinite',
            }}
        />
    );
}

function CommandRoomSkeleton() {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Pulse bar skeleton */}
            <div
                style={{
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 10,
                    padding: '12px 20px',
                    height: 72,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 16,
                }}
            >
                {[100, 80, 90, 70].map((w, i) => (
                    <SkeletonRow key={i} width={w} height={28} />
                ))}
            </div>

            {/* Cards + panel skeleton */}
            <div style={{ display: 'grid', gridTemplateColumns: '55fr 45fr', gap: 12, minHeight: 500 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {[1, 2, 3, 4, 5].map((i) => (
                        <div
                            key={i}
                            style={{
                                backgroundColor: 'var(--bg-card)',
                                border: '1px solid var(--border-primary)',
                                borderRadius: 8,
                                padding: '14px',
                                display: 'flex',
                                flexDirection: 'column',
                                gap: 8,
                            }}
                        >
                            <SkeletonRow width="70%" height={14} />
                            <SkeletonRow width="45%" height={12} />
                        </div>
                    ))}
                </div>
                <div
                    style={{
                        backgroundColor: 'var(--bg-card)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 10,
                    }}
                />
            </div>
        </div>
    );
}

// ── Empty states ──────────────────────────────────────────────────────────────

function RadarEmptyState() {
    const c = 60;
    const r1 = 52, r2 = 36, r3 = 18;
    function hex(r) {
        return Array.from({ length: 6 }, (_, i) => {
            const a = (Math.PI / 3) * i - Math.PI / 2;
            return `${c + r * Math.cos(a)},${c + r * Math.sin(a)}`;
        }).join(' ');
    }
    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20, padding: '60px 20px', textAlign: 'center' }}>
            <svg width={120} height={120} viewBox="0 0 120 120" aria-hidden="true" style={{ opacity: 0.5 }}>
                <polygon points={hex(r1)} fill="none" stroke="var(--accent-primary)" strokeWidth="1.5" opacity="0.3" />
                <polygon points={hex(r2)} fill="none" stroke="var(--accent-primary)" strokeWidth="1.5" opacity="0.25" />
                <polygon points={hex(r3)} fill="none" stroke="var(--accent-primary)" strokeWidth="1.5" opacity="0.2" />
                {Array.from({ length: 6 }, (_, i) => {
                    const a = (Math.PI / 3) * i - Math.PI / 2;
                    return <line key={i} x1={c} y1={c} x2={c + r1 * Math.cos(a)} y2={c + r1 * Math.sin(a)} stroke="var(--accent-primary)" strokeWidth="0.75" opacity="0.2" />;
                })}
                <circle cx={c} cy={c} r={4} fill="var(--accent-primary)" opacity="0.6" />
            </svg>

            <div>
                <h2 style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
                    Your threat radar is ready.
                </h2>
                <p style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 320, lineHeight: 1.6, margin: '0 auto 20px' }}>
                    No scans have run yet. Run a scan to see threat scenarios.
                </p>
                <div style={{ display: 'flex', gap: 10, justifyContent: 'center', flexWrap: 'wrap' }}>
                    <Link
                        href="/scans"
                        style={{
                            backgroundColor: '#EA580C',
                            color: '#fff',
                            borderRadius: 6,
                            fontSize: 13,
                            fontWeight: 700,
                            padding: '8px 18px',
                            textDecoration: 'none',
                        }}
                    >
                        Run a Scan
                    </Link>
                    <Link
                        href="/onboarding"
                        style={{
                            backgroundColor: 'var(--bg-tertiary)',
                            color: 'var(--text-secondary)',
                            border: '1px solid var(--border-primary)',
                            borderRadius: 6,
                            fontSize: 13,
                            fontWeight: 600,
                            padding: '8px 18px',
                            textDecoration: 'none',
                        }}
                    >
                        View Onboarding
                    </Link>
                </div>
            </div>
        </div>
    );
}

function CleanEmptyState() {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 20, padding: '60px 20px', textAlign: 'center' }}>
            {/* Green shield */}
            <svg width={80} height={80} viewBox="0 0 80 80" aria-hidden="true">
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

            <div>
                <h2 style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)', marginBottom: 8 }}>
                    No active threat scenarios.
                </h2>
                <p style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 300, lineHeight: 1.6, margin: '0 auto 20px' }}>
                    Your environment is clean for this scan.
                </p>
                <div style={{ display: 'flex', gap: 10, justifyContent: 'center', flexWrap: 'wrap', fontSize: 13 }}>
                    <Link href="/misconfig" style={{ color: '#EA580C', textDecoration: 'underline', fontWeight: 600 }}>
                        View all findings &rarr;
                    </Link>
                    <Link href="/threats/attack-coverage" style={{ color: 'var(--text-muted)', textDecoration: 'underline' }}>
                        Check ATT&amp;CK coverage &rarr;
                    </Link>
                </div>
            </div>
        </div>
    );
}

// ── CommandRoom ───────────────────────────────────────────────────────────────

export default function CommandRoom() {
    const { data, loading, error, refetch } = useViewFetch('threat-command-room');
    const { setBadgeCount } = useThreatBadge();

    // ── Component state ────────────────────────────────────────────────────
    const [selectedScenario,  setSelectedScenario]  = useState(null);
    const [hoveredScenarioId, setHoveredScenarioId] = useState(null);
    const [activeFilters,     setActiveFilters]      = useState({ sort: 'risk_score' });
    const [searchQuery,       setSearchQuery]         = useState('');

    // Detail panel (Scenario Detail Panel — THREAT-UI-02)
    const [detailPanelOpen,   setDetailPanelOpen]   = useState(false);
    const [detailScenarioId,  setDetailScenarioId]  = useState(null);

    const pollRef = useRef(null);

    // ── Extract BFF data ───────────────────────────────────────────────────
    const pulseStats = data.pulse_stats || {};
    const scenarios  = data.scenarios   || [];
    const total      = data.total       || 0;
    const scanStatus = pulseStats.scan_status || null;

    // ── Populate nav badge ─────────────────────────────────────────────────
    useEffect(() => {
        if (pulseStats.critical_count !== undefined) {
            const count = (pulseStats.critical_count || 0) + (pulseStats.high_count || 0);
            setBadgeCount('threatCriticalHighCount', count);
        }
    }, [pulseStats.critical_count, pulseStats.high_count, setBadgeCount]);

    // ── Poll when scan is running ──────────────────────────────────────────
    useEffect(() => {
        clearInterval(pollRef.current);
        if (scanStatus === 'running') {
            pollRef.current = setInterval(() => {
                refetch();
            }, 30000);
        }
        return () => clearInterval(pollRef.current);
    }, [scanStatus, refetch]);

    // ── Derived: hovered scenario object ──────────────────────────────────
    const hoveredScenario = useMemo(() => {
        if (!hoveredScenarioId) return null;
        return scenarios.find((s) => s.scenario_id === hoveredScenarioId) || null;
    }, [hoveredScenarioId, scenarios]);

    // ── criticalHighCount for sub-nav badge ───────────────────────────────
    const criticalHighCount = (pulseStats.critical_count || 0) + (pulseStats.high_count || 0);

    // ── Filter handlers ────────────────────────────────────────────────────
    const handleFilterChange = useCallback(({ key, value }) => {
        setActiveFilters((prev) => ({ ...prev, [key]: value }));
    }, []);

    const handleFilterBySeverity = useCallback((severity) => {
        setActiveFilters((prev) => ({
            ...prev,
            severity: prev.severity === severity ? null : severity,
        }));
    }, []);

    const handleSelectScenario = useCallback((scenario) => {
        setSelectedScenario((prev) =>
            prev?.scenario_id === scenario?.scenario_id ? null : scenario
        );
        // Open detail panel for the selected scenario (AC1, AC15)
        if (scenario?.scenario_id) {
            setDetailScenarioId(scenario.scenario_id);
            setDetailPanelOpen(true);
        }
    }, []);

    const handleHoverScenario = useCallback((scenarioId) => {
        setHoveredScenarioId(scenarioId);
    }, []);

    const handleHoverEnd = useCallback(() => {
        setHoveredScenarioId(null);
    }, []);

    const handleOpenDetail = useCallback((scenario) => {
        setSelectedScenario(scenario);
        if (scenario?.scenario_id) {
            setDetailScenarioId(scenario.scenario_id);
            setDetailPanelOpen(true);
        }
    }, []);

    const handleCloseDetailPanel = useCallback(() => {
        setDetailPanelOpen(false);
    }, []);

    // ── Loading state ──────────────────────────────────────────────────────
    if (loading) {
        return (
            <div>
                <ThreatSubNav />
                <CommandRoomSkeleton />
            </div>
        );
    }

    // ── Error state ────────────────────────────────────────────────────────
    if (error) {
        return (
            <div>
                <ThreatSubNav />
                <div
                    style={{
                        backgroundColor: 'var(--bg-card)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 10,
                        padding: '40px 20px',
                        textAlign: 'center',
                        color: 'var(--text-muted)',
                        fontSize: 13,
                    }}
                >
                    Unable to load threat data. The threat engine may be unavailable.
                </div>
            </div>
        );
    }

    // ── Empty states ───────────────────────────────────────────────────────
    if (total === 0 && !pulseStats.last_scan_at) {
        return (
            <div>
                <ThreatSubNav criticalHighCount={criticalHighCount} />
                <RadarEmptyState />
            </div>
        );
    }

    if (total === 0 && pulseStats.last_scan_at) {
        return (
            <div>
                <ThreatSubNav criticalHighCount={criticalHighCount} />
                {/* Show pulse bar even for clean state */}
                <ThreatPulseBar
                    pulseStats={pulseStats}
                    onFilterBySeverity={handleFilterBySeverity}
                />
                <CleanEmptyState />
            </div>
        );
    }

    // ── Main layout ────────────────────────────────────────────────────────
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Sub-nav */}
            <ThreatSubNav criticalHighCount={criticalHighCount} />

            {/* Zone A: Pulse Bar */}
            <ThreatPulseBar
                pulseStats={pulseStats}
                onFilterBySeverity={handleFilterBySeverity}
            />

            {/* Zones B + C + Detail Panel */}
            <div
                style={{
                    display: 'grid',
                    /* AC2: Zone B compresses from 55% → 40% when detail panel opens */
                    gridTemplateColumns: detailPanelOpen
                        ? '40fr 0fr 60fr'   /* B compressed, C hidden, Detail expanded */
                        : '55fr 45fr 0fr',  /* B normal, C visible, Detail off-screen */
                    gap: 12,
                    alignItems: 'stretch',
                    minHeight: 520,
                    transition: 'grid-template-columns 400ms ease',
                    overflow: 'hidden',
                }}
            >
                {/* Zone B: Scenario Cards */}
                <ScenarioCardList
                    scenarios={scenarios}
                    selectedScenarioId={selectedScenario?.scenario_id || null}
                    hoveredScenarioId={hoveredScenarioId}
                    activeFilters={activeFilters}
                    searchQuery={searchQuery}
                    scanStatus={scanStatus}
                    onSelectScenario={handleSelectScenario}
                    onHoverScenario={handleHoverScenario}
                    onHoverEnd={handleHoverEnd}
                    onFilterChange={handleFilterChange}
                    onSearchChange={setSearchQuery}
                />

                {/* Zone C: Preview Panel (hidden when detail panel is open) */}
                <div style={{ overflow: 'hidden', display: detailPanelOpen ? 'none' : 'block' }}>
                    <PreviewPanel
                        hoveredScenario={hoveredScenario}
                        onOpenDetail={handleOpenDetail}
                    />
                </div>

                {/* Zone D: Scenario Detail Panel (slides in from right) */}
                <ScenarioDetailPanel
                    isOpen={detailPanelOpen}
                    scenarioId={detailScenarioId}
                    onClose={handleCloseDetailPanel}
                />
            </div>
        </div>
    );
}
