'use client';

/**
 * CommandRoom — Threat Command Room (THREATS-UI-01).
 *
 * Layout: flex column — ThreatSubNav → ThreatPulseBar → FilterBar → ScenarioCardList.
 * Scenario selection opens a centered ScenarioModal overlay (no layout shift).
 *
 * URL state (ADR-CR-03 / ADR-CR-04):
 *   ?selected=<id>&sev=CRIT,HIGH&status=open&sort=risk_score
 *
 * All filtering is client-side; no re-fetch on filter changes.
 * Poll interval: 30 seconds when scan_status === 'running'.
 */

import { useState, useCallback, useEffect, useRef, useMemo } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { useViewFetch } from '@/lib/use-view-fetch';
import { useThreatBadge } from '@/lib/threat-badge-context';
import { useAuth } from '@/lib/auth-context';
import ThreatPulseBar from './ThreatPulseBar';
import ThreatSubNav from './ThreatSubNav';
import ScenarioCardList from './ScenarioCardList';
import { FilterBar } from './FilterBar';
import { ScenarioModal } from './ScenarioModal';

// ── Severity normalisation ─────────────────────────────────────────────────────
// BFF uses lowercase ('critical'); FilterBar uses abbreviated uppercase ('CRIT').
const SEV_MAP = {
    CRIT: 'critical',
    HIGH: 'high',
    MED:  'medium',
    LOW:  'low',
};

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ── Skeleton ───────────────────────────────────────────────────────────────────

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

            {/* Filter bar skeleton */}
            <div
                style={{
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 8,
                    padding: '8px 12px',
                    height: 44,
                }}
            />

            {/* Card list skeleton */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {[1, 2, 3, 4, 5].map((i) => (
                    <div
                        key={i}
                        style={{
                            backgroundColor: 'var(--bg-card)',
                            border: '1px solid var(--border-primary)',
                            borderRadius: 8,
                            padding: '14px',
                            height: 88,
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 8,
                            justifyContent: 'center',
                        }}
                    >
                        <SkeletonRow width="70%" height={14} />
                        <SkeletonRow width="45%" height={12} />
                    </div>
                ))}
            </div>
        </div>
    );
}

// ── Empty states ───────────────────────────────────────────────────────────────

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
        <div
            style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 20,
                padding: '60px 20px',
                textAlign: 'center',
            }}
        >
            <svg width={120} height={120} viewBox="0 0 120 120" aria-hidden="true" style={{ opacity: 0.5 }}>
                <polygon points={hex(r1)} fill="none" stroke="var(--accent-primary)" strokeWidth="1.5" opacity="0.3" />
                <polygon points={hex(r2)} fill="none" stroke="var(--accent-primary)" strokeWidth="1.5" opacity="0.25" />
                <polygon points={hex(r3)} fill="none" stroke="var(--accent-primary)" strokeWidth="1.5" opacity="0.2" />
                {Array.from({ length: 6 }, (_, i) => {
                    const a = (Math.PI / 3) * i - Math.PI / 2;
                    return (
                        <line
                            key={i}
                            x1={c} y1={c}
                            x2={c + r1 * Math.cos(a)}
                            y2={c + r1 * Math.sin(a)}
                            stroke="var(--accent-primary)"
                            strokeWidth="0.75"
                            opacity="0.2"
                        />
                    );
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
        <div
            style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: 20,
                padding: '60px 20px',
                textAlign: 'center',
            }}
        >
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
                        View all findings
                    </Link>
                    <Link href="/threats/attack-map" style={{ color: 'var(--text-muted)', textDecoration: 'underline' }}>
                        Check ATT&amp;CK coverage
                    </Link>
                </div>
            </div>
        </div>
    );
}

// ── CommandRoom ────────────────────────────────────────────────────────────────

export default function CommandRoom() {
    const { data, loading, error, refetch } = useViewFetch('threat-command-room');
    const { setBadgeCount } = useThreatBadge();
    const auth = useAuth();

    // ── URL state ──────────────────────────────────────────────────────────
    const searchParams = useSearchParams();
    const router = useRouter();

    const selectedId  = searchParams.get('selected');
    const isModalOpen = !!selectedId;

    // Filters derived from URL (with defaults)
    const urlSev    = searchParams.get('sev')    || '';
    const urlStatus = searchParams.get('status') || 'open';
    const urlSort   = searchParams.get('sort')   || 'risk_score';

    // Local-only filter state (search is not URL-encoded — it's ephemeral)
    const [searchQuery, setSearchQuery] = useState('');

    // Merged filter object passed to FilterBar
    const filters = {
        sev:    urlSev,
        status: urlStatus,
        sort:   urlSort,
        search: searchQuery,
    };

    const pollRef = useRef(null);

    // ── Extract BFF data ───────────────────────────────────────────────────
    const pulseStats = useMemo(() => data.pulse_stats || {}, [data.pulse_stats]);
    const scenarios  = useMemo(() => data.scenarios   || [], [data.scenarios]);
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

    // ── Derived: criticalHighCount for sub-nav badge ───────────────────────
    const criticalHighCount = (pulseStats.critical_count || 0) + (pulseStats.high_count || 0);

    // ── Filtering + sorting (all client-side) ─────────────────────────────
    const filteredScenarios = useMemo(() => {
        let list = [...scenarios];

        // Severity filter (multi-select from URL sev param)
        if (urlSev) {
            const sevKeys = urlSev.split(',').filter(Boolean).map((s) => SEV_MAP[s]).filter(Boolean);
            if (sevKeys.length > 0) {
                list = list.filter((s) => sevKeys.includes((s.severity || '').toLowerCase()));
            }
        }

        // Status filter
        if (urlStatus && urlStatus !== 'all') {
            list = list.filter((s) => (s.status || 'open') === urlStatus);
        }

        // Search filter
        if (searchQuery.trim()) {
            const q = searchQuery.trim().toLowerCase();
            list = list.filter(
                (s) =>
                    s.title?.toLowerCase().includes(q) ||
                    s.resource_name?.toLowerCase().includes(q) ||
                    s.resource_uid?.toLowerCase().includes(q) ||
                    (s.mitre_techniques || []).some((t) => t.id?.toLowerCase().includes(q))
            );
        }

        // Sort
        if (urlSort === 'risk_score') {
            list.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
        } else if (urlSort === 'severity') {
            list.sort(
                (a, b) =>
                    (SEV_ORDER[(a.severity || '').toLowerCase()] ?? 9) -
                    (SEV_ORDER[(b.severity || '').toLowerCase()] ?? 9)
            );
        } else if (urlSort === 'newest') {
            list.sort((a, b) => {
                const ta = a.first_seen_at || '';
                const tb = b.first_seen_at || '';
                return tb.localeCompare(ta);
            });
        } else if (urlSort === 'resource_name') {
            list.sort((a, b) =>
                (a.resource_name || '').localeCompare(b.resource_name || '')
            );
        }

        return list;
    }, [scenarios, urlSev, urlStatus, urlSort, searchQuery]);

    // ── Selected scenario object ───────────────────────────────────────────
    const selectedScenario = useMemo(() => {
        if (!selectedId) return null;
        return scenarios.find((s) => s.scenario_id === selectedId) || null;
    }, [selectedId, scenarios]);

    // ── URL navigation helpers ─────────────────────────────────────────────
    const buildParams = useCallback(
        (overrides = {}) => {
            const params = new URLSearchParams(searchParams.toString());
            Object.entries(overrides).forEach(([k, v]) => {
                if (v === null || v === undefined || v === '') {
                    params.delete(k);
                } else {
                    params.set(k, v);
                }
            });
            return params.toString();
        },
        [searchParams]
    );

    const handleCardClick = useCallback(
        (scenario) => {
            // Mobile fallback: navigate directly instead of opening modal
            if (typeof window !== 'undefined' && window.innerWidth < 768) {
                router.push(`/threats/${scenario.scenario_id}`);
                return;
            }
            const qs = buildParams({ selected: scenario.scenario_id });
            router.push(`/threats?${qs}`, { scroll: false });
        },
        [router, buildParams]
    );

    const handleClose = useCallback(() => {
        const qs = buildParams({ selected: null });
        router.push(qs ? `/threats?${qs}` : '/threats', { scroll: false });
    }, [router, buildParams]);

    // ── Filter change handler ──────────────────────────────────────────────
    const handleFilterChange = useCallback(
        (partial) => {
            // Search is local state
            if ('search' in partial) {
                setSearchQuery(partial.search || '');
                return;
            }
            const qs = buildParams(partial);
            router.push(qs ? `/threats?${qs}` : '/threats', { scroll: false });
        },
        [buildParams, router]
    );

    // Wire ThreatPulseBar severity click to toggle the sev URL param
    const handleSeverityToggle = useCallback(
        (severity) => {
            // PulseBar sends lowercase e.g. 'critical' — map to CRIT abbreviation
            const abbr = Object.entries(SEV_MAP).find(([, v]) => v === severity)?.[0];
            if (!abbr) return;
            const current = urlSev ? urlSev.split(',').filter(Boolean) : [];
            const next = current.includes(abbr)
                ? current.filter((s) => s !== abbr)
                : [...current, abbr];
            handleFilterChange({ sev: next.join(',') });
        },
        [urlSev, handleFilterChange]
    );

    // ── ESC key closes modal ───────────────────────────────────────────────
    useEffect(() => {
        function onKeyDown(e) {
            if (e.key === 'Escape' && isModalOpen) handleClose();
        }
        document.addEventListener('keydown', onKeyDown);
        return () => document.removeEventListener('keydown', onKeyDown);
    }, [isModalOpen, handleClose]);

    // ── Auto-close modal when selected scenario is filtered out ────────────
    useEffect(() => {
        if (!selectedId) return;
        const stillVisible = filteredScenarios.some((s) => s.scenario_id === selectedId);
        if (!stillVisible) handleClose();
    }, [filteredScenarios, selectedId, handleClose]);

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
                <ThreatPulseBar
                    pulseStats={pulseStats}
                    onFilterBySeverity={handleSeverityToggle}
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

            {/* KPI strip */}
            <ThreatPulseBar
                pulseStats={pulseStats}
                onFilterBySeverity={handleSeverityToggle}
            />

            {/* Filter bar */}
            <FilterBar filters={filters} onFilterChange={handleFilterChange} />

            {/* Card list — always full width, never reflowed by modal */}
            <ScenarioCardList
                scenarios={filteredScenarios}
                selectedId={selectedId}
                onCardClick={handleCardClick}
                scanStatus={scanStatus}
                totalCount={total}
            />

            {/* Centered modal — rendered via portal, no layout impact */}
            {isModalOpen && selectedScenario && (
                <ScenarioModal
                    scenario={selectedScenario}
                    onClose={handleClose}
                    userRole={auth.role}
                />
            )}
        </div>
    );
}
