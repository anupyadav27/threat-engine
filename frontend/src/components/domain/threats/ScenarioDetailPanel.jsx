'use client';

/**
 * ScenarioDetailPanel — right-side drawer for the Scenario Detail 4-chapter view.
 *
 * Opens when a scenario card is clicked in the Command Room.
 * Slides in from the right at 400px wide (min). Zone B width transitions from
 * 55% to 40% via the parent's CSS grid (synchronised).
 *
 * Features:
 *  - Fetches data via useViewFetch('threat-scenario/{scenarioId}')
 *  - Maintains open state across card switches (no remount)
 *  - Focus trap when open (Tab cycles within panel only)
 *  - Esc key closes panel and returns focus to previously selected card
 *  - Full Page toggle expands panel to full viewport width
 *
 * @param {Object}   props
 * @param {boolean}  props.isOpen         - Whether the panel is visible
 * @param {string|null} props.scenarioId  - ID of the scenario to display
 * @param {Function} props.onClose        - Called when panel should close
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/lib/auth-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { fetchView, fetchApi } from '@/lib/api';
import { TENANT_ID } from '@/lib/constants';
import Chapter1Setup from './chapters/Chapter1Setup';
import Chapter2Anatomy from './chapters/Chapter2Anatomy';
import Chapter3Stakes from './chapters/Chapter3Stakes';
import Chapter4Response from './chapters/Chapter4Response';
import CreateTicketModal from './CreateTicketModal';

// ── Severity colour helpers ───────────────────────────────────────────────────

const SEV_COLORS = {
    critical: '#DC2626',
    high:     '#EA580C',
    medium:   '#D97706',
    low:      '#64748B',
    info:     '#6B7280',
};

function scoreColor(score) {
    if (score <= 33) return '#22C55E';
    if (score <= 66) return '#D97706';
    return '#DC2626';
}

// ── Skeleton placeholder ──────────────────────────────────────────────────────

function PanelSkeleton() {
    function Shimmer({ width = '100%', height = 14, style = {} }) {
        return (
            <div
                style={{
                    width,
                    height,
                    backgroundColor: 'var(--bg-tertiary)',
                    borderRadius: 6,
                    animation: 'pulse 1.5s ease-in-out infinite',
                    ...style,
                }}
            />
        );
    }

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14, padding: '20px 20px' }}>
            <Shimmer height={20} width="60%" />
            <Shimmer height={16} width="40%" />
            <Shimmer height={30} width="90%" />
            <Shimmer height={12} width="70%" />
            <Shimmer height={12} width="50%" />
            <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
                {[1, 2, 3, 4, 5].map((i) => (
                    <Shimmer key={i} height={30} width={60} style={{ borderRadius: 6 }} />
                ))}
            </div>
            <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {[1, 2, 3].map((i) => (
                    <Shimmer key={i} height={80} />
                ))}
            </div>
        </div>
    );
}

// ── Chapter tab bar ───────────────────────────────────────────────────────────

const CHAPTERS = [
    { id: 1, label: '1 Setup' },
    { id: 2, label: '2 Anatomy' },
    { id: 3, label: '3 Stakes' },
    { id: 4, label: '4 Response' },
    { id: 5, label: 'AI Investigation' },
];

// ── AI Investigation tab ──────────────────────────────────────────────────────

function AiInvestigationTab({ findingId, scanRunId, tenantId }) {
    const [narrative, setNarrative] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [retryCount, setRetryCount] = useState(0);

    useEffect(() => {
        if (!findingId) return;
        let cancelled = false;
        setLoading(true);
        setError(null);
        fetchApi('/gateway/api/v1/narrative/generate', {
            method: 'POST',
            body: JSON.stringify({
                finding_id: findingId,
                scan_run_id: scanRunId || '',
                tenant_id: tenantId || '',
            }),
        })
            .then((res) => {
                if (cancelled) return;
                if (res?.error) setError(res.error);
                else setNarrative(res?.narrative_text || res?.narrative || res?.text || null);
            })
            .catch((e) => { if (!cancelled) setError(String(e)); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [findingId, scanRunId, tenantId, retryCount]);

    if (loading) {
        return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: '4px 0' }}>
                {[80, 65, 90, 55, 75, 60, 85].map((w, i) => (
                    <div
                        key={i}
                        style={{
                            height: 13,
                            width: `${w}%`,
                            backgroundColor: 'var(--bg-tertiary)',
                            borderRadius: 4,
                            animation: 'pulse 1.5s ease-in-out infinite',
                            animationDelay: `${i * 80}ms`,
                        }}
                    />
                ))}
            </div>
        );
    }

    if (error || !narrative) {
        return (
            <div style={{ padding: '28px 0', textAlign: 'center' }}>
                <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 14 }}>
                    {error
                        ? `Could not generate investigation: ${error}`
                        : 'No narrative available for this scenario.'}
                </p>
                <button
                    onClick={() => setRetryCount((c) => c + 1)}
                    style={{
                        fontSize: 12,
                        padding: '5px 14px',
                        borderRadius: 6,
                        border: '1px solid var(--border-primary)',
                        background: 'var(--bg-tertiary)',
                        color: 'var(--text-secondary)',
                        cursor: 'pointer',
                    }}
                >
                    Retry
                </button>
            </div>
        );
    }

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    paddingBottom: 10,
                    borderBottom: '1px solid var(--border-primary)',
                }}
            >
                <span
                    style={{
                        width: 20,
                        height: 20,
                        borderRadius: 4,
                        backgroundColor: '#3B82F620',
                        border: '1px solid #3B82F640',
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: 9,
                        fontWeight: 900,
                        color: '#3B82F6',
                        letterSpacing: '-0.02em',
                    }}
                >
                    AI
                </span>
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                    AI Threat Investigation
                </span>
                <span
                    style={{
                        fontSize: 10,
                        padding: '2px 8px',
                        borderRadius: 4,
                        backgroundColor: '#3B82F618',
                        color: '#3B82F6',
                        fontWeight: 600,
                    }}
                >
                    AI Generated
                </span>
            </div>
            <div
                style={{
                    fontSize: 13,
                    lineHeight: 1.75,
                    color: 'var(--text-secondary)',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                }}
            >
                {narrative}
            </div>
        </div>
    );
}

// ── Panel header ──────────────────────────────────────────────────────────────

function PanelHeader({ data, onClose, onToggleFullPage, isFullPage, onCreateTicket }) {
    const {
        scenario_id = '',
        title = '',
        severity = 'medium',
        risk_score = 0,
        resource_name = '',
        csp = '',
        region = '',
        scan_age = '—',
        signal_types = [],
        mitre_techniques = [],
    } = data;

    const sevColor = SEV_COLORS[severity] || SEV_COLORS.info;
    const riskColor = scoreColor(risk_score);

    function copyLink() {
        if (typeof window !== 'undefined' && navigator?.clipboard) {
            const url = `${window.location.href.split('?')[0]}?scenario=${scenario_id}`;
            navigator.clipboard.writeText(url);
        }
    }

    return (
        <div
            style={{
                borderBottom: '1px solid var(--border-primary)',
                padding: '12px 16px',
                display: 'flex',
                flexDirection: 'column',
                gap: 10,
                flexShrink: 0,
            }}
        >
            {/* Top control row */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <button
                    onClick={onClose}
                    style={{
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        fontSize: 13,
                        color: 'var(--text-muted)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: 4,
                        padding: '2px 4px',
                        borderRadius: 4,
                    }}
                    aria-label="Close panel"
                >
                    &#8592; Back
                </button>
                <div style={{ display: 'flex', gap: 6 }}>
                    <button
                        onClick={onToggleFullPage}
                        title={isFullPage ? 'Collapse panel' : 'Expand to full page'}
                        style={{
                            background: 'none',
                            border: '1px solid var(--border-primary)',
                            cursor: 'pointer',
                            fontSize: 11,
                            color: 'var(--text-muted)',
                            padding: '3px 7px',
                            borderRadius: 4,
                        }}
                        aria-label={isFullPage ? 'Collapse panel' : 'Expand to full page'}
                    >
                        {isFullPage ? '&#8601; Collapse' : '&#8599; Full Page'}
                    </button>
                    <button
                        onClick={onClose}
                        style={{
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            fontSize: 16,
                            color: 'var(--text-muted)',
                            padding: '2px 6px',
                            borderRadius: 4,
                            lineHeight: 1,
                        }}
                        aria-label="Close panel"
                    >
                        &times;
                    </button>
                </div>
            </div>

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
                        letterSpacing: '0.06em',
                    }}
                >
                    {severity}
                </span>
                <span style={{ fontSize: 22, fontWeight: 900, color: riskColor, lineHeight: 1 }}>
                    {risk_score}
                </span>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/100</span>
            </div>

            {/* Title */}
            <h2
                style={{
                    fontSize: 15,
                    fontWeight: 700,
                    color: 'var(--text-primary)',
                    lineHeight: 1.45,
                    margin: 0,
                }}
            >
                {title || 'Threat Scenario'}
            </h2>

            {/* Resource + location + scan age */}
            <div
                style={{
                    fontSize: 11,
                    color: 'var(--text-muted)',
                    display: 'flex',
                    gap: 5,
                    flexWrap: 'wrap',
                    alignItems: 'center',
                }}
            >
                {resource_name && <span style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>{resource_name}</span>}
                {resource_name && <span>&#183;</span>}
                {csp && <span>{csp.toUpperCase()}</span>}
                {csp && region && <span>&#183;</span>}
                {region && <span>{region}</span>}
                {scan_age !== '—' && <><span>&#183;</span><span>Scan: {scan_age}</span></>}
            </div>

            {/* Signal badges + MITRE chips */}
            {(signal_types.length > 0 || mitre_techniques.length > 0) && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
                    {signal_types.map((st) => (
                        <span
                            key={st}
                            style={{
                                fontSize: 9,
                                fontWeight: 800,
                                width: 18,
                                height: 18,
                                display: 'inline-flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                borderRadius: 3,
                                backgroundColor: '#33415520',
                                border: '1px solid #47556960',
                                color: '#94A3B8',
                                textTransform: 'uppercase',
                            }}
                            title={st}
                        >
                            {st[0].toUpperCase()}
                        </span>
                    ))}
                    {mitre_techniques.slice(0, 4).map((t) => (
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

            {/* Action bar */}
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <button
                    onClick={onCreateTicket}
                    style={{
                        fontSize: 11,
                        fontWeight: 700,
                        padding: '5px 12px',
                        borderRadius: 6,
                        border: 'none',
                        backgroundColor: '#EA580C',
                        color: '#fff',
                        cursor: 'pointer',
                    }}
                >
                    Create Ticket
                </button>
                <button
                    onClick={copyLink}
                    style={{
                        fontSize: 11,
                        fontWeight: 600,
                        padding: '5px 12px',
                        borderRadius: 6,
                        border: '1px solid var(--border-primary)',
                        backgroundColor: 'var(--bg-tertiary)',
                        color: 'var(--text-secondary)',
                        cursor: 'pointer',
                    }}
                >
                    Copy
                </button>
                <button
                    onClick={copyLink}
                    style={{
                        fontSize: 11,
                        fontWeight: 600,
                        padding: '5px 12px',
                        borderRadius: 6,
                        border: '1px solid var(--border-primary)',
                        backgroundColor: 'var(--bg-tertiary)',
                        color: 'var(--text-secondary)',
                        cursor: 'pointer',
                    }}
                >
                    Share
                </button>
                <div style={{ position: 'relative' }}>
                    <MoreDropdown scenarioId={scenario_id} />
                </div>
            </div>
        </div>
    );
}

// ── More dropdown ─────────────────────────────────────────────────────────────

function MoreDropdown({ scenarioId }) {
    const [open, setOpen] = useState(false);
    const dropRef = useRef(null);

    useEffect(() => {
        if (!open) return;
        function handler(e) {
            if (dropRef.current && !dropRef.current.contains(e.target)) setOpen(false);
        }
        document.addEventListener('mousedown', handler);
        return () => document.removeEventListener('mousedown', handler);
    }, [open]);

    const baseUrl = typeof window !== 'undefined' ? window.location.origin : '';

    return (
        <div ref={dropRef}>
            <button
                onClick={() => setOpen((v) => !v)}
                aria-expanded={open}
                aria-label="More options"
                style={{
                    fontSize: 11,
                    fontWeight: 600,
                    padding: '5px 10px',
                    borderRadius: 6,
                    border: '1px solid var(--border-primary)',
                    backgroundColor: 'var(--bg-tertiary)',
                    color: 'var(--text-secondary)',
                    cursor: 'pointer',
                }}
            >
                &#8943; More
            </button>
            {open && (
                <div
                    style={{
                        position: 'absolute',
                        top: '110%',
                        right: 0,
                        backgroundColor: 'var(--bg-card)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 8,
                        padding: '4px 0',
                        minWidth: 180,
                        zIndex: 30,
                        boxShadow: '0 4px 16px rgba(0,0,0,0.3)',
                    }}
                >
                    <button
                        onClick={() => {
                            if (typeof window !== 'undefined') {
                                const blob = new Blob(
                                    [JSON.stringify({ scenario_id: scenarioId }, null, 2)],
                                    { type: 'application/json' }
                                );
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = `scenario-${scenarioId}.json`;
                                a.click();
                                URL.revokeObjectURL(url);
                            }
                            setOpen(false);
                        }}
                        style={{
                            display: 'block',
                            width: '100%',
                            textAlign: 'left',
                            fontSize: 12,
                            padding: '8px 14px',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            color: 'var(--text-secondary)',
                        }}
                    >
                        Export JSON
                    </button>
                    <a
                        href={`${baseUrl}/api/v1/threat/threats/${scenarioId}`}
                        target="_blank"
                        rel="noreferrer noopener"
                        onClick={() => setOpen(false)}
                        style={{
                            display: 'block',
                            fontSize: 12,
                            padding: '8px 14px',
                            color: 'var(--text-secondary)',
                            textDecoration: 'none',
                        }}
                    >
                        View in Threat Engine API &#8599;
                    </a>
                </div>
            )}
        </div>
    );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ScenarioDetailPanel({ isOpen, scenarioId, onClose }) {
    const [activeChapter, setActiveChapter] = useState(1);
    const [highlightedFindingId, setHighlightedFindingId] = useState(null);
    const [ticketModalOpen, setTicketModalOpen] = useState(false);
    const [isFullPage, setIsFullPage] = useState(false);
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(false);

    const panelRef = useRef(null);
    const prevScenarioIdRef = useRef(null);
    const closeButtonRef = useRef(null);

    // Auth context for tenant_id (mirrors useViewFetch pattern)
    const { selectedTenant } = useAuth();
    const { provider, account, region } = useGlobalFilter();

    // Fetch detail data when scenarioId changes — panel stays open (AC15)
    useEffect(() => {
        if (!scenarioId || !isOpen) return;
        let cancelled = false;
        setLoading(true);
        const tenantId = selectedTenant || TENANT_ID || 'default-tenant';
        const params = {
            tenant_id: tenantId,
            ...(provider ? { provider } : {}),
            ...(account ? { account } : {}),
            ...(region ? { region } : {}),
        };
        fetchView(`threat-scenario/${scenarioId}`, params)
            .then((result) => {
                if (!cancelled) {
                    setData(result?.error ? null : result || null);
                }
            })
            .catch(() => { if (!cancelled) setData(null); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [scenarioId, isOpen, selectedTenant, provider, account, region]);

    // When scenarioId changes while panel is open, reset to chapter 1
    useEffect(() => {
        if (scenarioId && scenarioId !== prevScenarioIdRef.current) {
            setActiveChapter(1);
            setHighlightedFindingId(null);
            prevScenarioIdRef.current = scenarioId;
        }
    }, [scenarioId]);

    // Escape key closes the panel
    useEffect(() => {
        if (!isOpen) return;
        function handler(e) {
            if (e.key === 'Escape') {
                onClose();
            }
        }
        document.addEventListener('keydown', handler);
        return () => document.removeEventListener('keydown', handler);
    }, [isOpen, onClose]);

    // Focus trap — Tab and Shift+Tab cycle within panel
    useEffect(() => {
        if (!isOpen || !panelRef.current) return;
        function handler(e) {
            if (e.key !== 'Tab') return;
            const focusable = panelRef.current.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
            );
            if (!focusable.length) return;
            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (e.shiftKey) {
                if (document.activeElement === first) {
                    e.preventDefault();
                    last.focus();
                }
            } else {
                if (document.activeElement === last) {
                    e.preventDefault();
                    first.focus();
                }
            }
        }
        document.addEventListener('keydown', handler);
        return () => document.removeEventListener('keydown', handler);
    }, [isOpen]);

    // Move focus into panel when it opens
    useEffect(() => {
        if (isOpen && closeButtonRef.current) {
            closeButtonRef.current.focus();
        }
    }, [isOpen]);

    const handleJumpToFinding = useCallback((findingId) => {
        setHighlightedFindingId(findingId);
        setActiveChapter(2);
    }, []);

    const handleClose = useCallback(() => {
        setIsFullPage(false);
        onClose();
    }, [onClose]);

    const hasData = data && data.scenario_id;

    return (
        <div
            ref={panelRef}
            role="complementary"
            aria-label="Scenario Detail Panel"
            style={{
                position: isFullPage ? 'fixed' : 'relative',
                inset: isFullPage ? 0 : 'auto',
                zIndex: isFullPage ? 50 : 'auto',
                width: isFullPage ? '100%' : '100%',
                height: isFullPage ? '100vh' : '100%',
                backgroundColor: 'var(--bg-card)',
                border: '1px solid var(--border-primary)',
                borderRadius: isFullPage ? 0 : 10,
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden',
                transform: isOpen ? 'translateX(0)' : 'translateX(100%)',
                transition: 'transform 400ms ease',
                visibility: isOpen ? 'visible' : 'hidden',
                minWidth: isFullPage ? '100%' : 400,
            }}
        >
            {loading ? (
                <PanelSkeleton />
            ) : !hasData ? (
                <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
                    <div style={{ textAlign: 'center' }}>
                        <button
                            ref={closeButtonRef}
                            onClick={handleClose}
                            style={{
                                background: 'none',
                                border: 'none',
                                cursor: 'pointer',
                                fontSize: 13,
                                color: 'var(--text-muted)',
                                marginBottom: 12,
                            }}
                        >
                            &times; Close
                        </button>
                        <p style={{ fontSize: 13, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                            Unable to load scenario detail.
                        </p>
                    </div>
                </div>
            ) : (
                <>
                    {/* Panel header (fixed at top) */}
                    <PanelHeader
                        data={data}
                        onClose={handleClose}
                        onToggleFullPage={() => setIsFullPage((v) => !v)}
                        isFullPage={isFullPage}
                        onCreateTicket={() => setTicketModalOpen(true)}
                    />

                    {/* Chapter tabs */}
                    <div
                        style={{
                            display: 'flex',
                            borderBottom: '1px solid var(--border-primary)',
                            flexShrink: 0,
                            paddingLeft: 12,
                        }}
                    >
                        {CHAPTERS.map((ch) => (
                            <button
                                key={ch.id}
                                onClick={() => setActiveChapter(ch.id)}
                                style={{
                                    fontSize: 12,
                                    fontWeight: activeChapter === ch.id ? 700 : 500,
                                    padding: '9px 12px',
                                    border: 'none',
                                    borderBottom: activeChapter === ch.id ? '2px solid #EA580C' : '2px solid transparent',
                                    backgroundColor: 'transparent',
                                    color: activeChapter === ch.id ? '#EA580C' : 'var(--text-muted)',
                                    cursor: 'pointer',
                                    marginBottom: -1,
                                    transition: 'color 150ms ease',
                                    whiteSpace: 'nowrap',
                                }}
                                aria-selected={activeChapter === ch.id}
                                role="tab"
                            >
                                {ch.label}
                            </button>
                        ))}
                    </div>

                    {/* Chapter content area (scrollable) */}
                    <div
                        style={{
                            flex: 1,
                            overflowY: 'auto',
                            padding: '16px 16px',
                            position: 'relative',
                        }}
                        role="tabpanel"
                    >
                        {activeChapter === 1 && (
                            <Chapter1Setup
                                data={data}
                                onJumpToFinding={handleJumpToFinding}
                            />
                        )}
                        {activeChapter === 2 && (
                            <Chapter2Anatomy
                                data={data}
                                highlightedFindingId={highlightedFindingId}
                                onJumpToFinding={handleJumpToFinding}
                            />
                        )}
                        {activeChapter === 3 && (
                            <Chapter3Stakes data={data} />
                        )}
                        {activeChapter === 4 && (
                            <Chapter4Response
                                data={data}
                                onCreateTicket={() => setTicketModalOpen(true)}
                            />
                        )}
                        {activeChapter === 5 && (
                            <AiInvestigationTab
                                findingId={data.finding_id || data.scenario_id}
                                scanRunId={data.scan_run_id}
                                tenantId={selectedTenant}
                            />
                        )}

                        {/* Create Ticket Modal — positioned within the scrollable area */}
                        <CreateTicketModal
                            isOpen={ticketModalOpen}
                            onClose={() => setTicketModalOpen(false)}
                            scenarioData={data}
                        />
                    </div>
                </>
            )}

            <style>{`
                @keyframes pulse {
                    0%   { opacity: 1; }
                    50%  { opacity: 0.5; }
                    100% { opacity: 1; }
                }
            `}</style>
        </div>
    );
}
