'use client';

/**
 * ScenarioCardList — Zone B of the Threat Command Room.
 *
 * Renders filter controls, a search box, active filter chips, and the
 * list of ScenarioCard components.  All filtering is client-side; no
 * additional network calls are made when filters change.
 *
 * @param {Object}   props
 * @param {Array}    props.scenarios          - Full scenarios array from BFF
 * @param {string}   props.selectedScenarioId - Currently selected scenario id
 * @param {string}   props.hoveredScenarioId  - Currently hovered scenario id (for Zone C)
 * @param {Object}   props.activeFilters      - { severity, csp, technique, signalType, sort }
 * @param {string}   props.searchQuery
 * @param {string|null} props.scanStatus      - 'running' | 'completed' | null
 * @param {Function} props.onSelectScenario   - Called with scenario when a card is clicked
 * @param {Function} props.onHoverScenario    - Called with scenario_id when a card is hovered
 * @param {Function} props.onHoverEnd         - Called when hover ends
 * @param {Function} props.onFilterChange     - Called with { key, value } to update filters
 * @param {Function} props.onSearchChange     - Called with search string
 */

import { useMemo, useCallback, useRef, useState } from 'react';
import ScenarioCard from './ScenarioCard';

const SORT_OPTIONS = [
    { value: 'risk_score',  label: 'Risk Score' },
    { value: 'severity',    label: 'Severity' },
    { value: 'first_seen',  label: 'First Seen' },
];

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function Chip({ label, onRemove }) {
    return (
        <span
            style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                backgroundColor: 'rgba(234,88,12,0.1)',
                border: '1px solid rgba(234,88,12,0.3)',
                color: '#EA580C',
                borderRadius: 9999,
                fontSize: 11,
                fontWeight: 600,
                padding: '2px 8px',
            }}
        >
            {label}
            <button
                onClick={onRemove}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#EA580C', padding: 0, lineHeight: 1, fontSize: 13 }}
            >
                ×
            </button>
        </span>
    );
}

function FilterSelect({ label, options, value, onChange }) {
    return (
        <select
            value={value || ''}
            onChange={(e) => onChange(e.target.value || null)}
            style={{
                backgroundColor: 'var(--bg-secondary)',
                border: '1px solid var(--border-primary)',
                borderRadius: 6,
                color: 'var(--text-secondary)',
                fontSize: 12,
                padding: '5px 10px',
                cursor: 'pointer',
            }}
        >
            <option value="">{label}</option>
            {options.map((opt) => (
                <option key={opt} value={opt}>{opt}</option>
            ))}
        </select>
    );
}

export default function ScenarioCardList({
    scenarios = [],
    selectedScenarioId = null,
    hoveredScenarioId  = null,
    activeFilters      = {},
    searchQuery        = '',
    scanStatus         = null,
    onSelectScenario,
    onHoverScenario,
    onHoverEnd,
    onFilterChange,
    onSearchChange,
}) {
    const searchTimer = useRef(null);

    // ── Derived filter options from live data ──────────────────────────────
    const filterOptions = useMemo(() => {
        const csps       = [...new Set(scenarios.map((s) => s.csp).filter(Boolean))].sort();
        const techniques = [
            ...new Set(
                scenarios.flatMap((s) =>
                    (s.mitre_techniques || []).map((t) => t.id).filter(Boolean)
                )
            ),
        ].sort();
        const signalTypes = [
            ...new Set(scenarios.flatMap((s) => s.signal_types || []).filter(Boolean)),
        ].sort();
        return { csps, techniques, signalTypes };
    }, [scenarios]);

    // ── Filtered + sorted scenarios (all client-side) ─────────────────────
    const filtered = useMemo(() => {
        let list = [...scenarios];

        // Severity filter
        if (activeFilters.severity) {
            list = list.filter((s) => s.severity === activeFilters.severity);
        }
        // CSP filter
        if (activeFilters.csp) {
            list = list.filter((s) => (s.csp || '').toLowerCase() === activeFilters.csp.toLowerCase());
        }
        // Technique filter
        if (activeFilters.technique) {
            list = list.filter((s) =>
                (s.mitre_techniques || []).some((t) => t.id === activeFilters.technique)
            );
        }
        // Signal type filter
        if (activeFilters.signalType) {
            list = list.filter((s) =>
                (s.signal_types || []).includes(activeFilters.signalType)
            );
        }
        // Search
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
        const sort = activeFilters.sort || 'risk_score';
        if (sort === 'risk_score') {
            list.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
        } else if (sort === 'severity') {
            list.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
        } else if (sort === 'first_seen') {
            list.sort((a, b) => {
                const ta = a.first_seen_at || '';
                const tb = b.first_seen_at || '';
                return tb.localeCompare(ta);
            });
        }

        return list;
    }, [scenarios, activeFilters, searchQuery]);

    // ── Active filter chips ────────────────────────────────────────────────
    const activeChips = useMemo(() => {
        const chips = [];
        if (activeFilters.severity)   chips.push({ key: 'severity',   label: activeFilters.severity });
        if (activeFilters.csp)        chips.push({ key: 'csp',        label: activeFilters.csp.toUpperCase() });
        if (activeFilters.technique)  chips.push({ key: 'technique',  label: activeFilters.technique });
        if (activeFilters.signalType) chips.push({ key: 'signalType', label: activeFilters.signalType });
        return chips;
    }, [activeFilters]);

    // ── Debounced search ───────────────────────────────────────────────────
    const handleSearchInput = useCallback((e) => {
        const val = e.target.value;
        clearTimeout(searchTimer.current);
        searchTimer.current = setTimeout(() => {
            onSearchChange && onSearchChange(val);
        }, 200);
    }, [onSearchChange]);

    const clearAllFilters = useCallback(() => {
        ['severity', 'csp', 'technique', 'signalType'].forEach((key) =>
            onFilterChange && onFilterChange({ key, value: null })
        );
        onSearchChange && onSearchChange('');
    }, [onFilterChange, onSearchChange]);

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0, height: '100%' }}>

            {/* Scan-in-progress amber banner */}
            {scanStatus === 'running' && (
                <div
                    style={{
                        backgroundColor: 'rgba(217,119,6,0.1)',
                        border: '1px solid rgba(217,119,6,0.3)',
                        borderRadius: 6,
                        padding: '8px 14px',
                        marginBottom: 10,
                        fontSize: 12,
                        color: '#D97706',
                        fontWeight: 600,
                    }}
                >
                    Scan in progress — results will update automatically.
                </div>
            )}

            {/* ── Filter row ─────────────────────────────────────────────── */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
                <FilterSelect
                    label="All CSPs"
                    options={filterOptions.csps}
                    value={activeFilters.csp}
                    onChange={(v) => onFilterChange && onFilterChange({ key: 'csp', value: v })}
                />
                <FilterSelect
                    label="Techniques"
                    options={filterOptions.techniques}
                    value={activeFilters.technique}
                    onChange={(v) => onFilterChange && onFilterChange({ key: 'technique', value: v })}
                />
                <FilterSelect
                    label="Signals"
                    options={filterOptions.signalTypes}
                    value={activeFilters.signalType}
                    onChange={(v) => onFilterChange && onFilterChange({ key: 'signalType', value: v })}
                />

                {/* Sort */}
                <select
                    value={activeFilters.sort || 'risk_score'}
                    onChange={(e) => onFilterChange && onFilterChange({ key: 'sort', value: e.target.value })}
                    style={{
                        backgroundColor: 'var(--bg-secondary)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 6,
                        color: 'var(--text-secondary)',
                        fontSize: 12,
                        padding: '5px 10px',
                        cursor: 'pointer',
                    }}
                >
                    {SORT_OPTIONS.map((o) => (
                        <option key={o.value} value={o.value}>Sort: {o.label}</option>
                    ))}
                </select>

                {/* Search */}
                <input
                    type="text"
                    placeholder="Search scenarios..."
                    defaultValue={searchQuery}
                    onChange={handleSearchInput}
                    style={{
                        flex: 1,
                        minWidth: 140,
                        backgroundColor: 'var(--bg-secondary)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 6,
                        color: 'var(--text-primary)',
                        fontSize: 12,
                        padding: '5px 10px',
                        outline: 'none',
                    }}
                />
            </div>

            {/* Active filter chips */}
            {activeChips.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
                    {activeChips.map(({ key, label }) => (
                        <Chip
                            key={key}
                            label={label}
                            onRemove={() => onFilterChange && onFilterChange({ key, value: null })}
                        />
                    ))}
                    <button
                        onClick={clearAllFilters}
                        style={{
                            fontSize: 11,
                            color: 'var(--text-muted)',
                            background: 'none',
                            border: 'none',
                            cursor: 'pointer',
                            textDecoration: 'underline',
                        }}
                    >
                        Clear all
                    </button>
                </div>
            )}

            {/* ── Card list ──────────────────────────────────────────────── */}
            <div
                style={{
                    flex: 1,
                    overflowY: 'auto',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 6,
                }}
            >
                {filtered.length === 0 && (
                    <div
                        style={{
                            flex: 1,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: 'var(--text-muted)',
                            fontSize: 13,
                            padding: '40px 20px',
                            textAlign: 'center',
                        }}
                    >
                        No scenarios match the current filters.
                    </div>
                )}
                {filtered.map((scenario) => (
                    <ScenarioCard
                        key={scenario.scenario_id || scenario.resource_uid}
                        scenario={scenario}
                        isSelected={selectedScenarioId === scenario.scenario_id}
                        isHovered={hoveredScenarioId === scenario.scenario_id}
                        onSelect={onSelectScenario}
                        onHover={onHoverScenario}
                        onHoverEnd={onHoverEnd}
                    />
                ))}
            </div>

            {/* Count footer */}
            {filtered.length > 0 && (
                <div
                    style={{
                        fontSize: 11,
                        color: 'var(--text-muted)',
                        paddingTop: 8,
                        borderTop: '1px solid var(--border-primary)',
                        marginTop: 6,
                        textAlign: 'right',
                    }}
                >
                    Showing {filtered.length} of {scenarios.length} scenarios
                </div>
            )}
        </div>
    );
}
