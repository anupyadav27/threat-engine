'use client';

/**
 * ThreatTrendChart — 90-day threat trend chart with three display modes.
 *
 * Display modes (toggle buttons):
 *   1. "Show Score"       (default) — LineChart, risk_score line
 *   2. "Show by Severity" — AreaChart stacked by severity
 *   3. "Show by Tactic"   — LineChart one line per MITRE tactic
 *                           disabled when no tactics data is available
 *
 * Each data point represents one completed scan run.
 * Hover tooltip: date + scan_run_id (8 chars) + values + "View this scan" link.
 *
 * Props:
 *   trendPoints  {Array}    - BFF trend_data array
 *   loading      {boolean}  - show shimmer when true
 */

import { useState, useMemo } from 'react';
import {
    LineChart,
    Line,
    AreaChart,
    Area,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from 'recharts';

// ── Color constants ────────────────────────────────────────────────────────────

const SEV_COLORS = {
    critical: '#DC2626',
    high: '#EA580C',
    medium: '#D97706',
    low: '#64748B',
};
const SCORE_COLOR = '#EA580C';
const TACTIC_COLORS = [
    '#3B82F6', '#8B5CF6', '#22C55E', '#F59E0B', '#EC4899', '#0D9488',
    '#F97316', '#6366F1',
];

// ── Date tick formatter ────────────────────────────────────────────────────────

function _formatDateTick(dateStr) {
    if (!dateStr) return '';
    try {
        const d = new Date(dateStr);
        return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch {
        return dateStr.slice(5, 10);
    }
}

// ── Custom tooltip ─────────────────────────────────────────────────────────────

function CustomTooltip({ active, payload, label, mode }) {
    if (!active || !payload?.length) return null;

    const scanRunId = payload[0]?.payload?.scan_run_id || '';
    const shortId = scanRunId ? scanRunId.slice(0, 8) : '';

    const handleViewScan = () => {
        if (scanRunId) {
            window.location.href = `/threats?scan_run_id=${scanRunId}`;
        }
    };

    return (
        <div
            style={{
                backgroundColor: 'var(--bg-card)',
                border: '1px solid var(--border-primary)',
                borderRadius: 8,
                padding: '10px 14px',
                fontSize: 12,
                minWidth: 180,
                boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            }}
        >
            <p
                style={{
                    fontWeight: 700,
                    color: 'var(--text-secondary)',
                    marginBottom: 6,
                    fontSize: 11,
                }}
            >
                {_formatDateTick(label)}
                {shortId && (
                    <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 6 }}>
                        #{shortId}
                    </span>
                )}
            </p>

            {payload.map((p, i) => (
                <div
                    key={i}
                    style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        gap: 16,
                        paddingBottom: 2,
                    }}
                >
                    <span style={{ color: p.color, display: 'flex', alignItems: 'center', gap: 5 }}>
                        <span
                            style={{
                                width: 7,
                                height: 7,
                                borderRadius: '50%',
                                backgroundColor: p.color,
                                flexShrink: 0,
                                display: 'inline-block',
                            }}
                        />
                        {p.name}
                    </span>
                    <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                        {p.value}
                    </span>
                </div>
            ))}

            {scanRunId && (
                <p
                    onClick={handleViewScan}
                    style={{
                        marginTop: 8,
                        fontSize: 11,
                        color: '#EA580C',
                        cursor: 'pointer',
                        textDecoration: 'underline',
                        borderTop: '1px solid var(--border-primary)',
                        paddingTop: 6,
                    }}
                >
                    View this scan →
                </p>
            )}
        </div>
    );
}

// ── Shimmer placeholder ────────────────────────────────────────────────────────

function ChartShimmer() {
    return (
        <div
            style={{
                width: '100%',
                height: 280,
                backgroundColor: 'var(--bg-tertiary)',
                borderRadius: 8,
                animation: 'pulse 1.5s ease-in-out infinite',
            }}
        >
            <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.45} }`}</style>
        </div>
    );
}

// ── Toggle button ──────────────────────────────────────────────────────────────

function ModeButton({ label, active, disabled, disabledTitle, onClick }) {
    return (
        <button
            onClick={disabled ? undefined : onClick}
            title={disabled ? disabledTitle : undefined}
            style={{
                padding: '4px 12px',
                borderRadius: 6,
                fontSize: 12,
                fontWeight: active ? 700 : 500,
                border: '1px solid',
                borderColor: disabled
                    ? 'var(--border-primary)'
                    : active
                    ? '#EA580C'
                    : 'var(--border-primary)',
                backgroundColor: disabled
                    ? 'transparent'
                    : active
                    ? 'rgba(234,88,12,0.12)'
                    : 'transparent',
                color: disabled
                    ? 'var(--text-muted)'
                    : active
                    ? '#EA580C'
                    : 'var(--text-secondary)',
                cursor: disabled ? 'not-allowed' : 'pointer',
                opacity: disabled ? 0.5 : 1,
            }}
        >
            {label}
        </button>
    );
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function ThreatTrendChart({ trendPoints = [], loading = false }) {
    const [mode, setMode] = useState('score'); // 'score' | 'severity' | 'tactic'

    // Check if tactic data is available at all
    const tacticsAvailable = useMemo(
        () => trendPoints.some((p) => p.tactics && Object.keys(p.tactics).length > 0),
        [trendPoints],
    );

    // Collect all tactic keys across all data points
    const allTactics = useMemo(() => {
        if (!tacticsAvailable) return [];
        const keys = new Set();
        trendPoints.forEach((p) => {
            if (p.tactics) Object.keys(p.tactics).forEach((k) => keys.add(k));
        });
        return Array.from(keys).sort();
    }, [trendPoints, tacticsAvailable]);

    // Flatten tactic counts into each data point for tactic mode (must be before early returns)
    const flatPoints = useMemo(() => {
        if (mode !== 'tactic') return trendPoints;
        return trendPoints.map((p) => ({
            ...p,
            ...(p.tactics || {}),
        }));
    }, [trendPoints, mode]);

    if (loading) return <ChartShimmer />;

    if (!trendPoints.length) {
        return (
            <div
                style={{
                    height: 280,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'var(--text-muted)',
                    fontSize: 13,
                    border: '1px dashed var(--border-primary)',
                    borderRadius: 8,
                }}
            >
                No trend data available for this period.
            </div>
        );
    }

    const chartProps = {
        data: flatPoints,
        margin: { top: 8, right: 16, left: 0, bottom: 4 },
    };

    const xAxisProps = {
        dataKey: 'date',
        tickFormatter: _formatDateTick,
        tick: { fill: 'var(--text-muted)', fontSize: 11 },
        tickLine: false,
        axisLine: { stroke: 'var(--border-primary)' },
        dy: 6,
    };

    return (
        <div>
            {/* Mode toggles */}
            <div style={{ display: 'flex', gap: 6, marginBottom: 16, flexWrap: 'wrap' }}>
                <ModeButton
                    label="Show Score"
                    active={mode === 'score'}
                    onClick={() => setMode('score')}
                />
                <ModeButton
                    label="Show by Severity"
                    active={mode === 'severity'}
                    onClick={() => setMode('severity')}
                />
                <ModeButton
                    label="Show by Tactic"
                    active={mode === 'tactic'}
                    disabled={!tacticsAvailable}
                    disabledTitle="Tactic-level data not available for this scan range."
                    onClick={() => setMode('tactic')}
                />
            </div>

            {/* Chart */}
            <ResponsiveContainer width="100%" height={280}>
                {mode === 'severity' ? (
                    <AreaChart {...chartProps}>
                        <CartesianGrid
                            horizontal
                            strokeDasharray="3 3"
                            stroke="var(--border-primary)"
                            vertical={false}
                        />
                        <XAxis {...xAxisProps} />
                        <YAxis
                            tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                            tickLine={false}
                            axisLine={false}
                            width={32}
                        />
                        <Tooltip
                            content={<CustomTooltip mode={mode} />}
                            cursor={{ stroke: 'rgba(148,163,184,0.12)', strokeWidth: 1.5 }}
                        />
                        <Area
                            type="monotone"
                            dataKey="critical"
                            name="Critical"
                            stackId="sev"
                            stroke={SEV_COLORS.critical}
                            fill={SEV_COLORS.critical}
                            fillOpacity={0.75}
                            isAnimationActive={false}
                        />
                        <Area
                            type="monotone"
                            dataKey="high"
                            name="High"
                            stackId="sev"
                            stroke={SEV_COLORS.high}
                            fill={SEV_COLORS.high}
                            fillOpacity={0.65}
                            isAnimationActive={false}
                        />
                        <Area
                            type="monotone"
                            dataKey="medium"
                            name="Medium"
                            stackId="sev"
                            stroke={SEV_COLORS.medium}
                            fill={SEV_COLORS.medium}
                            fillOpacity={0.55}
                            isAnimationActive={false}
                        />
                        <Area
                            type="monotone"
                            dataKey="low"
                            name="Low"
                            stackId="sev"
                            stroke={SEV_COLORS.low}
                            fill={SEV_COLORS.low}
                            fillOpacity={0.45}
                            isAnimationActive={false}
                        />
                    </AreaChart>
                ) : mode === 'tactic' && allTactics.length > 0 ? (
                    <LineChart {...chartProps}>
                        <CartesianGrid
                            horizontal
                            strokeDasharray="3 3"
                            stroke="var(--border-primary)"
                            vertical={false}
                        />
                        <XAxis {...xAxisProps} />
                        <YAxis
                            tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                            tickLine={false}
                            axisLine={false}
                            width={32}
                        />
                        <Tooltip
                            content={<CustomTooltip mode={mode} />}
                            cursor={{ stroke: 'rgba(148,163,184,0.12)', strokeWidth: 1.5 }}
                        />
                        {allTactics.map((tactic, idx) => (
                            <Line
                                key={tactic}
                                type="monotone"
                                dataKey={tactic}
                                name={tactic}
                                stroke={TACTIC_COLORS[idx % TACTIC_COLORS.length]}
                                strokeWidth={1.8}
                                dot={false}
                                activeDot={{ r: 4, strokeWidth: 0 }}
                                isAnimationActive={false}
                            />
                        ))}
                    </LineChart>
                ) : (
                    /* Default: Show Score */
                    <LineChart {...chartProps}>
                        <CartesianGrid
                            horizontal
                            strokeDasharray="3 3"
                            stroke="var(--border-primary)"
                            vertical={false}
                        />
                        <XAxis {...xAxisProps} />
                        <YAxis
                            domain={[0, 100]}
                            ticks={[0, 25, 50, 75, 100]}
                            tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                            tickLine={false}
                            axisLine={false}
                            width={32}
                        />
                        <Tooltip
                            content={<CustomTooltip mode={mode} />}
                            cursor={{ stroke: 'rgba(148,163,184,0.12)', strokeWidth: 1.5 }}
                        />
                        <Line
                            type="monotone"
                            dataKey="risk_score"
                            name="Risk Score"
                            stroke={SCORE_COLOR}
                            strokeWidth={2}
                            dot={{ r: 3, fill: SCORE_COLOR, strokeWidth: 0 }}
                            activeDot={{ r: 5, strokeWidth: 0 }}
                            isAnimationActive={false}
                        />
                    </LineChart>
                )}
            </ResponsiveContainer>
        </div>
    );
}
