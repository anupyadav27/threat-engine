'use client';

/**
 * PostureSummaryRow — 4-KPI delta blocks in a horizontal row.
 *
 * KPIs: Threat Score | Scenarios | Critical | ATT&CK Coverage
 *
 * Delta coloring rules:
 *   - threat_score, scenarios, critical: lower is better
 *       negative delta → green + downward arrow (improvement)
 *       positive delta → red  + upward arrow   (regression)
 *   - attack_coverage_pct: higher is better (inverted)
 *       positive delta → green + upward arrow
 *       negative delta → red  + downward arrow
 *
 * Net change strip below the 4 blocks:
 *   "+N appeared · -N resolved · Net: ±N"
 *
 * Single-scan mode: shows an informational message card instead.
 *
 * Props:
 *   summary       {object}   - BFF summary object
 *   scanA         {object}   - {scan_run_id, completed_at, label}
 *   scanB         {object}   - {scan_run_id, completed_at, label}
 *   loading       {boolean}  - show shimmer skeleton
 *   singleScanMode {boolean} - only one scan available
 */

// ── Helper: delta badge color / arrow ─────────────────────────────────────────

function _deltaDisplay(delta, lowerIsBetter = true) {
    if (delta === 0 || delta === null || delta === undefined) {
        return { color: '#94A3B8', arrow: '→', sign: '' };
    }
    const improved = lowerIsBetter ? delta < 0 : delta > 0;
    return {
        color: improved ? '#22C55E' : '#DC2626',
        arrow: delta < 0 ? '▼' : '▲',
        sign: delta > 0 ? '+' : '',
    };
}

// ── KPI block ─────────────────────────────────────────────────────────────────

function StatBlock({ label, valueA, valueB, delta, lowerIsBetter = true, suffix = '' }) {
    const { color, arrow, sign } = _deltaDisplay(delta, lowerIsBetter);
    const deltaStr = delta !== null && delta !== undefined
        ? `${sign}${delta}${suffix}`
        : '—';

    return (
        <div
            style={{
                flex: 1,
                minWidth: 140,
                padding: '14px 16px',
                backgroundColor: 'var(--bg-secondary)',
                border: '1px solid var(--border-primary)',
                borderRadius: 8,
            }}
        >
            <p
                style={{
                    fontSize: 10,
                    fontWeight: 700,
                    color: 'var(--text-muted)',
                    letterSpacing: '0.08em',
                    textTransform: 'uppercase',
                    marginBottom: 8,
                }}
            >
                {label}
            </p>

            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, flexWrap: 'wrap' }}>
                <span style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>
                    {valueA}{suffix}
                </span>
                <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>→</span>
                <span style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)' }}>
                    {valueB}{suffix}
                </span>
            </div>

            {/* Delta badge */}
            <div
                style={{
                    marginTop: 6,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 3,
                    backgroundColor: `${color}18`,
                    color,
                    borderRadius: 4,
                    padding: '2px 7px',
                    fontSize: 11,
                    fontWeight: 700,
                }}
            >
                <span>{arrow}</span>
                <span>{deltaStr}</span>
            </div>
        </div>
    );
}

// ── Shimmer skeleton ──────────────────────────────────────────────────────────

function ShimmerBlock() {
    return (
        <div
            style={{
                flex: 1,
                minWidth: 140,
                height: 90,
                backgroundColor: 'var(--bg-tertiary)',
                borderRadius: 8,
                animation: 'pulse 1.5s ease-in-out infinite',
            }}
        />
    );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function PostureSummaryRow({
    summary = null,
    scanA = null,
    scanB = null,
    loading = false,
    singleScanMode = false,
}) {
    if (loading) {
        return (
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                {[1, 2, 3, 4].map((i) => <ShimmerBlock key={i} />)}
                <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.45} }`}</style>
            </div>
        );
    }

    // Single-scan mode: no comparison available
    if (singleScanMode) {
        return (
            <div
                style={{
                    padding: '24px 20px',
                    backgroundColor: 'var(--bg-secondary)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 8,
                    textAlign: 'center',
                    color: 'var(--text-muted)',
                    fontSize: 13,
                    lineHeight: 1.6,
                }}
            >
                <div style={{ fontSize: 28, marginBottom: 8 }}>📊</div>
                <p style={{ fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 4 }}>
                    Only one scan available.
                </p>
                <p>Run another scan to see posture changes.</p>
            </div>
        );
    }

    // No data yet (empty state before first load)
    if (!summary) {
        return (
            <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '16px 0' }}>
                No comparison data available.
            </div>
        );
    }

    const labelA = scanA?.label || 'Scan A';
    const labelB = scanB?.label || 'Scan B';

    const netChange = summary.net_change ?? 0;
    const netColor = netChange > 0 ? '#DC2626' : netChange < 0 ? '#22C55E' : '#94A3B8';
    const netSign = netChange > 0 ? '+' : '';

    return (
        <div>
            {/* Scan labels */}
            <div
                style={{
                    display: 'flex',
                    gap: 6,
                    marginBottom: 12,
                    fontSize: 11,
                    color: 'var(--text-muted)',
                    alignItems: 'center',
                }}
            >
                <span
                    style={{
                        backgroundColor: 'var(--bg-tertiary)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 4,
                        padding: '2px 8px',
                    }}
                >
                    {labelA}
                </span>
                <span>compared to</span>
                <span
                    style={{
                        backgroundColor: 'rgba(234,88,12,0.1)',
                        border: '1px solid rgba(234,88,12,0.3)',
                        borderRadius: 4,
                        padding: '2px 8px',
                        color: '#EA580C',
                    }}
                >
                    {labelB}
                </span>
            </div>

            {/* 4 KPI blocks */}
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                <StatBlock
                    label="Threat Score"
                    valueA={summary.threat_score_a ?? '—'}
                    valueB={summary.threat_score_b ?? '—'}
                    delta={summary.threat_score_delta ?? null}
                    lowerIsBetter={true}
                />
                <StatBlock
                    label="Scenarios"
                    valueA={summary.scenarios_a ?? '—'}
                    valueB={summary.scenarios_b ?? '—'}
                    delta={summary.scenarios_delta ?? null}
                    lowerIsBetter={true}
                />
                <StatBlock
                    label="Critical"
                    valueA={summary.critical_a ?? '—'}
                    valueB={summary.critical_b ?? '—'}
                    delta={summary.critical_delta ?? null}
                    lowerIsBetter={true}
                />
                <StatBlock
                    label="ATT&CK Coverage"
                    valueA={summary.attack_coverage_pct_a ?? '—'}
                    valueB={summary.attack_coverage_pct_b ?? '—'}
                    delta={summary.attack_coverage_delta ?? null}
                    lowerIsBetter={false}
                    suffix="%"
                />
            </div>

            {/* Net change strip */}
            <div
                style={{
                    marginTop: 12,
                    padding: '8px 14px',
                    backgroundColor: 'var(--bg-secondary)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 6,
                    fontSize: 12,
                    color: 'var(--text-muted)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    flexWrap: 'wrap',
                }}
            >
                <span>
                    <span style={{ color: '#DC2626', fontWeight: 600 }}>
                        +{summary.new_count ?? 0}
                    </span>
                    {' '}appeared
                </span>
                <span style={{ color: 'var(--border-primary)' }}>·</span>
                <span>
                    <span style={{ color: '#22C55E', fontWeight: 600 }}>
                        -{summary.resolved_count ?? 0}
                    </span>
                    {' '}resolved
                </span>
                <span style={{ color: 'var(--border-primary)' }}>·</span>
                <span>
                    Net:{' '}
                    <span style={{ color: netColor, fontWeight: 700 }}>
                        {netSign}{netChange}
                    </span>
                </span>
            </div>
        </div>
    );
}
