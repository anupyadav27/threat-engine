'use client';

/**
 * PostureDelta — main container for the Trends & Posture page.
 *
 * Layout:
 *   1. ScanComparison (selector + preset day buttons)
 *   2. PostureSummaryRow (4-KPI delta row)
 *   3. ThreatTrendChart (90-day line/area chart)
 *   4. WhatChangedTabs (New | Resolved | Escalated | De-escalated)
 *
 * Props:
 *   deltaData     {object}  - BFF /threat-posture-delta response
 *   trendData     {object}  - BFF /threat-trend response
 *   deltaLoading  {boolean} - delta fetch in flight
 *   trendLoading  {boolean} - trend fetch in flight
 *   onScanChange  {function(scan_a_id, scan_b_id)} - called when scan selection changes
 *   onDaysChange  {function(days)} - called when chart window changes
 *   activeDays    {number}  - currently selected days window
 */

import ThreatSubNav from './ThreatSubNav';
import ScanComparison from './ScanComparison';
import PostureSummaryRow from './PostureSummaryRow';
import ThreatTrendChart from './ThreatTrendChart';
import WhatChangedTabs from './WhatChangedTabs';

export default function PostureDelta({
    deltaData = {},
    trendData = {},
    deltaLoading = false,
    trendLoading = false,
    onScanChange,
    onDaysChange,
    activeDays = 90,
}) {
    const availableScans = deltaData.available_scans || [];
    const scanA = deltaData.scan_a || null;
    const scanB = deltaData.scan_b || null;
    const summary = deltaData.summary || null;
    const singleScanMode = deltaData.single_scan_mode === true;
    const trendPoints = trendData.trend_data || [];

    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {/* Sub-navigation */}
            <ThreatSubNav />

            {/* Section: Scan Selector */}
            <div
                style={{
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 10,
                    padding: '14px 20px',
                    marginBottom: 12,
                }}
            >
                <ScanComparison
                    availableScans={availableScans}
                    activeScanA={scanA?.scan_run_id || ''}
                    activeScanB={scanB?.scan_run_id || ''}
                    activeDays={activeDays}
                    loading={deltaLoading}
                    onScanChange={onScanChange}
                    onDaysChange={onDaysChange}
                />
            </div>

            {/* Section: Posture Summary Row */}
            <div
                style={{
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 10,
                    padding: '20px',
                    marginBottom: 12,
                }}
            >
                <p
                    style={{
                        fontSize: 11,
                        fontWeight: 700,
                        color: 'var(--text-muted)',
                        letterSpacing: '0.08em',
                        textTransform: 'uppercase',
                        marginBottom: 14,
                    }}
                >
                    Posture Summary
                </p>
                <PostureSummaryRow
                    summary={summary}
                    scanA={scanA}
                    scanB={scanB}
                    loading={deltaLoading}
                    singleScanMode={singleScanMode}
                />
            </div>

            {/* Section: Trend Chart */}
            <div
                style={{
                    backgroundColor: 'var(--bg-card)',
                    border: '1px solid var(--border-primary)',
                    borderRadius: 10,
                    padding: '20px',
                    marginBottom: 12,
                }}
            >
                <p
                    style={{
                        fontSize: 11,
                        fontWeight: 700,
                        color: 'var(--text-muted)',
                        letterSpacing: '0.08em',
                        textTransform: 'uppercase',
                        marginBottom: 14,
                    }}
                >
                    Threat Trend — {activeDays}d
                </p>
                <ThreatTrendChart
                    trendPoints={trendPoints}
                    loading={trendLoading}
                />
            </div>

            {/* Section: What Changed Tabs */}
            {!singleScanMode && (
                <div
                    style={{
                        backgroundColor: 'var(--bg-card)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 10,
                        padding: '20px',
                    }}
                >
                    <p
                        style={{
                            fontSize: 11,
                            fontWeight: 700,
                            color: 'var(--text-muted)',
                            letterSpacing: '0.08em',
                            textTransform: 'uppercase',
                            marginBottom: 14,
                        }}
                    >
                        What Changed
                    </p>
                    <WhatChangedTabs
                        newScenarios={deltaData.new_scenarios || []}
                        resolvedScenarios={deltaData.resolved_scenarios || []}
                        escalatedScenarios={deltaData.escalated_scenarios || []}
                        deescalatedScenarios={deltaData.deescalated_scenarios || []}
                        loading={deltaLoading}
                        scanBCompletedAt={scanB?.completed_at || ''}
                    />
                </div>
            )}
        </div>
    );
}
