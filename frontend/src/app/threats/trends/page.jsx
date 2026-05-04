'use client';

/**
 * /threats/trends — Trends & Posture Delta page (THREAT-UI-03)
 *
 * Answers "Is my threat posture getting better or worse?" by comparing
 * two scan runs side-by-side and showing a 90-day trend chart.
 *
 * Two independent BFF fetches:
 *   - threat-posture-delta: scan comparison, KPI deltas, what-changed tabs
 *   - threat-trend:         time-series data for the trend chart
 *
 * Both load independently — the chart renders as soon as trend data arrives
 * even if the delta comparison is still loading.
 *
 * RBAC: threats:read permission required (viewer role can access).
 * Auth: forwarded via X-Auth-Context header — no DEV_BYPASS_AUTH.
 */

import { useState } from 'react';
import useViewFetch from '@/lib/use-view-fetch';
import PostureDelta from '@/components/domain/threats/PostureDelta';

export default function ThreatsTrendsPage() {
    const [scanParams, setScanParams] = useState({});
    const [trendDays, setTrendDays] = useState(90);

    const { data: deltaData, loading: deltaLoading } = useViewFetch(
        'threat-posture-delta',
        scanParams,
    );
    const { data: trendData, loading: trendLoading } = useViewFetch(
        'threat-trend',
        { days: trendDays },
    );

    return (
        <PostureDelta
            deltaData={deltaData}
            trendData={trendData}
            deltaLoading={deltaLoading}
            trendLoading={trendLoading}
            onScanChange={(a, b) => setScanParams({ scan_a: a, scan_b: b })}
            onDaysChange={setTrendDays}
            activeDays={trendDays}
        />
    );
}
