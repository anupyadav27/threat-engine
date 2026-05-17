'use client';

/**
 * /threats-v1 — Threat Center v1 (3-tier pattern-based detection)
 *
 * 3-pane layout:
 *   Left:   FilterSidebar (tier, severity, incident_class, status)
 *   Center: IncidentList (paginated, sortable)
 *   Right:  IncidentDetailPanel (9-section drawer — shown when incident selected)
 *
 * Data source: BFF GET /api/v1/views/threat_v1
 * Direct engine: GET /api/v1/incidents/{id} (detail with CDR evidence)
 * RBAC: threat:read required. CDR evidence fields need cdr:sensitive.
 */

import { Suspense } from 'react';
import ThreatCenterV1 from '@/components/domain/threats-v1/ThreatCenterV1';
import ThreatSubNav from '@/components/domain/threats/ThreatSubNav';

function ThreatCenterSkeleton() {
    return (
        <div style={{ display: 'flex', gap: 12, padding: '12px 0', height: 'calc(100vh - 80px)' }}>
            {/* Filter sidebar skeleton */}
            <div style={{
                width: 220,
                backgroundColor: 'var(--bg-card)',
                border: '1px solid var(--border-primary)',
                borderRadius: 8,
                animation: 'pulse 1.5s ease-in-out infinite',
                flexShrink: 0,
            }} />
            {/* Incident list skeleton */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {[1, 2, 3, 4, 5, 6, 7].map((i) => (
                    <div key={i} style={{
                        height: 80,
                        backgroundColor: 'var(--bg-card)',
                        border: '1px solid var(--border-primary)',
                        borderRadius: 8,
                        animation: 'pulse 1.5s ease-in-out infinite',
                    }} />
                ))}
            </div>
        </div>
    );
}

export default function ThreatsV1Page() {
    return (
        <>
            <ThreatSubNav />
            <Suspense fallback={<ThreatCenterSkeleton />}>
                <ThreatCenterV1 />
            </Suspense>
        </>
    );
}
