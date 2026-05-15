'use client';

/**
 * ThreatCenterV1 — 3-pane Threat Center for pattern-based detection.
 *
 * Pane 1 (left):  FilterSidebarV1 — filter by tier, severity, class, status
 * Pane 2 (center): IncidentListV1 — paginated list of incidents
 * Pane 3 (right):  IncidentDetailPanelV1 — 9-section detail drawer (slide-in)
 */

import { useState, useCallback, useEffect } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import FilterSidebarV1 from './FilterSidebarV1';
import IncidentListV1 from './IncidentListV1';
import IncidentDetailPanelV1 from './IncidentDetailPanelV1';
import KpiBarV1 from './KpiBarV1';
import { fetchView } from '@/lib/api';

const SEVERITY_COLORS = {
    critical: 'var(--red-600, #dc2626)',
    high:     'var(--orange-500, #f97316)',
    medium:   'var(--yellow-500, #eab308)',
    low:      'var(--blue-500, #3b82f6)',
};

export default function ThreatCenterV1() {
    const searchParams = useSearchParams();
    const router = useRouter();

    const [filters, setFilters] = useState({
        severity:       searchParams.get('severity') || null,
        incident_class: searchParams.get('incident_class') || null,
        status:         searchParams.get('status') || 'open',
    });

    const [page, setPage] = useState(1);
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [selectedIncidentId, setSelectedIncidentId] = useState(null);

    const loadData = useCallback(async () => {
        setLoading(true);
        try {
            const params = new URLSearchParams({ page, page_size: 25 });
            if (filters.severity) params.set('severity', filters.severity);
            if (filters.incident_class) params.set('incident_class', filters.incident_class);
            if (filters.status) params.set('status', filters.status);

            const result = await fetchView(`threat_v1?${params.toString()}`);
            setData(result);
        } catch (err) {
            console.error('ThreatCenterV1 load error:', err);
        } finally {
            setLoading(false);
        }
    }, [filters, page]);

    useEffect(() => { loadData(); }, [loadData]);

    const handleFilterChange = (newFilters) => {
        setFilters(prev => ({ ...prev, ...newFilters }));
        setPage(1);
        setSelectedIncidentId(null);
    };

    const handleIncidentSelect = (incidentId) => {
        setSelectedIncidentId(incidentId === selectedIncidentId ? null : incidentId);
    };

    const incidents = data?.incidents?.items || [];
    const total = data?.incidents?.total || 0;
    const kpiGroups = data?.kpiGroups || [];
    const severityDist = data?.severity_distribution || {};
    const showDetail = !!selectedIncidentId;

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 102px)', overflow: 'hidden' }}>
            {/* KPI bar */}
            <KpiBarV1 kpiGroups={kpiGroups} severityDist={severityDist} loading={loading} />

            {/* 3-pane layout */}
            <div style={{ display: 'flex', flex: 1, gap: 12, padding: '12px 16px', overflow: 'hidden' }}>
                {/* Pane 1: Filter sidebar */}
                <FilterSidebarV1
                    filters={filters}
                    onChange={handleFilterChange}
                    severityDist={severityDist}
                />

                {/* Pane 2: Incident list */}
                <div style={{ flex: showDetail ? '0 0 45%' : 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                    <IncidentListV1
                        incidents={incidents}
                        total={total}
                        page={page}
                        pageSize={25}
                        loading={loading}
                        selectedId={selectedIncidentId}
                        onSelect={handleIncidentSelect}
                        onPageChange={setPage}
                        severityColors={SEVERITY_COLORS}
                    />
                </div>

                {/* Pane 3: Detail panel */}
                {showDetail && (
                    <IncidentDetailPanelV1
                        incidentId={selectedIncidentId}
                        onClose={() => setSelectedIncidentId(null)}
                        severityColors={SEVERITY_COLORS}
                    />
                )}
            </div>
        </div>
    );
}
