'use client';

function KpiTile({ label, value, severity, loading }) {
    const severityColor = {
        critical: 'var(--red-600, #dc2626)',
        high:     'var(--orange-500, #f97316)',
        medium:   'var(--yellow-500, #eab308)',
    }[severity] || 'var(--text-primary, #f1f5f9)';

    return (
        <div style={{
            backgroundColor: 'var(--bg-card, #0f172a)',
            border: '1px solid var(--border-primary, #1e293b)',
            borderRadius: 8,
            padding: '10px 16px',
            display: 'flex',
            flexDirection: 'column',
            minWidth: 120,
            flex: 1,
        }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted, #64748b)', marginBottom: 4 }}>{label}</div>
            {loading ? (
                <div style={{ height: 24, backgroundColor: 'var(--border-primary)', borderRadius: 4, animation: 'pulse 1.5s infinite' }} />
            ) : (
                <div style={{ fontSize: 22, fontWeight: 700, color: severityColor }}>{value ?? '—'}</div>
            )}
        </div>
    );
}

export default function KpiBarV1({ kpiGroups, severityDist, loading }) {
    const group = kpiGroups?.[0];
    const kpis = group?.kpis || [];

    return (
        <div style={{
            display: 'flex',
            gap: 8,
            padding: '12px 16px 0',
            flexWrap: 'wrap',
        }}>
            {kpis.length > 0 ? kpis.map(kpi => (
                <KpiTile
                    key={kpi.id}
                    label={kpi.label}
                    value={kpi.value}
                    severity={kpi.severity}
                    loading={loading}
                />
            )) : [1, 2, 3, 4, 5].map(i => (
                <KpiTile key={i} label="" value={null} loading={true} />
            ))}
        </div>
    );
}
