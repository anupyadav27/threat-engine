'use client';

const SEVERITY_OPTIONS = [
    { value: null,       label: 'All Severities', color: null },
    { value: 'critical', label: 'Critical',        color: 'var(--red-600, #dc2626)' },
    { value: 'high',     label: 'High',            color: 'var(--orange-500, #f97316)' },
    { value: 'medium',   label: 'Medium',          color: 'var(--yellow-500, #eab308)' },
    { value: 'low',      label: 'Low',             color: 'var(--blue-500, #3b82f6)' },
];

const INCIDENT_CLASS_OPTIONS = [
    { value: null,         label: 'All Classes' },
    { value: 'active',     label: '🔴 Active (CDR confirmed)' },
    { value: 'suspicious', label: '🟡 Suspicious' },
    { value: 'posture',    label: '🔵 Posture' },
];

const STATUS_OPTIONS = [
    { value: 'open',      label: 'Open' },
    { value: 'reopened',  label: 'Reopened' },
    { value: 'resolved',  label: 'Resolved' },
];

export default function FilterSidebarV1({ filters, onChange, severityDist }) {
    const chip = (active) => ({
        padding: '4px 10px',
        borderRadius: 6,
        border: `1px solid ${active ? 'var(--accent-blue, #3b82f6)' : 'var(--border-primary, #334155)'}`,
        backgroundColor: active ? 'rgba(59,130,246,0.15)' : 'transparent',
        color: active ? 'var(--accent-blue, #3b82f6)' : 'var(--text-secondary, #94a3b8)',
        cursor: 'pointer',
        fontSize: 12,
        whiteSpace: 'nowrap',
        transition: 'all 0.15s',
        display: 'block',
        width: '100%',
        textAlign: 'left',
        marginBottom: 4,
    });

    return (
        <div style={{
            width: 200,
            flexShrink: 0,
            backgroundColor: 'var(--bg-card, #0f172a)',
            border: '1px solid var(--border-primary, #1e293b)',
            borderRadius: 8,
            padding: 12,
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
            overflowY: 'auto',
        }}>
            {/* Status */}
            <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
                    Status
                </div>
                {STATUS_OPTIONS.map(opt => (
                    <button key={opt.value} style={chip(filters.status === opt.value)}
                        onClick={() => onChange({ status: opt.value })}>
                        {opt.label}
                    </button>
                ))}
            </div>

            {/* Incident class */}
            <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
                    Detection Class
                </div>
                {INCIDENT_CLASS_OPTIONS.map(opt => (
                    <button key={String(opt.value)} style={chip(filters.incident_class === opt.value)}
                        onClick={() => onChange({ incident_class: opt.value })}>
                        {opt.label}
                    </button>
                ))}
            </div>

            {/* Severity */}
            <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted, #64748b)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>
                    Severity
                </div>
                {SEVERITY_OPTIONS.map(opt => (
                    <button key={String(opt.value)} style={chip(filters.severity === opt.value)}
                        onClick={() => onChange({ severity: opt.value })}>
                        <span style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ color: opt.color || 'inherit' }}>{opt.label}</span>
                            {opt.value && (
                                <span style={{ fontSize: 11, color: 'var(--text-muted, #64748b)' }}>
                                    {severityDist[opt.value] || 0}
                                </span>
                            )}
                        </span>
                    </button>
                ))}
            </div>

        </div>
    );
}
