'use client';

const CLASS_BADGE = {
    active:     { label: '● Active',     bg: 'rgba(220,38,38,0.15)',  color: '#dc2626' },
    suspicious: { label: '◐ Suspicious', bg: 'rgba(234,179,8,0.15)',  color: '#ca8a04' },
    posture:    { label: '○ Posture',    bg: 'rgba(59,130,246,0.15)', color: '#3b82f6' },
};

const TIER_LABEL = { 1: 'T1', 2: 'T2', 3: 'T3' };

function IncidentRow({ incident, selected, onSelect, severityColors }) {
    const classBadge = CLASS_BADGE[incident.incident_class] || CLASS_BADGE.posture;
    const sevColor = severityColors[incident.severity] || severityColors.low;
    const isSelected = selected === incident.dedup_key;

    return (
        <div
            onClick={() => onSelect(incident.dedup_key)}
            style={{
                padding: '10px 14px',
                borderRadius: 8,
                border: `1px solid ${isSelected ? 'var(--accent-blue, #3b82f6)' : 'var(--border-primary, #1e293b)'}`,
                backgroundColor: isSelected ? 'rgba(59,130,246,0.08)' : 'var(--bg-card, #0f172a)',
                cursor: 'pointer',
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
                transition: 'border-color 0.15s, background-color 0.15s',
            }}
        >
            {/* Row 1: pattern ID + tier + class + severity */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span style={{
                    fontSize: 11,
                    fontFamily: 'monospace',
                    color: 'var(--text-secondary, #94a3b8)',
                    backgroundColor: 'var(--bg-surface, #1e293b)',
                    padding: '1px 6px',
                    borderRadius: 4,
                }}>
                    {TIER_LABEL[incident.tier] || 'T?'} {incident.primary_pattern_id}
                </span>

                <span style={{
                    fontSize: 11,
                    padding: '1px 7px',
                    borderRadius: 4,
                    backgroundColor: classBadge.bg,
                    color: classBadge.color,
                    fontWeight: 600,
                }}>
                    {classBadge.label}
                </span>

                <span style={{
                    fontSize: 11,
                    padding: '1px 7px',
                    borderRadius: 4,
                    backgroundColor: `${sevColor}22`,
                    color: sevColor,
                    fontWeight: 600,
                    textTransform: 'uppercase',
                    marginLeft: 'auto',
                }}>
                    {incident.severity}
                </span>
            </div>

            {/* Row 2: story text */}
            {incident.story_text && (
                <div style={{
                    fontSize: 12,
                    color: 'var(--text-secondary, #94a3b8)',
                    overflow: 'hidden',
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                }}>
                    {incident.story_text}
                </div>
            )}

            {/* Row 3: resource + region + account + last seen */}
            <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-muted, #64748b)', flexWrap: 'wrap' }}>
                <span>{incident.entry_resource_uid?.slice(0, 40) || '—'}</span>
                <span>·</span>
                <span>{incident.region || '—'}</span>
                <span>·</span>
                <span>{incident.account_id?.slice(0, 12) || '—'}</span>
                {incident.last_seen_at && (
                    <>
                        <span style={{ marginLeft: 'auto' }}>
                            Last: {new Date(incident.last_seen_at).toLocaleDateString()}
                        </span>
                    </>
                )}
            </div>
        </div>
    );
}

export default function IncidentListV1({
    incidents, total, page, pageSize, loading,
    selectedId, onSelect, onPageChange, severityColors,
}) {
    const totalPages = Math.ceil(total / pageSize);

    return (
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            {/* Header */}
            <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 10,
            }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary, #f1f5f9)' }}>
                    Incidents
                    <span style={{ fontSize: 12, fontWeight: 400, color: 'var(--text-muted, #64748b)', marginLeft: 8 }}>
                        {total} total
                    </span>
                </div>
                {/* Pagination */}
                {totalPages > 1 && (
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <button
                            disabled={page <= 1}
                            onClick={() => onPageChange(page - 1)}
                            style={{
                                padding: '3px 8px', fontSize: 12, borderRadius: 4,
                                border: '1px solid var(--border-primary)',
                                backgroundColor: 'transparent',
                                color: 'var(--text-secondary)',
                                cursor: page <= 1 ? 'not-allowed' : 'pointer',
                                opacity: page <= 1 ? 0.4 : 1,
                            }}
                        >←</button>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {page} / {totalPages}
                        </span>
                        <button
                            disabled={page >= totalPages}
                            onClick={() => onPageChange(page + 1)}
                            style={{
                                padding: '3px 8px', fontSize: 12, borderRadius: 4,
                                border: '1px solid var(--border-primary)',
                                backgroundColor: 'transparent',
                                color: 'var(--text-secondary)',
                                cursor: page >= totalPages ? 'not-allowed' : 'pointer',
                                opacity: page >= totalPages ? 0.4 : 1,
                            }}
                        >→</button>
                    </div>
                )}
            </div>

            {/* List */}
            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
                {loading ? (
                    [1, 2, 3, 4, 5].map(i => (
                        <div key={i} style={{
                            height: 80,
                            borderRadius: 8,
                            backgroundColor: 'var(--bg-card)',
                            border: '1px solid var(--border-primary)',
                            animation: 'pulse 1.5s ease-in-out infinite',
                        }} />
                    ))
                ) : incidents.length === 0 ? (
                    <div style={{
                        textAlign: 'center',
                        color: 'var(--text-muted)',
                        fontSize: 13,
                        paddingTop: 48,
                    }}>
                        No incidents match the current filters.
                    </div>
                ) : (
                    incidents.map(inc => (
                        <IncidentRow
                            key={inc.incident_id || inc.dedup_key}
                            incident={inc}
                            selected={selectedId}
                            onSelect={onSelect}
                            severityColors={severityColors}
                        />
                    ))
                )}
            </div>
        </div>
    );
}
