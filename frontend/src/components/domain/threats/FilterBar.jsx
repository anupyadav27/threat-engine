'use client';

/**
 * FilterBar — severity multi-select buttons, status/sort dropdowns, and search input.
 *
 * Severity toggles are multi-select pills. Deselecting all severities = show all.
 * Filtering logic lives in CommandRoom; FilterBar only surfaces the UI controls.
 *
 * @param {Object}   props
 * @param {Object}   props.filters          - { sev, status, sort, search }
 * @param {Function} props.onFilterChange   - Called with partial filter object to merge
 */

const SEV_LABELS = ['CRIT', 'HIGH', 'MED', 'LOW'];

const SEV_COLORS = {
    CRIT: '#DC2626',
    HIGH: '#EA580C',
    MED:  '#D97706',
    LOW:  '#64748B',
};

const selectStyle = {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-primary)',
    borderRadius: 6,
    color: 'var(--text-secondary)',
    fontSize: 12,
    padding: '5px 10px',
    cursor: 'pointer',
    outline: 'none',
};

const inputStyle = {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-primary)',
    borderRadius: 6,
    color: 'var(--text-primary)',
    fontSize: 12,
    padding: '5px 10px',
    outline: 'none',
};

function SevButton({ label, active, onClick }) {
    const color = SEV_COLORS[label] || '#64748B';
    return (
        <button
            onClick={onClick}
            style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 4,
                backgroundColor: active ? `${color}20` : 'transparent',
                border: `1px solid ${active ? color : 'var(--border-primary)'}`,
                borderRadius: 9999,
                color: active ? color : 'var(--text-muted)',
                fontSize: 11,
                fontWeight: 700,
                padding: '4px 10px',
                cursor: 'pointer',
                transition: 'all 150ms ease',
            }}
        >
            <span
                style={{
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    backgroundColor: active ? color : 'var(--text-muted)',
                    flexShrink: 0,
                }}
            />
            {label}
        </button>
    );
}

function Separator() {
    return (
        <div
            style={{
                width: 1,
                height: 20,
                backgroundColor: 'var(--border-primary)',
                flexShrink: 0,
                marginLeft: 4,
                marginRight: 4,
            }}
        />
    );
}

export function FilterBar({ filters = {}, onFilterChange }) {
    const activeSevs = filters.sev
        ? filters.sev.split(',').filter(Boolean)
        : [];

    function toggleSev(s) {
        const next = activeSevs.includes(s)
            ? activeSevs.filter((x) => x !== s)
            : [...activeSevs, s];
        // Deselecting all = show all (empty string = no filter)
        onFilterChange && onFilterChange({ sev: next.length ? next.join(',') : '' });
    }

    return (
        <div
            style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                flexWrap: 'wrap',
                backgroundColor: 'var(--bg-card)',
                border: '1px solid var(--border-primary)',
                borderRadius: 8,
                padding: '8px 12px',
            }}
        >
            {/* Severity toggles */}
            {SEV_LABELS.map((s) => (
                <SevButton
                    key={s}
                    label={s}
                    active={activeSevs.includes(s)}
                    onClick={() => toggleSev(s)}
                />
            ))}

            <Separator />

            {/* Status */}
            <select
                value={filters.status || 'open'}
                onChange={(e) => onFilterChange && onFilterChange({ status: e.target.value })}
                style={selectStyle}
            >
                <option value="open">Open</option>
                <option value="suppressed">Suppressed</option>
                <option value="all">All</option>
            </select>

            {/* Sort */}
            <select
                value={filters.sort || 'risk_score'}
                onChange={(e) => onFilterChange && onFilterChange({ sort: e.target.value })}
                style={selectStyle}
            >
                <option value="risk_score">Sort: Risk Score</option>
                <option value="newest">Newest First</option>
                <option value="severity">Severity</option>
                <option value="resource_name">Resource Name A to Z</option>
            </select>

            {/* Search */}
            <input
                type="text"
                placeholder="Search scenarios..."
                value={filters.search || ''}
                onChange={(e) => onFilterChange && onFilterChange({ search: e.target.value })}
                style={{ flex: 1, minWidth: 160, ...inputStyle }}
            />
        </div>
    );
}
