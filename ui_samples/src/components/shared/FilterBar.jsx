'use client';

import { X } from 'lucide-react';

/**
 * FilterBar — sticky filter strip with cascading single-select filters.
 * Active filters are shown as dismissible chip pills below the dropdowns.
 *
 * @param {Array}    filters       - [{ key, label, options: string[]|{value,label}[] }]
 * @param {Function} onFilterChange - (key, value) => void
 * @param {Object}   activeFilters  - { [key]: string }
 */
export default function FilterBar({ filters = [], onFilterChange, activeFilters = {} }) {
  const hasActiveFilters = Object.values(activeFilters).some((val) => val);

  const getFilterId = (filter) => filter.key || filter.name;

  const handleClearAll = () => {
    filters.forEach((filter) => {
      onFilterChange(getFilterId(filter), '');
    });
  };

  // Active filter entries (key + label + value)
  const activeEntries = filters
    .map((f) => {
      const id = getFilterId(f);
      const val = Array.isArray(activeFilters[id])
        ? activeFilters[id][0] || ''
        : activeFilters[id] || '';
      return val ? { id, label: f.label, value: val } : null;
    })
    .filter(Boolean);

  return (
    <div
      className="flex flex-col gap-2 p-4 rounded-lg border transition-colors duration-200"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      {/* Select dropdowns row */}
      <div className="flex flex-wrap items-center gap-3">
        {filters.map((filter) => {
          const filterId = getFilterId(filter);
          const currentValue = Array.isArray(activeFilters[filterId])
            ? (activeFilters[filterId][0] || '')
            : (activeFilters[filterId] || '');

          return (
            <div key={filterId}>
              <select
                value={currentValue}
                onChange={(e) => onFilterChange(filterId, e.target.value)}
                style={{
                  backgroundColor: currentValue ? 'var(--accent-primary)18' : 'var(--bg-tertiary)',
                  borderColor: currentValue ? 'var(--accent-primary)' : 'var(--border-primary)',
                  color: 'var(--text-primary)',
                }}
                className="border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent hover:opacity-75 transition-colors duration-200 cursor-pointer"
              >
                <option value="">{filter.label}</option>
                {(filter.options || []).map((option) => {
                  const val = typeof option === 'string' ? option : option.value;
                  const lbl = typeof option === 'string' ? option : (option.label || option.value);
                  return (
                    <option key={val} value={val}>
                      {lbl}
                    </option>
                  );
                })}
              </select>
            </div>
          );
        })}

        {hasActiveFilters && (
          <button
            onClick={handleClearAll}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border hover:opacity-75 transition-colors duration-200 text-sm font-medium ml-auto"
            style={{
              backgroundColor: 'var(--bg-tertiary)',
              borderColor: 'var(--border-primary)',
              color: 'var(--text-secondary)',
            }}
            title="Clear all filters"
          >
            <X className="w-4 h-4" />
            Clear all
          </button>
        )}
      </div>

      {/* Active filter chips row */}
      {activeEntries.length > 0 && (
        <div
          className="flex flex-wrap gap-2 pt-2 border-t"
          style={{ borderColor: 'var(--border-primary)' }}
        >
          {activeEntries.map(({ id, label, value }) => (
            <span
              key={id}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border"
              style={{
                backgroundColor: 'rgba(59,130,246,0.12)',
                borderColor: 'rgba(59,130,246,0.5)',
                color: '#60a5fa',
              }}
            >
              <span style={{ color: 'var(--text-muted)' }}>{label}:</span>
              <strong style={{ color: 'var(--text-primary)' }}>{value}</strong>
              <button
                onClick={() => onFilterChange(id, '')}
                className="ml-0.5 hover:opacity-75 transition-opacity flex-shrink-0"
                title={`Remove ${label} filter`}
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
