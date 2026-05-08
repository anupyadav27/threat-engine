'use client';

import { Search, X, Plus, Layers } from 'lucide-react';
import { useState } from 'react';

/**
 * Wiz-style horizontal filter bar.
 * Line 1: Search + filter dropdowns + [+Filter]
 * Line 2: Group by (separate row)
 * Line 3: Active chips
 */
export default function FilterBar({
  search = '',
  onSearchChange,
  searchPlaceholder = 'Search...',
  filters = [],
  onFilterChange,
  activeFilters = {},
  extraFilters = [],
  groupByOptions = [],
  groupBy = '',
  onGroupByChange,
}) {
  const [showMore, setShowMore] = useState(false);

  const hasActiveFilters = Object.values(activeFilters).some(v => v);
  const hasSearch = search.length > 0;
  const hasGroupBy = groupBy.length > 0;

  const handleClearAll = () => {
    filters.forEach(f => onFilterChange(f.key, ''));
    extraFilters.forEach(f => onFilterChange(f.key, ''));
    if (onSearchChange) onSearchChange('');
    if (onGroupByChange) onGroupByChange('');
  };

  const activeEntries = [...filters, ...extraFilters]
    .map(f => {
      const val = activeFilters[f.key] || '';
      return val ? { key: f.key, label: f.label, value: val } : null;
    })
    .filter(Boolean);

  const hiddenFilters = extraFilters.filter(ef => !filters.some(f => f.key === ef.key));

  return (
    <div className="space-y-2">
      {/* Line 1: Search + Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative" style={{ width: '180px' }}>
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-tertiary)' }} />
          <input
            type="text"
            value={search}
            onChange={e => onSearchChange?.(e.target.value)}
            placeholder={searchPlaceholder}
            className="w-full pl-7 pr-6 py-1.5 text-xs rounded border focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors"
            style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
          />
          {hasSearch && (
            <button onClick={() => onSearchChange?.('')} className="absolute right-1.5 top-1/2 -translate-y-1/2">
              <X className="w-3 h-3" style={{ color: 'var(--text-tertiary)' }} />
            </button>
          )}
        </div>

        {filters.map(filter => {
          const val = activeFilters[filter.key] || '';
          return (
            <select key={filter.key} value={val} onChange={e => onFilterChange(filter.key, e.target.value)}
              style={{
                backgroundColor: val ? 'rgba(59,130,246,0.08)' : 'var(--bg-tertiary)',
                borderColor: val ? 'rgba(59,130,246,0.4)' : 'var(--border-primary)',
                color: val ? 'var(--accent-primary)' : 'var(--text-secondary)',
              }}
              className="border rounded px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer transition-colors">
              <option value="">{filter.label}</option>
              {(filter.options || []).map(opt => {
                const v = typeof opt === 'string' ? opt : opt.value;
                const l = typeof opt === 'string' ? opt : (opt.label || opt.value);
                return <option key={v} value={v}>{l}</option>;
              })}
            </select>
          );
        })}

        {hiddenFilters.length > 0 && (
          <div className="relative">
            <button onClick={() => setShowMore(!showMore)}
              className="flex items-center gap-1 px-2 py-1.5 text-xs rounded border hover:opacity-75 transition-colors"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
              <Plus className="w-3 h-3" />Filter
            </button>
            {showMore && (
              <div className="absolute top-full mt-1 left-0 z-50 min-w-52 rounded-lg border shadow-lg py-1"
                style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                {hiddenFilters.map(f => (
                  <div key={f.key} className="px-3 py-1.5">
                    <label className="text-[10px] mb-0.5 block font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>{f.label}</label>
                    <select value={activeFilters[f.key] || ''} onChange={e => onFilterChange(f.key, e.target.value)}
                      className="w-full text-xs rounded border px-2 py-1"
                      style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}>
                      <option value="">All</option>
                      {(f.options || []).map(opt => {
                        const v = typeof opt === 'string' ? opt : opt.value;
                        const l = typeof opt === 'string' ? opt : (opt.label || opt.value);
                        return <option key={v} value={v}>{l}</option>;
                      })}
                    </select>
                  </div>
                ))}
                <div className="px-3 pt-1 pb-1 border-t" style={{ borderColor: 'var(--border-primary)' }}>
                  <button onClick={() => setShowMore(false)} className="text-xs font-medium" style={{ color: 'var(--accent-primary)' }}>Done</button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Line 2: Group by (separate row) */}
      {groupByOptions.length > 0 && (
        <div className="flex items-center gap-2">
          <Layers className="w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
          <span className="text-[10px] font-medium uppercase tracking-wide" style={{ color: 'var(--text-muted)' }}>Group by</span>
          {groupByOptions.map(opt => (
            <button key={opt.key} onClick={() => onGroupByChange?.(groupBy === opt.key ? '' : opt.key)}
              className="px-2.5 py-1 text-xs rounded border transition-colors"
              style={{
                backgroundColor: groupBy === opt.key ? 'rgba(139,92,246,0.12)' : 'var(--bg-tertiary)',
                borderColor: groupBy === opt.key ? 'rgba(139,92,246,0.5)' : 'var(--border-primary)',
                color: groupBy === opt.key ? '#a78bfa' : 'var(--text-secondary)',
                fontWeight: groupBy === opt.key ? 600 : 400,
              }}>
              {opt.label}
            </button>
          ))}
        </div>
      )}

      {/* Line 3: Active chips */}
      {(activeEntries.length > 0 || hasSearch) && (
        <div className="flex items-center gap-1.5 flex-wrap">
          {hasSearch && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border"
              style={{ backgroundColor: 'rgba(59,130,246,0.08)', borderColor: 'rgba(59,130,246,0.3)', color: '#60a5fa' }}>
              Search: <strong style={{ color: 'var(--text-primary)' }}>{search}</strong>
              <button onClick={() => onSearchChange?.('')} className="hover:opacity-75"><X className="w-2.5 h-2.5" /></button>
            </span>
          )}
          {activeEntries.map(({ key, label, value }) => (
            <span key={key} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border"
              style={{ backgroundColor: 'rgba(59,130,246,0.08)', borderColor: 'rgba(59,130,246,0.3)', color: '#60a5fa' }}>
              {label}: <strong style={{ color: 'var(--text-primary)' }}>{value}</strong>
              <button onClick={() => onFilterChange(key, '')} className="hover:opacity-75"><X className="w-2.5 h-2.5" /></button>
            </span>
          ))}
          <button onClick={handleClearAll} className="text-[10px] hover:opacity-75" style={{ color: 'var(--text-muted)' }}>Clear all</button>
        </div>
      )}
    </div>
  );
}
