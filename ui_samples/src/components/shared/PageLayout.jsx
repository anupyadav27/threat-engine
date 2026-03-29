'use client';

import { useState, useMemo, useEffect } from 'react';
import { ChevronDown, ChevronRight, Info, AlertCircle } from 'lucide-react';
import DataTable from './DataTable';
import SeverityBadge from './SeverityBadge';
import FilterBar from './FilterBar';

/**
 * Standardized page layout for all CSPM pages.
 *
 * Props:
 *   icon           - Lucide icon component for page heading
 *   pageContext     - { title, brief, details, tabs }
 *   kpiGroups       - [{ title, items: [{ label, value, suffix }] }]
 *   insightRow      - ReactNode (optional) — Slot 3: charts between KPIs and tabs
 *   tabData         - { [tabId]: { data, columns, filters, extraFilters, groupByOptions, renderTab } }
 *                     If renderTab is provided, it is called instead of FilterBar+DataTable.
 *   loading         - boolean
 *   error           - string | null
 *   defaultTab      - string (default tab id)
 *   onRowClick      - function (optional) — callback when a table row is clicked
 */
export default function PageLayout({
  icon: Icon,
  pageContext = {},
  kpiGroups = [],
  insightRow = null,
  tabData = {},
  loading = false,
  error = null,
  defaultTab = '',
  onRowClick = null,
}) {
  const tabs = pageContext.tabs || [];
  const firstTab = defaultTab || tabs[0]?.id || '';

  const [activeTab, setActiveTab] = useState(firstTab);
  const [search, setSearch] = useState('');
  const [activeFilters, setActiveFilters] = useState({});
  const [groupBy, setGroupBy] = useState('');
  const [expandedGroups, setExpandedGroups] = useState({});
  const [detailsExpanded, setDetailsExpanded] = useState(false);

  // Reset on tab change
  const handleTabChange = (id) => {
    setActiveTab(id);
    setSearch('');
    setActiveFilters({});
    setGroupBy('');
  };

  const currentTab = tabData[activeTab] || {};
  const rawData = currentTab.data || [];
  const columns = currentTab.columns || [];
  const filters = currentTab.filters || [];
  const extraFilters = currentTab.extraFilters || [];
  const groupByOptions = currentTab.groupByOptions || [];

  // Apply search + filters
  const filtered = useMemo(() => {
    let result = rawData;
    if (search) {
      const q = search.toLowerCase();
      result = result.filter(row =>
        Object.values(row).some(v => v && String(v).toLowerCase().includes(q))
      );
    }
    Object.entries(activeFilters).forEach(([key, value]) => {
      if (!value) return;
      // Special handling for numeric range filters (risk_score, etc.)
      if (key.endsWith('_range')) {
        const realKey = key.replace('_range', '');
        const threshold = parseInt(value, 10);
        if (threshold === 0) result = result.filter(row => (row[realKey] || 0) < 25);
        else result = result.filter(row => (row[realKey] || 0) >= threshold);
        return;
      }
      result = result.filter(row => {
        const rowVal = row[key];
        if (rowVal === undefined || rowVal === null) return false;
        return String(rowVal).toLowerCase() === value.toLowerCase();
      });
    });
    return result;
  }, [rawData, search, activeFilters]);

  // Group
  const grouped = useMemo(() => {
    if (!groupBy || !filtered.length) return null;
    const groups = {};
    filtered.forEach(row => {
      const key = String(row[groupBy] ?? 'Other');
      if (!groups[key]) groups[key] = [];
      groups[key].push(row);
    });
    return Object.entries(groups)
      .sort(([, a], [, b]) => b.length - a.length)
      .map(([key, items]) => ({ key, items, count: items.length }));
  }, [filtered, groupBy]);

  useEffect(() => {
    if (grouped) {
      const exp = {};
      grouped.forEach(g => { exp[g.key] = true; });
      setExpandedGroups(exp);
    }
  }, [groupBy]);

  const toggleGroup = (key) => setExpandedGroups(prev => ({ ...prev, [key]: !prev[key] }));

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2" style={{ borderColor: 'var(--accent-primary)' }} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }}>
        <div className="flex items-center gap-2 text-red-400">
          <AlertCircle className="w-5 h-5" /><span>{error}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* ── Heading ── */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          {Icon && <Icon className="w-6 h-6" style={{ color: 'var(--accent-primary)' }} />}
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>{pageContext.title || ''}</h1>
        </div>
        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{pageContext.brief || ''}</p>
        {pageContext.details?.length > 0 && (
          <>
            <button onClick={() => setDetailsExpanded(!detailsExpanded)}
              className="flex items-center gap-1 text-xs mt-1 hover:underline" style={{ color: 'var(--accent-primary)' }}>
              <Info className="w-3.5 h-3.5" />
              {detailsExpanded ? 'Hide' : 'Best practices'}
              <ChevronDown className={`w-3.5 h-3.5 transition-transform ${detailsExpanded ? 'rotate-180' : ''}`} />
            </button>
            {detailsExpanded && (
              <ul className="mt-2 ml-4 space-y-1 text-xs list-disc" style={{ color: 'var(--text-tertiary)' }}>
                {pageContext.details.map((d, i) => <li key={i}>{d}</li>)}
              </ul>
            )}
          </>
        )}
      </div>

      {/* ── KPI Groups ── */}
      {kpiGroups.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {kpiGroups.map((group, gi) => {
            const accent = gi === 0 ? 'rgba(239,68,68,0.06)' : 'rgba(59,130,246,0.06)';
            const border = gi === 0 ? 'rgba(239,68,68,0.15)' : 'rgba(59,130,246,0.15)';
            const titleColor = gi === 0 ? '#f87171' : '#60a5fa';
            return (
              <div key={gi} className="rounded-lg p-4" style={{ backgroundColor: accent, border: `1px solid ${border}` }}>
                <h3 className="text-xs font-bold uppercase tracking-wider mb-3" style={{ color: titleColor }}>{group.title}</h3>
                <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
                  {(group.items || []).map((item, ii) => (
                    <div key={ii}>
                      <div className="text-[10px] uppercase tracking-wide mb-0.5" style={{ color: 'var(--text-muted)' }}>{item.label}</div>
                      <div className="text-xl font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>
                        {typeof item.value === 'number' ? item.value.toLocaleString() : item.value}
                        {item.suffix && <span className="text-xs font-normal ml-0.5" style={{ color: 'var(--text-tertiary)' }}>{item.suffix}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Slot 3: Insight Row (optional charts) ── */}
      {insightRow}

      {/* ── Tabs ── */}
      {tabs.length > 0 && (
        <div className="flex gap-1 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          {tabs.map(tab => (
            <button key={tab.id} onClick={() => handleTabChange(tab.id)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${activeTab === tab.id ? 'border-current' : 'border-transparent hover:border-gray-600'}`}
              style={{ color: activeTab === tab.id ? 'var(--accent-primary)' : 'var(--text-tertiary)' }}>
              {tab.label}
              {tab.count > 0 && (
                <span className="ml-1.5 text-xs px-1.5 py-0.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{tab.count}</span>
              )}
            </button>
          ))}
        </div>
      )}

      {/* ── Custom renderTab or standard FilterBar+DataTable ── */}
      {currentTab.renderTab ? (
        currentTab.renderTab()
      ) : (
        <>
          {/* ── Filter Bar ── */}
          <FilterBar
            search={search}
            onSearchChange={setSearch}
            searchPlaceholder="Search..."
            filters={filters}
            onFilterChange={(k, v) => setActiveFilters(prev => ({ ...prev, [k]: v }))}
            activeFilters={activeFilters}
            extraFilters={extraFilters}
            groupByOptions={groupByOptions}
            groupBy={groupBy}
            onGroupByChange={setGroupBy}
          />

          {/* ── Table / Grouped ── */}
          {grouped ? (
            <div className="space-y-3">
              {grouped.map(({ key, items, count }) => (
                <div key={key} className="rounded-lg border" style={{ borderColor: 'var(--border-primary)' }}>
                  <button onClick={() => toggleGroup(key)}
                    className="w-full flex items-center gap-2 px-4 py-2.5 text-sm font-medium"
                    style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-primary)' }}>
                    {expandedGroups[key] ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    <span>{key}</span>
                    <span className="text-xs px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}>{count}</span>
                  </button>
                  {expandedGroups[key] && <DataTable data={items} columns={columns} pageSize={25} hideToolbar onRowClick={onRowClick} />}
                </div>
              ))}
              <div className="text-xs" style={{ color: 'var(--text-tertiary)' }}>{grouped.length} groups, {filtered.length} total</div>
            </div>
          ) : (
            <DataTable data={filtered} columns={columns} pageSize={25} hideToolbar onRowClick={onRowClick} />
          )}
        </>
      )}
    </div>
  );
}
