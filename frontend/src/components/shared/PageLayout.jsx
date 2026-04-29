'use client';

import { useState, useMemo } from 'react';
import { ChevronDown, Info, AlertCircle } from 'lucide-react';
import DataTable from './DataTable';
import FilterBar from './FilterBar';

/**
 * Standardized page layout for all CSPM pages.
 *
 * Props:
 *   icon           - Lucide icon component for page heading
 *   pageContext     - { title, brief, details, tabs }
 *   kpiGroups       - [{ title, items: [{ label, value, suffix }] }]
 *   insightRow      - ReactNode (optional) — Slot 3: charts between KPIs and tabs
 *   tabData         - { [tabId]: { data, columns, filters, extraFilters, groupByOptions, renderTab, headerExtra } }
 *                     If renderTab is provided, it is called instead of FilterBar+DataTable.
 *                     headerExtra: ReactNode rendered above FilterBar (e.g. a filter/notice badge).
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
  hideHeader = false,
  topNav = false,
}) {
  const tabs = pageContext.tabs || [];
  const firstTab = defaultTab || tabs[0]?.id || '';

  const [activeTab, setActiveTab] = useState(firstTab);
  const [detailsExpanded, setDetailsExpanded] = useState(false);
  const [search, setSearch] = useState('');
  const [activeFilters, setActiveFilters] = useState({});

  const handleTabChange = (id) => {
    setActiveTab(id);
    setSearch('');
    setActiveFilters({});
  };

  const handleFilterChange = (key, value) => {
    setActiveFilters(prev => ({ ...prev, [key]: value }));
  };

  const currentTab = tabData[activeTab] || {};
  const rawData = currentTab.data || [];
  const columns = currentTab.columns || [];

  const hasFilters = !!(currentTab.filters);

  const filteredData = useMemo(() => {
    if (!hasFilters) return rawData;

    const searchFields = ['title', 'rule_id', 'resource_uid', 'resource_type', 'service', 'description'];
    const lowerSearch = search.toLowerCase();

    return rawData.filter(row => {
      // Search
      if (search) {
        const matchesSearch = searchFields.some(field => {
          const val = row[field];
          return val && String(val).toLowerCase().includes(lowerSearch);
        });
        if (!matchesSearch) return false;
      }

      // Active filters
      for (const [key, value] of Object.entries(activeFilters)) {
        if (!value) continue;
        const rowVal = row[key];
        if (rowVal == null) return false;
        if (!String(rowVal).toLowerCase().includes(String(value).toLowerCase())) return false;
      }

      return true;
    });
  }, [rawData, search, activeFilters, hasFilters]);

  const displayData = hasFilters ? filteredData : rawData;
  const isFiltering = hasFilters && (search || Object.values(activeFilters).some(v => v));

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

  // Shared tab bar markup
  const tabBar = tabs.length > 0 && (
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
  );

  // KPI groups + insight row — only shown on the overview (first) tab when topNav is active
  const overviewContent = (
    <>
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
      {/* ── Insight Row (optional charts) ── */}
      {insightRow}
    </>
  );

  return (
    <div className="space-y-5">
      {/* ── Heading ── */}
      {!hideHeader && <div>
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
      </div>}

      {topNav ? (
        <>
          {/* topNav=true: Tab bar sits right below header */}
          {tabBar}
          {/* KPIs + charts only visible on the first/overview tab */}
          {activeTab === firstTab && overviewContent}
        </>
      ) : (
        <>
          {/* Default order: KPIs → charts → tab bar */}
          {overviewContent}
          {tabBar}
        </>
      )}

      {/* ── Custom renderTab or standard DataTable ── */}
      {currentTab.renderTab ? (
        currentTab.renderTab()
      ) : (
        <>
          {currentTab.headerExtra && currentTab.headerExtra}
          {hasFilters && (
            <FilterBar
              search={search}
              onSearchChange={setSearch}
              searchPlaceholder={currentTab.searchPlaceholder || 'Search findings...'}
              filters={currentTab.filters || []}
              extraFilters={currentTab.extraFilters || []}
              activeFilters={activeFilters}
              onFilterChange={handleFilterChange}
            />
          )}
          {isFiltering && (
            <div className="text-xs text-right" style={{ color: 'var(--text-muted)' }}>
              Showing {displayData.length.toLocaleString()} of {rawData.length.toLocaleString()}
            </div>
          )}
          <DataTable data={displayData} columns={columns} pageSize={25} onRowClick={onRowClick} />
        </>
      )}
    </div>
  );
}
