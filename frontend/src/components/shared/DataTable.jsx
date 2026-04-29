'use client';

import React, { useState, useMemo, useCallback, useEffect } from 'react';
import {
  useReactTable,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  flexRender,
} from '@tanstack/react-table';
import { ChevronUp, ChevronDown, ChevronRight, ArrowUp, ArrowDown, ChevronsLeft, ChevronsRight, Search, Download, FileSpreadsheet, Columns, AlignJustify, AlignLeft, AlignCenter, X, Eye, Copy, BellOff, Filter, Layers } from 'lucide-react';
import LoadingSkeleton from './LoadingSkeleton';

/**
 * Reusable TanStack Table wrapper component for CSPM dashboard with enterprise features.
 *
 * @component
 * @param {Object} props - Component props
 * @param {Array} props.data - Array of data objects to display
 * @param {Array} props.columns - TanStack column definitions
 * @param {number} [props.pageSize=10] - Number of rows per page (client mode)
 * @param {Function} [props.onRowClick] - Callback fired when a row is clicked
 * @param {boolean} [props.loading=false] - Show loading skeleton state
 * @param {string} [props.emptyMessage='No data available'] - Message when no rows exist
 * @param {boolean} [props.serverPagination=false] - Enable server-side pagination mode
 * @param {number} [props.totalRows] - Total rows on server (server mode)
 * @param {number} [props.currentPage] - Current page index (server mode)
 * @param {Function} [props.onPageChange] - Callback for page change (server mode)
 * @param {Function} [props.onPageSizeChange] - Callback for page size change (server mode)
 * @param {Function} [props.onSearchChange] - Callback for search text change (server mode)
 * @param {Function} [props.onSortChange] - Callback for sort change (server mode)
 * @param {Function} [props.onExportPdf] - Callback for PDF export
 * @param {Function} [props.onExportExcel] - Callback for Excel export
 * @param {boolean} [props.showExport=false] - Show export buttons
 * @returns {JSX.Element}
 */
export default function DataTable({
  data = [],
  columns = [],
  pageSize = 10,
  onRowClick,
  loading = false,
  emptyMessage = 'No data available',
  serverPagination = false,
  totalRows,
  currentPage = 0,
  onPageChange,
  onPageSizeChange,
  onSearchChange,
  onSortChange,
  onExportPdf,
  onExportExcel,
  showExport = false,
  renderExpandedRow,
  hideToolbar = false,
  defaultDensity = 'comfortable',
}) {
  const [searchText, setSearchText] = useState('');
  const [columnSearches, setColumnSearches] = useState({});
  const [sorting, setSorting] = useState([]);
  const [currentPageSize, setCurrentPageSize] = useState(pageSize);
  const [goToPageInput, setGoToPageInput] = useState('');
  const [exportProgress, setExportProgress] = useState(null);
  // Column visibility & density
  const [columnVisibility, setColumnVisibility] = useState({});
  const [density, setDensity] = useState(defaultDensity); // 'compact' | 'comfortable' | 'spacious'
  const [showColPicker, setShowColPicker] = useState(false);
  const [selectedRows, setSelectedRows] = useState(new Set());
  const [hoveredRow, setHoveredRow] = useState(null);
  const [columnFilters, setColumnFilters] = useState({}); // { colId: Set<string> }
  const [openFilterCol, setOpenFilterCol] = useState(null);
  const [filterBtnPos, setFilterBtnPos] = useState(null); // { top, left } for fixed popover
  const [filterSearch, setFilterSearch] = useState({});
  const [groupBy, setGroupBy] = useState('');
  const [collapsedGroups, setCollapsedGroups] = useState(new Set()); // tracks collapsed groups; default = all expanded
  const [showGroupPicker, setShowGroupPicker] = useState(false);

  // Severity left-border stripe color
  const SEV_STRIPE = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6' };
  const getRowSevColor = (rowData) => {
    const sev = (rowData?.severity || rowData?.risk_rating || rowData?.risk_level || '').toLowerCase();
    return SEV_STRIPE[sev] || null;
  };

  const toggleSelect = (rowId) => {
    setSelectedRows(prev => {
      const next = new Set(prev);
      if (next.has(rowId)) next.delete(rowId); else next.add(rowId);
      return next;
    });
  };

  const toggleSelectAll = () => {
    const allIds = table.getRowModel().rows.map(r => r.id);
    setSelectedRows(prev => prev.size === allIds.length ? new Set() : new Set(allIds));
  };

  // Compute distinct values per column from unfiltered source data
  const columnDistinctValues = useMemo(() => {
    const vals = {};
    columns.forEach(col => {
      const key = col.accessorKey || col.id;
      if (!key) return;
      const unique = [...new Set(data.map(r => r[key]).filter(v => v !== null && v !== undefined && v !== ''))].sort((a, b) => String(a).localeCompare(String(b)));
      if (unique.length > 0 && unique.length <= 200) vals[key] = unique;
    });
    return vals;
  }, [data, columns]);

  // Options for Group By picker — columns with string accessorKey + string header
  const groupByOptions = useMemo(() =>
    columns
      .filter(col => col.accessorKey && typeof col.header === 'string')
      .map(col => ({ key: col.accessorKey, label: col.header })),
    [columns]
  );

  const toggleColumnFilterValue = (colId, val) => {
    setColumnFilters(prev => {
      const cur = new Set(prev[colId] || []);
      if (cur.has(val)) cur.delete(val); else cur.add(val);
      return { ...prev, [colId]: cur };
    });
  };

  const clearColumnFilter = (colId) => setColumnFilters(prev => ({ ...prev, [colId]: new Set() }));

  const activeFilterCount = Object.values(columnFilters).filter(s => s && s.size > 0).length;

  // Close filter popover on outside click
  useEffect(() => {
    if (!openFilterCol) return;
    const handler = () => { setOpenFilterCol(null); setFilterBtnPos(null); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [openFilterCol]);

  // Close group picker on outside click
  useEffect(() => {
    if (!showGroupPicker) return;
    const handler = () => setShowGroupPicker(false);
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showGroupPicker]);

  const densityPadding = { compact: 'px-4 py-1.5 text-xs', comfortable: 'px-6 py-4 text-sm', spacious: 'px-6 py-6 text-sm' };
  const densityHeaderPadding = { compact: 'px-4 py-2.5', comfortable: 'px-6 py-4', spacious: 'px-6 py-5' };

  // Debounce timer for column search
  const debounceTimers = useMemo(() => ({}), []);

  // Handle search text change with server/client modes
  const handleSearchChange = useCallback((text) => {
    setSearchText(text);
    if (serverPagination) {
      onSearchChange?.(text);
    }
  }, [serverPagination, onSearchChange]);

  // Handle column-specific search with debounce
  const handleColumnSearch = useCallback((columnId, searchValue) => {
    setColumnSearches((prev) => ({
      ...prev,
      [columnId]: searchValue,
    }));

    if (serverPagination && onSearchChange) {
      clearTimeout(debounceTimers[columnId]);
      debounceTimers[columnId] = setTimeout(() => {
        onSearchChange({ [columnId]: searchValue });
      }, 300);
    }
  }, [serverPagination, onSearchChange, debounceTimers]);

  // Filter data based on search text and column searches (client mode only)
  const filteredData = useMemo(() => {
    if (serverPagination) return data;

    let result = data;

    // Apply global search
    if (searchText) {
      result = result.filter((row) => {
        return Object.values(row).some((value) =>
          String(value).toLowerCase().includes(searchText.toLowerCase())
        );
      });
    }

    // Apply column-specific searches
    Object.entries(columnSearches).forEach(([columnId, searchValue]) => {
      if (searchValue) {
        result = result.filter((row) => {
          const cellValue = row[columnId];
          return String(cellValue).toLowerCase().includes(searchValue.toLowerCase());
        });
      }
    });

    // Apply column header checkbox filters
    Object.entries(columnFilters).forEach(([colId, selectedSet]) => {
      if (selectedSet && selectedSet.size > 0) {
        result = result.filter(row => selectedSet.has(String(row[colId] ?? '')));
      }
    });

    return result;
  }, [data, searchText, columnSearches, columnFilters, serverPagination]);

  // Group filtered data by the selected groupBy column
  const groupedData = useMemo(() => {
    if (!groupBy) return null;
    const groups = {};
    filteredData.forEach(row => {
      const key = String(row[groupBy] ?? '(empty)');
      if (!groups[key]) groups[key] = [];
      groups[key].push(row);
    });
    return Object.entries(groups).sort(([a], [b]) => a.localeCompare(b));
  }, [filteredData, groupBy]);

  // Reset collapsed groups when groupBy column changes
  useEffect(() => {
    setCollapsedGroups(new Set());
  }, [groupBy]);

  // Handle sorting with server/client modes
  const handleSortingChange = useCallback((newSorting) => {
    setSorting(newSorting);
    if (serverPagination && onSortChange && newSorting.length > 0) {
      const { id, desc } = newSorting[0];
      onSortChange(id, desc ? 'desc' : 'asc');
    }
  }, [serverPagination, onSortChange]);

  // Handle page size change
  const handlePageSizeChange = useCallback((newSize) => {
    setCurrentPageSize(newSize);
    if (serverPagination) {
      onPageSizeChange?.(newSize);
    } else {
      table.setPageSize(newSize);
    }
  }, [serverPagination, onPageSizeChange]);

  // Handle go-to-page
  const handleGoToPage = useCallback(() => {
    const pageNum = parseInt(goToPageInput, 10);
    if (!Number.isNaN(pageNum) && pageNum > 0) {
      if (serverPagination) {
        onPageChange?.(pageNum - 1);
      } else {
        table.setPageIndex(pageNum - 1);
      }
      setGoToPageInput('');
    }
  }, [goToPageInput, serverPagination, onPageChange]);

  const table = useReactTable({
    data: filteredData,
    columns,
    state: {
      sorting,
      columnVisibility,
    },
    onSortingChange: handleSortingChange,
    onColumnVisibilityChange: setColumnVisibility,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: serverPagination ? undefined : getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    manualPagination: serverPagination,
    initialState: {
      pagination: {
        pageSize: currentPageSize,
      },
    },
  });

  // Update table page size when it changes
  useEffect(() => {
    if (!serverPagination) {
      table.setPageSize(currentPageSize);
    }
  }, [currentPageSize, serverPagination, table]);

  const tableState = serverPagination
    ? {
        pageIndex: currentPage,
        pageSize: currentPageSize,
        totalRows,
      }
    : {
        pageIndex: table.getState().pagination.pageIndex,
        pageSize: table.getState().pagination.pageSize,
        totalRows: filteredData.length,
      };

  const { pageIndex, pageSize: tablePage, totalRows: displayTotalRows } = tableState;
  const startRow = pageIndex * tablePage + 1;
  const endRow = Math.min((pageIndex + 1) * tablePage, displayTotalRows);
  const pageCount = Math.ceil(displayTotalRows / tablePage);

  // Export handlers
  const handleExportPdf = async () => {
    setExportProgress(0);
    try {
      await onExportPdf?.();
      setExportProgress(100);
      setTimeout(() => setExportProgress(null), 1500);
    } catch (error) {
      console.error('PDF export failed:', error);
      setExportProgress(null);
    }
  };

  const handleExportExcel = async () => {
    setExportProgress(0);
    try {
      await onExportExcel?.();
      setExportProgress(100);
      setTimeout(() => setExportProgress(null), 1500);
    } catch (error) {
      console.error('Excel export failed:', error);
      setExportProgress(null);
    }
  };

  if (loading) {
    return (
      <div className="w-full">
        <LoadingSkeleton rows={pageSize} cols={columns.length} />
      </div>
    );
  }

  if (displayTotalRows === 0) {
    return (
      <div className="w-full">
        <div className="mb-4 flex items-center justify-between gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search..."
              value={searchText}
              onChange={(e) => {
                handleSearchChange(e.target.value);
                if (!serverPagination) {
                  table.resetPageIndex();
                }
              }}
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
              className="w-full pl-10 pr-4 py-2 border rounded-lg placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
            />
          </div>
          {showExport && (
            <div className="flex gap-2">
              <button
                onClick={handleExportPdf}
                disabled={loading || exportProgress !== null}
                style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
                className="flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium hover:opacity-75 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              >
                <Download className="w-4 h-4" />
                PDF
              </button>
              <button
                onClick={handleExportExcel}
                disabled={loading || exportProgress !== null}
                style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
                className="flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium hover:opacity-75 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              >
                <FileSpreadsheet className="w-4 h-4" />
                Excel
              </button>
            </div>
          )}
        </div>
        <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} className="flex items-center justify-center py-16 rounded-lg border transition-colors duration-200">
          <div className="flex flex-col items-center gap-3 text-center">
            <div className="w-12 h-12 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
              <Search className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
            </div>
            <div>
              <p className="text-sm font-semibold mb-1" style={{ color: 'var(--text-secondary)' }}>No results found</p>
              <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{emptyMessage}</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full space-y-4">
      {/* Search Bar, Column Picker, Density & Export Buttons — hidden when parent provides FilterBar */}
      {!hideToolbar && <div className="flex items-center justify-between gap-3">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search..."
            value={searchText}
            onChange={(e) => {
              handleSearchChange(e.target.value);
              if (!serverPagination) {
                table.resetPageIndex();
              }
            }}
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
            className="w-full pl-10 pr-4 py-2 border rounded-lg placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
          />
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-xs font-medium px-2.5 py-1.5 rounded-lg" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
            {displayTotalRows.toLocaleString()} results{groupBy && groupedData ? ` · ${groupedData.length} groups` : ''}
          </span>
          {activeFilterCount > 0 && (
            <button
              onClick={() => setColumnFilters({})}
              className="flex items-center gap-1.5 text-xs font-medium px-2.5 py-1.5 rounded-lg hover:opacity-75 transition-opacity"
              style={{ backgroundColor: 'rgba(59,130,246,0.1)', color: '#60a5fa', border: '1px solid rgba(59,130,246,0.3)' }}
            >
              <Filter className="w-3 h-3" />
              {activeFilterCount} filter{activeFilterCount > 1 ? 's' : ''} active
              <X className="w-3 h-3" />
            </button>
          )}
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          {/* Column Visibility Toggle */}
          <div className="relative">
            <button
              onClick={() => setShowColPicker(p => !p)}
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm font-medium hover:opacity-75 transition-colors duration-200"
              title="Toggle columns"
            >
              <Columns className="w-4 h-4" />
              <span className="hidden sm:inline">Columns</span>
            </button>
            {showColPicker && (
              <div
                className="absolute right-0 top-full mt-1 z-50 rounded-xl border shadow-xl p-3 min-w-44"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>COLUMNS</span>
                  <button onClick={() => setShowColPicker(false)} className="hover:opacity-75" style={{ color: 'var(--text-muted)' }}>
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
                {table.getAllLeafColumns().filter(col => col.id !== 'actions').map(col => (
                  <label key={col.id} className="flex items-center gap-2 text-sm cursor-pointer py-1 hover:opacity-75 transition-opacity">
                    <input
                      type="checkbox"
                      checked={col.getIsVisible()}
                      onChange={col.getToggleVisibilityHandler()}
                      className="rounded"
                    />
                    <span style={{ color: 'var(--text-secondary)' }}>
                      {typeof col.columnDef.header === 'string' ? col.columnDef.header : col.id}
                    </span>
                  </label>
                ))}
              </div>
            )}
          </div>

          {/* Row Density Toggle */}
          <div
            className="flex border rounded-lg overflow-hidden"
            style={{ borderColor: 'var(--border-primary)' }}
          >
            {[
              { key: 'compact',     icon: <AlignJustify className="w-3.5 h-3.5" />, title: 'Compact' },
              { key: 'comfortable', icon: <AlignLeft    className="w-3.5 h-3.5" />, title: 'Comfortable' },
              { key: 'spacious',    icon: <AlignCenter  className="w-3.5 h-3.5" />, title: 'Spacious' },
            ].map(({ key, icon, title }) => (
              <button
                key={key}
                onClick={() => setDensity(key)}
                title={title}
                className="px-2.5 py-2 transition-colors duration-150"
                style={{
                  backgroundColor: density === key ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                  color: density === key ? '#fff' : 'var(--text-muted)',
                }}
              >
                {icon}
              </button>
            ))}
          </div>

          {/* Group By */}
          {groupByOptions.length > 0 && (
            <div className="relative">
              <button
                onClick={() => setShowGroupPicker(p => !p)}
                style={{
                  backgroundColor: groupBy ? 'rgba(139,92,246,0.15)' : 'var(--bg-tertiary)',
                  borderColor: groupBy ? '#8b5cf6' : 'var(--border-primary)',
                  color: groupBy ? '#8b5cf6' : 'var(--text-secondary)',
                }}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm font-medium hover:opacity-75 transition-colors duration-200"
                title="Group rows"
              >
                <Layers className="w-4 h-4" />
                <span className="hidden sm:inline">{groupBy ? groupByOptions.find(o => o.key === groupBy)?.label || 'Group By' : 'Group By'}</span>
                {groupBy && (
                  <span
                    className="ml-1 p-0.5 rounded hover:opacity-75"
                    onClick={e => { e.stopPropagation(); setGroupBy(''); setShowGroupPicker(false); }}
                    title="Clear grouping"
                  >
                    <X className="w-3 h-3" />
                  </span>
                )}
              </button>
              {showGroupPicker && (
                <div
                  className="absolute right-0 top-full mt-1 z-50 rounded-xl border shadow-xl p-2 min-w-44"
                  style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
                  onMouseDown={e => e.stopPropagation()}
                >
                  <div className="flex items-center justify-between mb-2 px-1">
                    <span className="text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>GROUP BY</span>
                    <button onClick={() => setShowGroupPicker(false)} className="hover:opacity-75" style={{ color: 'var(--text-muted)' }}>
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <button
                    onClick={() => { setGroupBy(''); setShowGroupPicker(false); }}
                    className="w-full text-left text-xs px-2 py-1.5 rounded hover:opacity-75 mb-1 font-medium"
                    style={{ color: !groupBy ? '#8b5cf6' : 'var(--text-secondary)', backgroundColor: !groupBy ? 'rgba(139,92,246,0.1)' : 'transparent' }}
                  >
                    No grouping
                  </button>
                  <div className="border-t mb-1" style={{ borderColor: 'var(--border-primary)' }} />
                  {groupByOptions.map(opt => (
                    <button
                      key={opt.key}
                      onClick={() => { setGroupBy(opt.key); setShowGroupPicker(false); }}
                      className="w-full text-left text-xs px-2 py-1.5 rounded hover:opacity-75"
                      style={{ color: groupBy === opt.key ? '#8b5cf6' : 'var(--text-secondary)', backgroundColor: groupBy === opt.key ? 'rgba(139,92,246,0.1)' : 'transparent' }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {showExport && (
            <>
              <button
                onClick={handleExportPdf}
                disabled={loading || exportProgress !== null}
                style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
                className="flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium hover:opacity-75 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
                title="Export as PDF"
              >
                <Download className="w-4 h-4" />
                PDF
              </button>
              <button
                onClick={handleExportExcel}
                disabled={loading || exportProgress !== null}
                style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
                className="flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium hover:opacity-75 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
                title="Export as Excel"
              >
                <FileSpreadsheet className="w-4 h-4" />
                Excel
              </button>
            </>
          )}
        </div>
      </div>

      }

      {/* Export Progress Bar */}
      {exportProgress !== null && (
        <div className="w-full h-1 bg-gray-200 rounded-full overflow-hidden">
          <div
            className="h-full bg-blue-500 transition-all duration-300"
            style={{ width: `${exportProgress}%` }}
          />
        </div>
      )}

      {/* Bulk Actions Bar */}
      {selectedRows.size > 0 && (
        <div className="flex items-center justify-between px-4 py-2.5 rounded-lg border" style={{ backgroundColor: 'rgba(59,130,246,0.08)', borderColor: 'rgba(59,130,246,0.3)' }}>
          <span className="text-sm font-semibold" style={{ color: '#60a5fa' }}>{selectedRows.size} row{selectedRows.size > 1 ? 's' : ''} selected</span>
          <div className="flex items-center gap-2">
            {[{label:'Suppress'},{label:'Assign'},{label:'Export'}].map(({label}) => (
              <button key={label} className="text-xs px-3 py-1.5 rounded-lg font-medium transition-opacity hover:opacity-75"
                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                {label}
              </button>
            ))}
            <button onClick={() => setSelectedRows(new Set())} className="p-1.5 rounded hover:opacity-75" style={{ color: 'var(--text-muted)' }}>
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* ── DEBUG BADGE (temporary) ── */}
      <div style={{ position: 'fixed', bottom: 16, right: 16, zIndex: 9999, background: '#1e1b4b', border: '1.5px solid #8b5cf6', borderRadius: 8, padding: '6px 12px', fontSize: 11, color: '#c4b5fd', fontFamily: 'monospace', pointerEvents: 'none', boxShadow: '0 4px 16px rgba(0,0,0,0.5)' }}>
        <div style={{ fontWeight: 700, marginBottom: 2 }}>DataTable v4 (debug)</div>
        <div>groupBy: <span style={{ color: groupBy ? '#a78bfa' : '#6b7280' }}>{groupBy || '(none)'}</span></div>
        <div>groups: <span style={{ color: '#a78bfa' }}>{groupedData ? groupedData.length : '—'}</span></div>
        <div>rows: <span style={{ color: '#a78bfa' }}>{filteredData.length}</span></div>
      </div>

      {/* Table */}
      <div style={{ borderColor: 'var(--border-primary)' }} className="overflow-x-auto rounded-lg border transition-colors duration-200">
        <table style={{ backgroundColor: 'var(--bg-card)' }} className="min-w-full table-auto">
          <thead style={{ position: 'sticky', top: 0, zIndex: 20 }}>
            {table.getHeaderGroups().map((headerGroup) => (
              <React.Fragment key={`header-group-${headerGroup.id}`}>
                <tr key={headerGroup.id} style={{ backgroundColor: 'var(--bg-tertiary)', borderBottomColor: 'var(--border-primary)' }} className="border-b transition-colors duration-200">
                  <th className="pl-3 pr-1 w-8" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                    <input
                      type="checkbox"
                      checked={table.getRowModel().rows.length > 0 && selectedRows.size === table.getRowModel().rows.length}
                      onChange={toggleSelectAll}
                      className="cursor-pointer"
                      style={{ accentColor: '#3b82f6' }}
                    />
                  </th>
                  {headerGroup.headers.map((header) => {
                    const columnDef = header.column.columnDef;
                    const isSticky = columnDef.sticky;

                    return (
                      <th
                        key={header.id}
                        style={{
                          color: 'var(--text-secondary)',
                          borderRightColor: 'var(--border-primary)',
                          position: 'relative',
                          ...(columnDef.size && columnDef.size !== 150 && { width: columnDef.size, minWidth: columnDef.size }),
                          ...(isSticky && {
                            position: 'sticky',
                            left: 0,
                            zIndex: 10,
                            boxShadow: '4px 0 8px rgba(0, 0, 0, 0.1)',
                          }),
                        }}
                        className={`${densityHeaderPadding[density]} text-left font-semibold border-r last:border-r-0 transition-colors duration-200`}
                      >
                        <div className="flex items-center gap-1">
                          {/* Sort button */}
                          <button
                            onClick={header.column.getToggleSortingHandler()}
                            className={`flex items-center gap-1 ${header.column.getCanSort() ? 'cursor-pointer hover:opacity-75' : 'cursor-default'}`}
                          >
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            {header.column.getCanSort() && (
                              <span className="flex-shrink-0" style={{
                                color: header.column.getIsSorted() ? 'var(--accent-primary)' : 'var(--text-secondary)',
                                opacity: header.column.getIsSorted() ? 1 : 0.5,
                              }}>
                                {header.column.getIsSorted() === 'desc'
                                  ? <ArrowDown className="w-3.5 h-3.5" />
                                  : <ArrowUp className="w-3.5 h-3.5" />}
                              </span>
                            )}
                          </button>
                          {/* Column filter button */}
                          {columnDistinctValues[header.column.columnDef.accessorKey] && (
                            <button
                              onMouseDown={e => e.stopPropagation()}
                              onClick={e => {
                                e.stopPropagation();
                                if (openFilterCol === header.id) {
                                  setOpenFilterCol(null);
                                  setFilterBtnPos(null);
                                } else {
                                  const rect = e.currentTarget.getBoundingClientRect();
                                  setFilterBtnPos({ top: rect.bottom + 4, left: rect.left });
                                  setOpenFilterCol(header.id);
                                }
                              }}
                              className="flex-shrink-0 p-0.5 rounded hover:opacity-75 transition-opacity relative"
                              title="Filter column"
                              style={{ color: columnFilters[header.column.columnDef.accessorKey]?.size > 0 ? '#3b82f6' : 'var(--text-muted)' }}
                            >
                              <Filter className="w-3 h-3" style={{ fill: columnFilters[header.column.columnDef.accessorKey]?.size > 0 ? '#3b82f6' : 'none' }} />
                              {columnFilters[header.column.columnDef.accessorKey]?.size > 0 && (
                                <span className="absolute -top-1 -right-1 w-3.5 h-3.5 rounded-full text-[9px] font-bold flex items-center justify-center"
                                  style={{ backgroundColor: '#3b82f6', color: '#fff' }}>
                                  {columnFilters[header.column.columnDef.accessorKey].size}
                                </span>
                              )}
                            </button>
                          )}
                        </div>
                      </th>
                    );
                  })}
                  <th className="w-20 px-2" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
                    <span className="text-[10px] font-semibold uppercase tracking-wider">Actions</span>
                  </th>
                </tr>

              </React.Fragment>
            ))}
          </thead>
          <tbody>
            {serverPagination
              ? data.map((row, idx) => {
                  const expandedContent = renderExpandedRow?.(row);
                  return (
                    <React.Fragment key={idx}>
                      <tr
                        onClick={() => onRowClick?.({ original: row })}
                        onMouseEnter={() => setHoveredRow(String(idx))}
                        onMouseLeave={() => setHoveredRow(null)}
                        style={{
                          borderBottomColor: 'var(--border-primary)',
                          backgroundColor: selectedRows.has(String(idx))
                            ? 'rgba(59,130,246,0.06)'
                            : idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-secondary)',
                          borderLeft: `3px solid ${getRowSevColor(row) || 'transparent'}`,
                        }}
                        className={`border-b last:border-b-0 transition-colors duration-200 ${onRowClick ? 'cursor-pointer hover:opacity-80' : ''}`}
                      >
                        <td className="pl-3 pr-1 w-8" onClick={e => { e.stopPropagation(); toggleSelect(String(idx)); }}
                          style={{ color: 'var(--text-muted)' }}>
                          <input type="checkbox" checked={selectedRows.has(String(idx))} onChange={() => {}}
                            className="cursor-pointer" style={{ accentColor: '#3b82f6' }} />
                        </td>
                        {columns.map((col) => {
                          const isSticky = col.sticky;
                          const cellValue = row[col.accessorKey] || '';

                          return (
                            <td
                              key={`${idx}-${col.accessorKey || col.id}`}
                              style={{
                                color: 'var(--text-secondary)',
                                borderRightColor: 'var(--border-primary)',
                                ...(col.size && col.size !== 150 && { width: col.size, minWidth: col.size }),
                                ...(isSticky && {
                                  position: 'sticky',
                                  left: 0,
                                  zIndex: 9,
                                  boxShadow: '4px 0 8px rgba(0, 0, 0, 0.05)',
                                }),
                              }}
                              className={`${densityPadding[density]} border-r last:border-r-0 transition-colors duration-200`}
                            >
                              <div className="min-w-0">
                                {col.cell ? col.cell({ getValue: () => cellValue, row: { original: row } }) : cellValue}
                              </div>
                            </td>
                          );
                        })}
                        <td className="px-1.5 w-20"
                          style={{
                            opacity: hoveredRow === String(idx) ? 1 : 0,
                            transition: 'opacity 0.15s',
                            backgroundColor: selectedRows.has(String(idx)) ? 'rgba(59,130,246,0.06)' : idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-secondary)',
                            minWidth: 80,
                          }}
                          onClick={e => e.stopPropagation()}>
                          <div className="flex items-center gap-0.5">
                            {[
                              { icon: <Eye className="w-3 h-3" />, title: 'View', action: () => onRowClick?.({ original: row }) },
                              { icon: <Copy className="w-3 h-3" />, title: 'Copy ID', action: () => navigator.clipboard?.writeText(String(row?.resource_uid || row?.id || '')) },
                              { icon: <BellOff className="w-3 h-3" />, title: 'Suppress', action: () => {} },
                            ].map(({ icon, title, action }) => (
                              <button key={title} title={title} onClick={action}
                                className="p-1.5 rounded hover:opacity-75 transition-opacity"
                                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                                {icon}
                              </button>
                            ))}
                          </div>
                        </td>
                      </tr>
                      {expandedContent && (
                        <tr>
                          <td colSpan={columns.length + 2} className="p-0">
                            {expandedContent}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              : groupBy && groupedData
              ? groupedData.map(([groupKey, groupRows]) => {
                  const isExpanded = !collapsedGroups.has(groupKey); // collapsed = explicitly collapsed; default expanded
                  const visibleColCount = table.getAllLeafColumns().filter(c => c.getIsVisible()).length;
                  const totalCols = visibleColCount + 2;
                  return (
                    <React.Fragment key={groupKey}>
                      {/* Group header row */}
                      <tr
                        onClick={() => setCollapsedGroups(prev => {
                          const next = new Set(prev);
                          if (next.has(groupKey)) next.delete(groupKey); else next.add(groupKey);
                          return next;
                        })}
                        style={{
                          backgroundColor: 'rgba(139,92,246,0.18)',
                          borderTop: '2px solid rgba(139,92,246,0.4)',
                          borderBottom: '2px solid rgba(139,92,246,0.4)',
                          borderLeft: '4px solid #8b5cf6',
                          cursor: 'pointer',
                        }}
                        className="select-none"
                      >
                        <td colSpan={totalCols} className="px-4 py-2">
                          <div className="flex items-center gap-2">
                            <span style={{ color: '#8b5cf6', display: 'flex', alignItems: 'center' }}>
                              {isExpanded
                                ? <ChevronDown className="w-4 h-4" />
                                : <ChevronRight className="w-4 h-4" />}
                            </span>
                            <span className="text-xs font-bold uppercase tracking-wider" style={{ color: '#8b5cf6' }}>{groupKey}</span>
                            <span className="text-xs px-2 py-0.5 rounded-full font-bold" style={{ backgroundColor: '#8b5cf6', color: '#fff' }}>
                              {groupRows.length}
                            </span>
                            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                              {isExpanded ? 'click to collapse' : 'click to expand'}
                            </span>
                          </div>
                        </td>
                      </tr>
                      {/* Group data rows */}
                      {isExpanded && groupRows.map((row, idx) => {
                        const rowId = `${groupKey}-${idx}`;
                        const expandedContent = renderExpandedRow?.(row);
                        return (
                          <React.Fragment key={rowId}>
                            <tr
                              onClick={() => onRowClick?.(row)}
                              onMouseEnter={() => setHoveredRow(rowId)}
                              onMouseLeave={() => setHoveredRow(null)}
                              style={{
                                borderBottomColor: 'var(--border-primary)',
                                backgroundColor: selectedRows.has(rowId)
                                  ? 'rgba(59,130,246,0.06)'
                                  : idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-secondary)',
                                borderLeft: `3px solid ${getRowSevColor(row) || 'transparent'}`,
                              }}
                              className={`border-b last:border-b-0 transition-colors duration-200 ${onRowClick ? 'cursor-pointer hover:opacity-80' : ''}`}
                            >
                              <td className="pl-3 pr-1 w-8" onClick={e => { e.stopPropagation(); toggleSelect(rowId); }}
                                style={{ color: 'var(--text-muted)' }}>
                                <input type="checkbox" checked={selectedRows.has(rowId)} onChange={() => {}}
                                  className="cursor-pointer" style={{ accentColor: '#3b82f6' }} />
                              </td>
                              {table.getAllLeafColumns().filter(c => c.getIsVisible()).map(col => {
                                const colDef = col.columnDef;
                                const isSticky = colDef.sticky;
                                const colSize = colDef.size;
                                const cellValue = row[colDef.accessorKey] ?? '';
                                return (
                                  <td
                                    key={col.id}
                                    style={{
                                      color: 'var(--text-secondary)',
                                      borderRightColor: 'var(--border-primary)',
                                      ...(colSize && colSize !== 150 && { width: colSize, minWidth: colSize }),
                                      ...(isSticky && { position: 'sticky', left: 0, zIndex: 9, boxShadow: '4px 0 8px rgba(0,0,0,0.05)' }),
                                    }}
                                    className={`${densityPadding[density]} border-r last:border-r-0 transition-colors duration-200`}
                                  >
                                    <div className="break-words">
                                      {colDef.cell
                                        ? colDef.cell({ getValue: () => cellValue, row: { original: row } })
                                        : String(cellValue)}
                                    </div>
                                  </td>
                                );
                              })}
                              <td className="px-1.5 w-20"
                                style={{
                                  opacity: hoveredRow === rowId ? 1 : 0,
                                  transition: 'opacity 0.15s',
                                  backgroundColor: selectedRows.has(rowId) ? 'rgba(59,130,246,0.06)' : idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-secondary)',
                                  minWidth: 80,
                                }}
                                onClick={e => e.stopPropagation()}>
                                <div className="flex items-center gap-0.5">
                                  {[
                                    { icon: <Eye className="w-3 h-3" />, title: 'View', action: () => onRowClick?.(row) },
                                    { icon: <Copy className="w-3 h-3" />, title: 'Copy ID', action: () => navigator.clipboard?.writeText(String(row?.resource_uid || row?.id || '')) },
                                    { icon: <BellOff className="w-3 h-3" />, title: 'Suppress', action: () => {} },
                                  ].map(({ icon, title, action }) => (
                                    <button key={title} title={title} onClick={action}
                                      className="p-1.5 rounded hover:opacity-75 transition-opacity"
                                      style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                                      {icon}
                                    </button>
                                  ))}
                                </div>
                              </td>
                            </tr>
                            {expandedContent && (
                              <tr><td colSpan={totalCols} className="p-0">{expandedContent}</td></tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </React.Fragment>
                  );
                })
              : table.getRowModel().rows.map((row, idx) => {
                  const expandedContent = renderExpandedRow?.(row.original);
                  return (
                    <React.Fragment key={row.id}>
                      <tr
                        onClick={() => onRowClick?.(row.original)}
                        onMouseEnter={() => setHoveredRow(row.id)}
                        onMouseLeave={() => setHoveredRow(null)}
                        style={{
                          borderBottomColor: 'var(--border-primary)',
                          backgroundColor: selectedRows.has(row.id)
                            ? 'rgba(59,130,246,0.06)'
                            : idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-secondary)',
                          borderLeft: `3px solid ${getRowSevColor(row.original) || 'transparent'}`,
                        }}
                        className={`border-b last:border-b-0 transition-colors duration-200 ${onRowClick ? 'cursor-pointer hover:opacity-80' : ''}`}
                      >
                        <td className="pl-3 pr-1 w-8" onClick={e => { e.stopPropagation(); toggleSelect(row.id); }}
                          style={{ color: 'var(--text-muted)' }}>
                          <input type="checkbox" checked={selectedRows.has(row.id)} onChange={() => {}}
                            className="cursor-pointer" style={{ accentColor: '#3b82f6' }} />
                        </td>
                        {row.getVisibleCells().map((cell) => {
                          const isSticky = cell.column.columnDef.sticky;
                          const colSize = cell.column.columnDef.size;

                          return (
                            <td
                              key={cell.id}
                              style={{
                                color: 'var(--text-secondary)',
                                borderRightColor: 'var(--border-primary)',
                                ...(colSize && colSize !== 150 && { width: colSize, minWidth: colSize }),
                                ...(isSticky && {
                                  position: 'sticky',
                                  left: 0,
                                  zIndex: 9,
                                  boxShadow: '4px 0 8px rgba(0, 0, 0, 0.05)',
                                }),
                              }}
                              className={`${densityPadding[density]} border-r last:border-r-0 transition-colors duration-200`}
                            >
                              <div className="min-w-0">
                                {flexRender(cell.column.columnDef.cell, cell.getContext())}
                              </div>
                            </td>
                          );
                        })}
                        <td className="px-1.5 w-20"
                          style={{
                            opacity: hoveredRow === row.id ? 1 : 0,
                            transition: 'opacity 0.15s',
                            backgroundColor: selectedRows.has(row.id) ? 'rgba(59,130,246,0.06)' : idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-secondary)',
                            minWidth: 80,
                          }}
                          onClick={e => e.stopPropagation()}>
                          <div className="flex items-center gap-0.5">
                            {[
                              { icon: <Eye className="w-3 h-3" />, title: 'View', action: () => onRowClick?.(row.original) },
                              { icon: <Copy className="w-3 h-3" />, title: 'Copy ID', action: () => navigator.clipboard?.writeText(String(row.original?.resource_uid || row.original?.id || '')) },
                              { icon: <BellOff className="w-3 h-3" />, title: 'Suppress', action: () => {} },
                            ].map(({ icon, title, action }) => (
                              <button key={title} title={title} onClick={action}
                                className="p-1.5 rounded hover:opacity-75 transition-opacity"
                                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', border: '1px solid var(--border-primary)' }}>
                                {icon}
                              </button>
                            ))}
                          </div>
                        </td>
                      </tr>
                      {expandedContent && (
                        <tr>
                          <td colSpan={row.getVisibleCells().length + 2} className="p-0">
                            {expandedContent}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
          </tbody>
        </table>
      </div>

      {/* Pagination Bar — hidden when all rows fit on one page */}
      {pageCount > 1 && (
      <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} className="flex items-center justify-between px-4 py-3 rounded-lg border transition-colors duration-200">
        <div style={{ color: 'var(--text-tertiary)' }} className="text-sm">
          Showing <span className="font-semibold">{startRow}</span> to{' '}
          <span className="font-semibold">{endRow}</span> of{' '}
          <span className="font-semibold">{displayTotalRows}</span>
        </div>

        <div className="flex items-center gap-4">
          {/* Page Size Selector */}
          <div className="flex items-center gap-2">
            <span style={{ color: 'var(--text-secondary)' }} className="text-sm font-medium">
              Rows per page:
            </span>
            <select
              value={currentPageSize}
              onChange={(e) => handlePageSizeChange(parseInt(e.target.value, 10))}
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
              className="px-3 py-2 rounded-lg border text-sm font-medium transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>

          {/* Go to Page Input */}
          <div className="flex items-center gap-1">
            <input
              type="number"
              min="1"
              max={pageCount}
              value={goToPageInput}
              onChange={(e) => setGoToPageInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleGoToPage()}
              placeholder="Go to"
              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
              className="w-16 px-2 py-2 border rounded-lg text-sm text-center focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
            />
            <button
              onClick={handleGoToPage}
              disabled={!goToPageInput}
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              className="px-2 py-2 rounded-lg border text-sm font-medium hover:opacity-75 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
            >
              Go
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => (serverPagination ? onPageChange?.(0) : table.setPageIndex(0))}
              disabled={pageIndex === 0}
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              className="p-2 rounded-lg border hover:opacity-75 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              title="First page"
            >
              <ChevronsLeft className="w-4 h-4" />
            </button>

            <button
              onClick={() =>
                serverPagination ? onPageChange?.(pageIndex - 1) : table.previousPage()
              }
              disabled={pageIndex === 0}
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              className="px-3 py-2 rounded-lg border text-sm font-medium hover:opacity-75 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
            >
              Prev
            </button>

            <div className="flex items-center gap-1">
              {(() => {
                const maxVisible = 5;
                let start = Math.max(0, pageIndex - Math.floor(maxVisible / 2));
                let end = start + maxVisible;
                if (end > pageCount) {
                  end = pageCount;
                  start = Math.max(0, end - maxVisible);
                }
                return Array.from({ length: end - start }, (_, i) => start + i).map((pageNum) => (
                  <button
                    key={pageNum}
                    onClick={() =>
                      serverPagination ? onPageChange?.(pageNum) : table.setPageIndex(pageNum)
                    }
                    style={
                      pageIndex === pageNum
                        ? { backgroundColor: 'rgb(37, 99, 235)' }
                        : { backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }
                    }
                    className={`w-8 h-8 rounded-lg text-sm font-medium transition-colors duration-200 ${pageIndex === pageNum ? 'text-white' : 'border'}`}
                  >
                    {pageNum + 1}
                  </button>
                ));
              })()}
            </div>

            <button
              onClick={() =>
                serverPagination ? onPageChange?.(pageCount - 1) : table.setPageIndex(pageCount - 1)
              }
              disabled={pageIndex === pageCount - 1}
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              className="px-3 py-2 rounded-lg border text-sm font-medium hover:opacity-75 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
            >
              Next
            </button>

            <button
              onClick={() =>
                serverPagination ? onPageChange?.(pageCount - 1) : table.setPageIndex(pageCount - 1)
              }
              disabled={pageIndex === pageCount - 1}
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
              className="p-2 rounded-lg border hover:opacity-75 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              title="Last page"
            >
              <ChevronsRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
      )}

      {/* ── Filter Popover — rendered fixed to avoid overflow-x-auto clipping ── */}
      {openFilterCol && filterBtnPos && (() => {
        const colKey = table.getAllLeafColumns().find(c => c.id === openFilterCol)?.columnDef?.accessorKey;
        if (!colKey) return null;
        const vals = columnDistinctValues[colKey] || [];
        const activeSet = columnFilters[colKey];
        const searchVal = filterSearch[openFilterCol] || '';
        const filtered = vals.filter(v => !searchVal || String(v).toLowerCase().includes(searchVal.toLowerCase()));
        return (
          <div
            onMouseDown={e => e.stopPropagation()}
            onClick={e => e.stopPropagation()}
            style={{
              position: 'fixed',
              top: filterBtnPos.top,
              left: Math.min(filterBtnPos.left, window.innerWidth - 230),
              zIndex: 9999,
              backgroundColor: 'var(--bg-card)',
              borderColor: 'var(--border-primary)',
              minWidth: 210,
              maxWidth: 280,
              border: '1px solid var(--border-primary)',
              borderRadius: 12,
              boxShadow: '0 8px 32px rgba(0,0,0,0.25)',
            }}
          >
            <div className="p-2 border-b" style={{ borderColor: 'var(--border-primary)' }}>
              <input
                autoFocus
                type="text"
                placeholder="Search values..."
                value={searchVal}
                onChange={e => setFilterSearch(prev => ({ ...prev, [openFilterCol]: e.target.value }))}
                className="w-full px-2 py-1 text-xs rounded border focus:outline-none focus:ring-1 focus:ring-blue-500"
                style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              />
            </div>
            <div className="p-2">
              <label className="flex items-center gap-2 text-xs cursor-pointer py-1 px-1 rounded hover:opacity-75">
                <input
                  type="checkbox"
                  checked={!activeSet || activeSet.size === 0}
                  onChange={() => clearColumnFilter(colKey)}
                  style={{ accentColor: '#3b82f6' }}
                />
                <span className="font-semibold" style={{ color: 'var(--text-primary)' }}>All</span>
              </label>
              <div className="my-1 border-t" style={{ borderColor: 'var(--border-primary)' }} />
              <div className="overflow-y-auto" style={{ maxHeight: 220 }}>
                {filtered.map(val => (
                  <label key={String(val)} className="flex items-center gap-2 text-xs cursor-pointer py-1 px-1 rounded hover:opacity-75">
                    <input
                      type="checkbox"
                      checked={activeSet?.has(String(val)) || false}
                      onChange={() => toggleColumnFilterValue(colKey, String(val))}
                      style={{ accentColor: '#3b82f6' }}
                    />
                    <span style={{ color: 'var(--text-secondary)' }}>{String(val)}</span>
                  </label>
                ))}
              </div>
            </div>
            {activeSet?.size > 0 && (
              <div className="px-3 py-2 border-t flex justify-between items-center" style={{ borderColor: 'var(--border-primary)' }}>
                <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>{activeSet.size} selected</span>
                <button onClick={() => clearColumnFilter(colKey)} className="text-[10px] font-semibold hover:opacity-75" style={{ color: '#3b82f6' }}>Clear</button>
              </div>
            )}
          </div>
        );
      })()}
    </div>
  );
}
