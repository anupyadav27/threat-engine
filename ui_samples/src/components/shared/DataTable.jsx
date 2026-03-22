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
import { ChevronUp, ChevronDown, ChevronsLeft, ChevronsRight, Search, Download, FileSpreadsheet, Columns, AlignJustify, AlignLeft, AlignCenter, X } from 'lucide-react';
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
}) {
  const [searchText, setSearchText] = useState('');
  const [columnSearches, setColumnSearches] = useState({});
  const [sorting, setSorting] = useState([]);
  const [currentPageSize, setCurrentPageSize] = useState(pageSize);
  const [goToPageInput, setGoToPageInput] = useState('');
  const [exportProgress, setExportProgress] = useState(null);
  // Column visibility & density
  const [columnVisibility, setColumnVisibility] = useState({});
  const [density, setDensity] = useState('comfortable'); // 'compact' | 'comfortable' | 'spacious'
  const [showColPicker, setShowColPicker] = useState(false);

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

    return result;
  }, [data, searchText, columnSearches, serverPagination]);

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
          <div className="text-center">
            <p style={{ color: 'var(--text-tertiary)' }} className="text-sm">{emptyMessage}</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full space-y-4">
      {/* Search Bar, Column Picker, Density & Export Buttons */}
      <div className="flex items-center justify-between gap-3">
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

      {/* Export Progress Bar */}
      {exportProgress !== null && (
        <div className="w-full h-1 bg-gray-200 rounded-full overflow-hidden">
          <div
            className="h-full bg-blue-500 transition-all duration-300"
            style={{ width: `${exportProgress}%` }}
          />
        </div>
      )}

      {/* Table */}
      <div style={{ borderColor: 'var(--border-primary)' }} className="overflow-x-auto rounded-lg border transition-colors duration-200">
        <table style={{ backgroundColor: 'var(--bg-card)' }} className="min-w-full table-auto">
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <React.Fragment key={`header-group-${headerGroup.id}`}>
                <tr key={headerGroup.id} style={{ backgroundColor: 'var(--bg-tertiary)', borderBottomColor: 'var(--border-primary)' }} className="border-b transition-colors duration-200">
                  {headerGroup.headers.map((header) => {
                    const columnDef = header.column.columnDef;
                    const isSticky = columnDef.sticky;

                    return (
                      <th
                        key={header.id}
                        onClick={header.column.getToggleSortingHandler()}
                        style={{
                          color: 'var(--text-secondary)',
                          borderRightColor: 'var(--border-primary)',
                          ...(columnDef.size && columnDef.size !== 150 && { width: columnDef.size, minWidth: columnDef.size, maxWidth: columnDef.size }),
                          ...(isSticky && {
                            position: 'sticky',
                            left: 0,
                            zIndex: 10,
                            boxShadow: '4px 0 8px rgba(0, 0, 0, 0.1)',
                          }),
                        }}
                        className={`${densityHeaderPadding[density]} text-left font-semibold border-r last:border-r-0 transition-colors duration-200 ${
                          header.column.getCanSort() ? 'cursor-pointer hover:opacity-75 transition-opacity' : ''
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {header.column.getCanSort() && (
                            <span style={{ color: 'var(--text-muted)' }}>
                              {header.column.getIsSorted() ? (
                                header.column.getIsSorted() === 'desc' ? (
                                  <ChevronDown className="w-4 h-4" />
                                ) : (
                                  <ChevronUp className="w-4 h-4" />
                                )
                              ) : (
                                <div className="w-4 h-4" />
                              )}
                            </span>
                          )}
                        </div>
                      </th>
                    );
                  })}
                </tr>

                {/* Column Search Row */}
                {columns.some((col) => col.enableColumnSearch) && (
                  <tr key={`search-row-${headerGroup.id}`} style={{ backgroundColor: 'var(--bg-card)', borderBottomColor: 'var(--border-primary)' }} className="border-b">
                    {headerGroup.headers.map((header) => {
                      const columnDef = header.column.columnDef;
                      const isSticky = columnDef.sticky;
                      const enableSearch = columnDef.enableColumnSearch;

                      return (
                        <th
                          key={`search-${header.id}`}
                          style={{
                            borderRightColor: 'var(--border-primary)',
                            ...(isSticky && {
                              position: 'sticky',
                              left: 0,
                              zIndex: 10,
                            }),
                          }}
                          className="px-6 py-2 border-r last:border-r-0"
                        >
                          {enableSearch && (
                            <input
                              type="text"
                              placeholder="Filter..."
                              value={columnSearches[header.id] || ''}
                              onChange={(e) => handleColumnSearch(header.id, e.target.value)}
                              style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-primary)', borderColor: 'var(--border-primary)' }}
                              className="w-full px-2 py-1 border rounded text-xs focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
                            />
                          )}
                        </th>
                      );
                    })}
                  </tr>
                )}
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
                        style={{ borderBottomColor: 'var(--border-primary)', backgroundColor: idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-secondary)' }}
                        className={`border-b last:border-b-0 transition-colors duration-200 ${onRowClick ? 'cursor-pointer hover:opacity-75 transition-opacity' : ''}`}
                      >
                        {columns.map((col) => {
                          const isSticky = col.sticky;
                          const cellValue = row[col.accessorKey] || '';

                          return (
                            <td
                              key={`${idx}-${col.accessorKey || col.id}`}
                              style={{
                                color: 'var(--text-secondary)',
                                borderRightColor: 'var(--border-primary)',
                                ...(col.size && col.size !== 150 && { width: col.size, minWidth: col.size, maxWidth: col.size }),
                                ...(isSticky && {
                                  position: 'sticky',
                                  left: 0,
                                  zIndex: 9,
                                  boxShadow: '4px 0 8px rgba(0, 0, 0, 0.05)',
                                }),
                              }}
                              className={`${densityPadding[density]} border-r last:border-r-0 transition-colors duration-200`}
                            >
                              <div className="break-words">
                                {col.cell ? col.cell({ getValue: () => cellValue, row: { original: row } }) : cellValue}
                              </div>
                            </td>
                          );
                        })}
                      </tr>
                      {expandedContent && (
                        <tr>
                          <td colSpan={columns.length} className="p-0">
                            {expandedContent}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              : table.getRowModel().rows.map((row, idx) => {
                  const expandedContent = renderExpandedRow?.(row.original);
                  return (
                    <React.Fragment key={row.id}>
                      <tr
                        onClick={() => onRowClick?.(row.original)}
                        style={{ borderBottomColor: 'var(--border-primary)', backgroundColor: idx % 2 === 0 ? 'var(--bg-card)' : 'var(--bg-secondary)' }}
                        className={`border-b last:border-b-0 transition-colors duration-200 ${onRowClick ? 'cursor-pointer hover:opacity-75 transition-opacity' : ''}`}
                      >
                        {row.getVisibleCells().map((cell) => {
                          const isSticky = cell.column.columnDef.sticky;
                          const colSize = cell.column.columnDef.size;

                          return (
                            <td
                              key={cell.id}
                              style={{
                                color: 'var(--text-secondary)',
                                borderRightColor: 'var(--border-primary)',
                                ...(colSize && colSize !== 150 && { width: colSize, minWidth: colSize, maxWidth: colSize }),
                                ...(isSticky && {
                                  position: 'sticky',
                                  left: 0,
                                  zIndex: 9,
                                  boxShadow: '4px 0 8px rgba(0, 0, 0, 0.05)',
                                }),
                              }}
                              className={`${densityPadding[density]} border-r last:border-r-0 transition-colors duration-200`}
                            >
                              <div className="break-words">
                                {flexRender(cell.column.columnDef.cell, cell.getContext())}
                              </div>
                            </td>
                          );
                        })}
                      </tr>
                      {expandedContent && (
                        <tr>
                          <td colSpan={row.getVisibleCells().length} className="p-0">
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

      {/* Pagination Bar */}
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
    </div>
  );
}
