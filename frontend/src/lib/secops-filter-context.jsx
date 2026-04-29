'use client';

/**
 * SecOpsFilterContext — shared filter state for the SecOps section.
 *
 * The filter bar (SecOpsFilterBar) writes to this context.
 * The overview page (secops/page.jsx) reads from it to filter its data.
 *
 * The overview page also registers available project options by calling
 * setAvailableProjects([{ value, label }]) after it loads scan data.
 */

import { createContext, useContext, useState, useCallback } from 'react';

const SecOpsFilterContext = createContext(null);

export function SecOpsFilterProvider({ children }) {
  const [scanner,   setScanner]   = useState('');
  const [severity,  setSeverity]  = useState('');
  const [status,    setStatus]    = useState('');
  const [timeRange, setTimeRange] = useState('30d');
  const [project,   setProject]   = useState('');

  // Available project options — populated by the page after loading scan data
  const [availableProjects, setAvailableProjects] = useState([]);

  const clearAll = useCallback(() => {
    setScanner('');
    setSeverity('');
    setStatus('');
    setTimeRange('30d');
    setProject('');
  }, []);

  return (
    <SecOpsFilterContext.Provider value={{
      scanner,   setScanner,
      severity,  setSeverity,
      status,    setStatus,
      timeRange, setTimeRange,
      project,   setProject,
      availableProjects, setAvailableProjects,
      clearAll,
    }}>
      {children}
    </SecOpsFilterContext.Provider>
  );
}

export function useSecOpsFilters() {
  const ctx = useContext(SecOpsFilterContext);
  if (!ctx) throw new Error('useSecOpsFilters must be used within SecOpsFilterProvider');
  return ctx;
}
