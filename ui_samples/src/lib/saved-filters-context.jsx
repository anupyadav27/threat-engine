'use client';

import { createContext, useContext, useState, useCallback, useEffect } from 'react';

const SavedFiltersContext = createContext(null);

const STORAGE_KEY = 'cspm-saved-filters';

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

export function SavedFiltersProvider({ children }) {
  const [savedFilters, setSavedFilters] = useState([]);

  // Hydrate from localStorage after mount (avoids SSR mismatch)
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) setSavedFilters(JSON.parse(raw));
    } catch {
      // ignore corrupt storage
    }
  }, []);

  // Persist on every change
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(savedFilters));
    } catch {
      // ignore quota errors
    }
  }, [savedFilters]);

  /**
   * Save the current filter state under a name.
   * @param {string} name - display name for the preset
   * @param {{ provider, account, region, timeRange }} filters - current filter values
   */
  const saveFilter = useCallback((name, filters) => {
    const entry = {
      id: generateId(),
      name: name.trim(),
      createdAt: new Date().toISOString(),
      filters,
    };
    setSavedFilters(prev => [...prev, entry]);
    return entry;
  }, []);

  /** Remove a saved preset by id */
  const deleteFilter = useCallback((id) => {
    setSavedFilters(prev => prev.filter(f => f.id !== id));
  }, []);

  return (
    <SavedFiltersContext.Provider value={{ savedFilters, saveFilter, deleteFilter }}>
      {children}
    </SavedFiltersContext.Provider>
  );
}

export function useSavedFilters() {
  const ctx = useContext(SavedFiltersContext);
  if (!ctx) throw new Error('useSavedFilters must be used inside <SavedFiltersProvider>');
  return ctx;
}
