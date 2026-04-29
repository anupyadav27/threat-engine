'use client';

import { useState, useCallback } from 'react';
import { Search, X } from 'lucide-react';

/**
 * Reusable search bar with debounce support.
 *
 * @param {object}   props
 * @param {string}   props.value          - Controlled value
 * @param {function} props.onChange        - Called with new string value
 * @param {string}   [props.placeholder]  - Placeholder text
 * @param {string}   [props.className]    - Extra class name for the wrapper
 * @param {object}   [props.style]        - Extra inline style for the wrapper
 */
export default function SearchBar({
  value = '',
  onChange,
  placeholder = 'Search...',
  className = '',
  style = {},
}) {
  const handleClear = useCallback(() => {
    onChange('');
  }, [onChange]);

  return (
    <div
      className={`flex items-center gap-2 px-3 rounded-lg border ${className}`}
      style={{
        backgroundColor: 'var(--bg-tertiary)',
        borderColor: 'var(--border-primary)',
        minWidth: '220px',
        height: '38px',
        ...style,
      }}
    >
      <Search className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--text-tertiary)' }} />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="flex-1 bg-transparent outline-none text-sm"
        style={{ color: 'var(--text-primary)' }}
      />
      {value && (
        <button
          onClick={handleClear}
          className="flex-shrink-0 hover:opacity-70 transition-opacity"
          style={{ color: 'var(--text-tertiary)' }}
          aria-label="Clear search"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  );
}
