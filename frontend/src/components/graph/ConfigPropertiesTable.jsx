'use client';

import { useState } from 'react';

const MAX_VISIBLE = 20;
const MAX_STRING_LENGTH = 50;

/**
 * Formats a prop_* key into a human-readable label.
 * Strips the "prop_" prefix and converts underscores to spaces with capitalised
 * first letter. e.g. "prop_storage_encrypted" → "Storage Encrypted"
 */
function formatPropName(key) {
  return key
    .replace(/^prop_/, '')
    .replace(/_/g, ' ')
    .replace(/^\w/, (c) => c.toUpperCase());
}

/**
 * Renders a single value cell.
 * - boolean  → coloured badge  (green "Yes" / red "No")
 * - number   → plain number
 * - string   → truncated at 50 chars
 */
function ValueCell({ value }) {
  if (typeof value === 'boolean') {
    return value ? (
      <span
        className="inline-block text-[11px] px-2 py-0.5 rounded-full font-semibold"
        style={{ backgroundColor: 'rgba(34,197,94,0.15)', color: '#16a34a' }}
      >
        Yes
      </span>
    ) : (
      <span
        className="inline-block text-[11px] px-2 py-0.5 rounded-full font-semibold"
        style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#dc2626' }}
      >
        No
      </span>
    );
  }

  if (typeof value === 'number') {
    return (
      <span className="text-xs" style={{ color: 'var(--text-primary)' }}>
        {value}
      </span>
    );
  }

  const str = String(value);
  const truncated = str.length > MAX_STRING_LENGTH ? `${str.slice(0, MAX_STRING_LENGTH)}...` : str;
  return (
    <span
      className="text-xs break-all"
      style={{ color: 'var(--text-primary)' }}
      title={str.length > MAX_STRING_LENGTH ? str : undefined}
    >
      {truncated}
    </span>
  );
}

/**
 * Extracts and displays prop_* security properties from a Neo4j Resource node.
 *
 * Accepts either:
 *   nodeProperties — the flat node object (top-level keys) or a nested
 *                    .properties sub-object returned by the BFF/Neo4j.
 *
 * The FAIL-first sort: rows where the companion prop_X_pass key is exactly
 * false are placed before passing rows, then alphabetically within each group.
 *
 * @param {{ nodeProperties: object }} props
 */
export function ConfigPropertiesTable({ nodeProperties }) {
  const [showAll, setShowAll] = useState(false);

  // Normalise: accept node.properties (nested) or flat node object
  const source =
    nodeProperties && typeof nodeProperties === 'object' ? nodeProperties : {};

  // Extract prop_* entries, skipping the companion _pass keys
  const rows = Object.entries(source)
    .filter(([key, value]) => {
      if (!key.startsWith('prop_')) return false;
      if (key.endsWith('_pass')) return false;
      if (value === null || value === undefined) return false;
      return true;
    })
    .map(([key, value]) => {
      const passKey = `${key}_pass`;
      const passValue = source[passKey];
      // pass is true unless the _pass companion explicitly equals false
      const pass = passValue !== false;
      return { name: formatPropName(key), rawKey: key, value, pass };
    });

  if (rows.length === 0) {
    return (
      <div
        className="text-xs py-3 px-1 text-center"
        style={{ color: 'var(--text-muted)' }}
      >
        No config properties available for this resource type
      </div>
    );
  }

  // FAIL rows first, then alphabetically within each group
  const sorted = [...rows].sort((a, b) => {
    if (!a.pass && b.pass) return -1;
    if (a.pass && !b.pass) return 1;
    return a.name.localeCompare(b.name);
  });

  const visible = showAll ? sorted : sorted.slice(0, MAX_VISIBLE);
  const overflow = sorted.length - MAX_VISIBLE;

  return (
    <div>
      <table
        className="w-full text-xs border-collapse"
        style={{ tableLayout: 'fixed' }}
      >
        <colgroup>
          <col style={{ width: '42%' }} />
          <col style={{ width: '38%' }} />
          <col style={{ width: '20%' }} />
        </colgroup>
        <thead>
          <tr
            className="text-[10px] font-semibold uppercase tracking-wider"
            style={{ color: 'var(--text-secondary)' }}
          >
            <th className="text-left pb-1.5 pr-2">Property</th>
            <th className="text-left pb-1.5 pr-2">Value</th>
            <th className="text-left pb-1.5">Status</th>
          </tr>
        </thead>
        <tbody>
          {visible.map(({ name, rawKey, value, pass }) => (
            <tr
              key={rawKey}
              style={{
                backgroundColor: pass ? '#e8f5e9' : '#ffebee',
              }}
            >
              <td
                className="py-1.5 pr-2 pl-1.5 align-top text-[11px] font-medium rounded-l"
                style={{ color: 'var(--text-secondary)' }}
                title={name}
              >
                <span className="block truncate">{name}</span>
              </td>
              <td className="py-1.5 pr-2 align-top">
                <ValueCell value={value} />
              </td>
              <td
                className="py-1.5 align-top rounded-r font-semibold text-[11px]"
                style={{ color: pass ? '#2e7d32' : '#c62828' }}
              >
                {pass ? '✓ PASS' : '✗ FAIL'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {!showAll && overflow > 0 && (
        <button
          onClick={() => setShowAll(true)}
          className="mt-2 text-[11px] hover:underline"
          style={{ color: 'var(--accent-primary, #3b82f6)' }}
        >
          Show {overflow} more
        </button>
      )}

      {showAll && sorted.length > MAX_VISIBLE && (
        <button
          onClick={() => setShowAll(false)}
          className="mt-2 text-[11px] hover:underline"
          style={{ color: 'var(--accent-primary, #3b82f6)' }}
        >
          Show less
        </button>
      )}
    </div>
  );
}

export default ConfigPropertiesTable;
