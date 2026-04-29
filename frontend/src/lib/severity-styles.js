/**
 * Severity style utilities that use CSS custom properties (design tokens)
 * rather than hardcoded hex values, enabling correct light/dark theme support.
 *
 * Supported levels: 'critical' | 'high' | 'medium' | 'low' | 'info'
 */

export const SEVERITY_TOKEN = {
  critical: 'var(--severity-critical)',
  high: 'var(--severity-high)',
  medium: 'var(--severity-medium)',
  low: 'var(--severity-low)',
  info: 'var(--severity-info)',
};

/**
 * Returns a style object with the correct text color for the given severity level.
 * @param {string} level - severity string (case-insensitive)
 * @returns {React.CSSProperties}
 */
export function getSeverityStyle(level) {
  return { color: SEVERITY_TOKEN[level?.toLowerCase()] || SEVERITY_TOKEN.info };
}

/**
 * Returns a full badge style object (color + bg + border + shape + typography)
 * suitable for inline `style=` on a <span> or <div>.
 * @param {string} level - severity string (case-insensitive)
 * @returns {React.CSSProperties}
 */
export function getSeverityBadge(level) {
  const key = level?.toLowerCase() ?? 'info';
  const color = SEVERITY_TOKEN[key] || SEVERITY_TOKEN.info;
  return {
    color,
    backgroundColor: color + '1a',   // 10 % opacity fill
    border: `1px solid ${color}4d`,   // 30 % opacity border
    borderRadius: 9999,
    padding: '2px 8px',
    fontSize: 11,
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    display: 'inline-block',
    lineHeight: 1.6,
  };
}

/**
 * Returns the dot/circle color for a severity indicator.
 * @param {string} level - severity string (case-insensitive)
 * @returns {string} CSS custom property reference
 */
export function getSeverityDotColor(level) {
  return SEVERITY_TOKEN[level?.toLowerCase()] || SEVERITY_TOKEN.info;
}
