'use client';

/**
 * EmptyState component for displaying when no data is available.
 *
 * @component
 * @param {Object} props - Component props
 * @param {JSX.Element} [props.icon] - Optional icon element
 * @param {string} props.title - Empty state title
 * @param {string} props.description - Empty state description
 * @param {Object} [props.action] - Optional action button
 * @param {string} props.action.label - Button label
 * @param {Function} props.action.onClick - Button click handler
 * @returns {JSX.Element}
 */
export default function EmptyState({ icon, title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4">
      {icon && <div style={{ color: 'var(--text-tertiary)' }} className="w-12 h-12 mb-4">{icon}</div>}

      <h3 style={{ color: 'var(--text-tertiary)' }} className="text-lg font-medium mb-2">{title}</h3>

      <p style={{ color: 'var(--text-muted)' }} className="text-sm text-center max-w-md mb-6">{description}</p>

      {action && (
        <button
          onClick={action.onClick}
          className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
          style={{ '--tw-ring-offset-color': 'var(--bg-primary)' }}
        >
          {action.label}
        </button>
      )}
    </div>
  );
}
