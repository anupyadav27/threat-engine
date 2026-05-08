'use client';

import { useEffect, useState } from 'react';
import { CheckCircle, AlertTriangle, XCircle, Info, X } from 'lucide-react';
import { useToasts } from '@/lib/toast-context';

const ICONS = {
  success: <CheckCircle className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--accent-success)' }} />,
  error:   <XCircle    className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--accent-danger)' }} />,
  warning: <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--accent-warning)' }} />,
  info:    <Info       className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--accent-primary)' }} />,
};

const BORDER = {
  success: 'var(--accent-success)',
  error:   'var(--accent-danger)',
  warning: 'var(--accent-warning)',
  info:    'var(--accent-primary)',
};

function ToastItem({ toast, onRemove }) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    // Slight delay so CSS transition fires
    const t = setTimeout(() => setVisible(true), 10);
    return () => clearTimeout(t);
  }, []);

  const handleClose = () => {
    setVisible(false);
    setTimeout(() => onRemove(toast.id), 300);
  };

  return (
    <div
      role="alert"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '12px',
        padding: '14px 16px',
        borderRadius: '10px',
        backgroundColor: 'var(--bg-card)',
        border: `1px solid var(--border-primary)`,
        borderLeft: `4px solid ${BORDER[toast.type] || BORDER.info}`,
        boxShadow: '0 8px 24px rgba(0,0,0,0.35)',
        width: '360px',
        opacity: visible ? 1 : 0,
        transform: visible ? 'translateX(0)' : 'translateX(24px)',
        transition: 'opacity 0.3s ease, transform 0.3s ease',
        cursor: 'default',
      }}
    >
      {ICONS[toast.type] || ICONS.info}
      <span
        className="text-sm flex-1 leading-snug"
        style={{ color: 'var(--text-primary)' }}
      >
        {toast.message}
      </span>
      <button
        onClick={handleClose}
        style={{ color: 'var(--text-tertiary)', flexShrink: 0, marginTop: '1px' }}
        className="hover:opacity-70 transition-opacity"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
}

export default function ToastContainer() {
  const { toasts, removeToast } = useToasts();

  if (!toasts.length) return null;

  return (
    <div
      style={{
        position: 'fixed',
        bottom: '24px',
        right: '24px',
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: '10px',
        pointerEvents: 'none',
      }}
    >
      {toasts.map((t) => (
        <div key={t.id} style={{ pointerEvents: 'auto' }}>
          <ToastItem toast={t} onRemove={removeToast} />
        </div>
      ))}
    </div>
  );
}
