'use client';

import { createContext, useContext, useState, useCallback } from 'react';

const ToastContext = createContext(null);

let _toastId = 0;

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);

  const addToast = useCallback(({ message, type = 'info', duration = 4000 }) => {
    const id = ++_toastId;
    setToasts((prev) => [...prev, { id, message, type, duration }]);
    setTimeout(() => removeToast(id), duration);
    return id;
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = {
    success: (message, opts) => addToast({ message, type: 'success', ...opts }),
    error:   (message, opts) => addToast({ message, type: 'error',   ...opts }),
    warning: (message, opts) => addToast({ message, type: 'warning', ...opts }),
    info:    (message, opts) => addToast({ message, type: 'info',    ...opts }),
  };

  return (
    <ToastContext.Provider value={{ toast, toasts, removeToast }}>
      {children}
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside ToastProvider');
  return ctx.toast;
}

export function useToasts() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToasts must be used inside ToastProvider');
  return { toasts: ctx.toasts, removeToast: ctx.removeToast };
}
