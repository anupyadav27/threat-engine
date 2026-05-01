'use client';

import { useEffect } from 'react';

export default function ErrorPage({ error, reset }) {
  useEffect(() => {
    console.error('[CSPM Error]', error);
  }, [error]);

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: '#020617',
        color: '#f8fafc',
        fontFamily: 'monospace',
        padding: '2rem',
        gap: '1.5rem',
      }}
    >
      <div style={{ fontSize: '2rem' }}>⚠</div>
      <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f87171', margin: 0 }}>
        Page Error
      </h1>
      <div
        style={{
          maxWidth: 640,
          backgroundColor: '#0f172a',
          border: '1px solid #1e293b',
          borderRadius: 8,
          padding: '1rem',
          fontSize: '0.8rem',
          lineHeight: 1.6,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
          color: '#fbbf24',
        }}
      >
        <strong style={{ color: '#f87171' }}>{error?.name || 'Error'}: </strong>
        {error?.message || 'An unknown error occurred'}
        {'\n\n'}
        {error?.stack?.split('\n').slice(1, 6).join('\n')}
      </div>
      <button
        onClick={reset}
        style={{
          padding: '0.5rem 1.5rem',
          backgroundColor: '#3b82f6',
          color: '#fff',
          border: 'none',
          borderRadius: 6,
          cursor: 'pointer',
          fontSize: '0.875rem',
          fontWeight: 600,
        }}
      >
        Try again
      </button>
    </div>
  );
}
