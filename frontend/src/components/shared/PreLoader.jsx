'use client';

import { Shield } from 'lucide-react';

export default function PreLoader() {
  return (
    <div
      className="fixed inset-0 flex items-center justify-center"
      style={{
        backgroundColor: 'var(--bg-primary)',
      }}
    >
      <div className="flex flex-col items-center gap-6">
        {/* Animated Shield Icon */}
        <div className="relative w-24 h-24">
          <Shield
            size={96}
            className="absolute inset-0 animate-pulse"
            style={{
              color: 'var(--text-primary)',
            }}
          />
          {/* Spinning ring */}
          <div
            className="absolute inset-0 rounded-full border-4 border-transparent"
            style={{
              borderTopColor: 'var(--text-primary)',
              animation: 'spin 2s linear infinite',
            }}
          />
        </div>

        {/* Brand Text */}
        <div className="text-center">
          <h1
            className="text-4xl font-bold tracking-tight mb-2"
            style={{
              color: 'var(--text-primary)',
            }}
          >
            THREAT ENGINE
          </h1>
          <p
            className="text-sm font-medium"
            style={{
              color: 'var(--text-secondary)',
            }}
          >
            Initializing Security Platform...
          </p>
        </div>
      </div>

      <style jsx>{`
        @keyframes spin {
          to {
            transform: rotate(360deg);
          }
        }
      `}</style>
    </div>
  );
}
