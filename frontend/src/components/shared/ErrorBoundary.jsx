'use client';

import { Component } from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    if (process.env.NODE_ENV !== 'production') {
      console.error('[ErrorBoundary]', error, info.componentStack);
    }
  }

  reset() {
    this.setState({ hasError: false, error: null });
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    const { fallback, title = 'Something went wrong', compact = false } = this.props;

    if (fallback) return fallback;

    if (compact) {
      return (
        <div
          className="flex items-center gap-2 rounded-lg px-4 py-3 text-sm"
          style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#f87171', border: '1px solid rgba(239,68,68,0.2)' }}
        >
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{title}</span>
          <button
            onClick={() => this.reset()}
            className="ml-auto flex items-center gap-1 text-xs underline opacity-70 hover:opacity-100"
          >
            <RefreshCw className="w-3 h-3" /> Retry
          </button>
        </div>
      );
    }

    return (
      <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
        <AlertCircle className="w-10 h-10 mb-3" style={{ color: '#f87171' }} />
        <h3 className="text-base font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>{title}</h3>
        <p className="text-sm mb-4" style={{ color: 'var(--text-secondary)' }}>
          {this.state.error?.message || 'An unexpected error occurred. The engine may be unavailable.'}
        </p>
        <button
          onClick={() => this.reset()}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
          style={{ backgroundColor: 'var(--accent-primary)' }}
        >
          <RefreshCw className="w-4 h-4" /> Retry
        </button>
      </div>
    );
  }
}

export function withErrorBoundary(Component, boundaryProps = {}) {
  return function WrappedWithErrorBoundary(props) {
    return (
      <ErrorBoundary {...boundaryProps}>
        <Component {...props} />
      </ErrorBoundary>
    );
  };
}
