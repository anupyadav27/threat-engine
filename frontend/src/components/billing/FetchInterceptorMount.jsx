'use client';

import { useEffect } from 'react';
import { registerFetchInterceptor } from '@/lib/fetchInterceptor';

/**
 * Thin client component that registers the global 402 fetch interceptor
 * once the browser environment is available.
 *
 * Rendered inside RootLayout (a server component) — this wrapper provides
 * the client boundary needed to call useEffect.
 *
 * The interceptor is idempotent: calling registerFetchInterceptor() more
 * than once is safe (guarded by window.__fetchInterceptorRegistered).
 */
export default function FetchInterceptorMount() {
  useEffect(() => {
    registerFetchInterceptor();
  }, []);

  return null;
}
