'use client';

import { useAuth } from '@/lib/auth-context';

/**
 * Permission wrapper component.
 * Renders children if the current user holds the required permission key.
 * Permission data is sourced from the /api/auth/me response (API-driven).
 *
 * @param {string} capability - Canonical permission key e.g. 'threat:read'
 * @param {React.ReactNode} children
 * @param {React.ReactNode} fallback - Rendered when permission is absent (default: null)
 */
export default function Can({ capability, children, fallback = null }) {
  const { hasPermission } = useAuth();

  if (hasPermission(capability)) {
    return children;
  }

  return fallback;
}
