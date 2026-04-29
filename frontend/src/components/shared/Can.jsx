'use client';

import { useAuth } from '@/lib/auth-context';

/**
 * Permission wrapper component
 * Renders children if user has the required capability
 */
export default function Can({ capability, children, fallback = null }) {
  const { capabilities } = useAuth();

  const hasPermission =
    capabilities && Array.isArray(capabilities) && capabilities.includes(capability);

  if (hasPermission) {
    return children;
  }

  return fallback;
}
