'use client';

import { useEffect, useRef } from 'react';
import { useAuth } from '@/lib/auth-context';
import { ShieldAlert } from 'lucide-react';

/**
 * TenantScopeGuard — prevents cross-tenant data leaks by validating that the
 * current selectedTenant matches what the authenticated user is allowed to access.
 *
 * Renders children when the tenant is valid.
 * Shows a warning and resets to the user's primary tenant when a mismatch is detected.
 */
export default function TenantScopeGuard({ children }) {
  const { user, selectedTenant, tenants, setSelectedTenant } = useAuth();
  const warnedRef = useRef(false);

  useEffect(() => {
    if (!user || !selectedTenant || !tenants?.length) return;

    const allowedIds = tenants.map(t => t.engine_tenant_id || t.id || t.tenant_id).filter(Boolean);
    if (allowedIds.length === 0) return;

    if (!allowedIds.includes(selectedTenant)) {
      if (!warnedRef.current) {
        warnedRef.current = true;
        console.warn('[TenantScopeGuard] selectedTenant not in allowed list — resetting to primary');
      }
      // Reset to first allowed tenant
      setSelectedTenant?.(allowedIds[0]);
    } else {
      warnedRef.current = false;
    }
  }, [user, selectedTenant, tenants, setSelectedTenant]);

  // If auth context is still loading, don't block rendering
  if (!user) return children;

  // Validate scope synchronously for the render
  if (selectedTenant && tenants?.length > 0) {
    const allowedIds = tenants.map(t => t.engine_tenant_id || t.id || t.tenant_id).filter(Boolean);
    if (allowedIds.length > 0 && !allowedIds.includes(selectedTenant)) {
      return (
        <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
          <ShieldAlert className="w-10 h-10 mb-3" style={{ color: '#f59e0b' }} />
          <h3 className="text-base font-semibold mb-1" style={{ color: 'var(--text-primary)' }}>
            Tenant Access Denied
          </h3>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            You do not have access to this tenant. Resetting to your primary tenant.
          </p>
        </div>
      );
    }
  }

  return children;
}
