'use client';

import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { FALLBACK_VIEWER_PERMISSIONS } from './permission-constants';

const AUTH_URL = process.env.NEXT_PUBLIC_AUTH_URL || process.env.NEXT_PUBLIC_API_BASE || '';

const AuthContext = createContext({
  user: null,
  role: null,
  level: 0,
  roles: [],
  isAuthenticated: false,
  tenants: [],
  selectedTenant: null,
  customerId: null,
  permissions: [],
  isLoading: false,
  isInitialized: false,
  hasPermission: () => false,
  login: async () => {},
  logout: () => {},
  refreshSession: async () => {},
  switchTenant: async () => {},
  setUser: () => {},
});

export function AuthProvider({ children }) {
  const [user, setUserState] = useState(null);
  const [role, setRole] = useState(null);
  const [level, setLevel] = useState(0);
  const [roles, setRoles] = useState([]);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [tenants, setTenants] = useState([]);
  const [selectedTenant, setSelectedTenant] = useState(null);
  const [customerId, setCustomerId] = useState(null);
  const [permissions, setPermissions] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);

  /**
   * Derive permissions from the /me response.
   * The API returns `user.permissions` as the canonical list (RBAC-03).
   * If the array is empty (legacy session), fall back to the basic viewer set
   * so the user still sees a usable shell without erroring.
   */
  const resolvePermissions = useCallback((u) => {
    const raw = u.permissions;
    if (Array.isArray(raw) && raw.length > 0) return raw;
    return FALLBACK_VIEWER_PERMISSIONS;
  }, []);

  const applySession = useCallback((data) => {
    const u = data.user || data;
    const resolvedPermissions = resolvePermissions(u);

    // platform_admin (level 1) defaults to null = "All Tenants".
    // All other roles default to their first tenant.
    const isPlatformAdmin = (u.level ?? 0) === 1;
    const rawTenantId = u.selected_tenant
      || u.tenants?.[0]?.engine_tenant_id
      || u.tenants?.[0]?.tenant_id
      || u.tenants?.[0]?.id
      || null;

    // Preserve a mid-session tenant switch across /me re-validations.
    // storedSelection !== undefined means the user already made a choice
    // (including explicitly choosing null = All Tenants).
    let finalTenantId;
    try {
      const stored = sessionStorage.getItem('auth_session');
      if (stored !== null) {
        const parsed = JSON.parse(stored);
        // "storedSelection" key is present (even as null) → honour it
        finalTenantId = 'selectedTenant' in parsed
          ? parsed.selectedTenant
          : (isPlatformAdmin ? null : rawTenantId);
      } else {
        finalTenantId = isPlatformAdmin ? null : rawTenantId;
      }
    } catch {
      finalTenantId = isPlatformAdmin ? null : rawTenantId;
    }

    setUserState(u);
    setRole(u.role || u.roles?.[0] || 'user');
    setLevel(u.level ?? 0);
    setRoles(u.roles || [u.role || 'user']);
    setIsAuthenticated(true);
    setTenants(u.tenants || []);
    setSelectedTenant(finalTenantId);
    setCustomerId(u.customer_id || u.id || null);
    setPermissions(resolvedPermissions);

    // Persist to sessionStorage (in-memory tab storage only — not localStorage,
    // so permissions cannot be tampered with across tabs or page refreshes
    // without re-validating against the backend).
    const session = {
      user: u,
      role: u.role || u.roles?.[0] || 'user',
      level: u.level ?? 0,
      roles: u.roles || [u.role || 'user'],
      tenants: u.tenants || [],
      selectedTenant: finalTenantId,
      customerId: u.customer_id || u.id || null,
      permissions: resolvedPermissions,
    };
    sessionStorage.setItem('auth_session', JSON.stringify(session));
  }, [resolvePermissions]);

  // Restore session on mount — always validates against the backend
  // to pick up any permission changes that happened since the tab was opened.
  useEffect(() => {
    const restoreSession = async () => {
      try {
        // Optimistically restore from sessionStorage to avoid flash of
        // unauthenticated content while the /me round-trip is in flight.
        const stored = sessionStorage.getItem('auth_session');
        if (stored) {
          const session = JSON.parse(stored);
          setUserState(session.user);
          setRole(session.role);
          setLevel(session.level ?? 0);
          setRoles(session.roles || []);
          setIsAuthenticated(true);
          setTenants(session.tenants || []);
          // Normalize: if stored selectedTenant is a Django UUID, resolve to engine_tenant_id
          const storedTenantId = session.selectedTenant;
          const tenantList = session.tenants || [];
          const resolvedTenant = storedTenantId
            ? (tenantList.find(t => t.engine_tenant_id === storedTenantId)?.engine_tenant_id
               || tenantList.find(t => t.tenant_id === storedTenantId)?.engine_tenant_id
               || storedTenantId)
            : null;
          setSelectedTenant(resolvedTenant);
          setCustomerId(session.customerId || null);
          setPermissions(session.permissions || FALLBACK_VIEWER_PERMISSIONS);
          setIsInitialized(true);
          // Fall through — still refresh from backend so stale permissions
          // are replaced with the latest set.
        }

        // Always re-validate with the backend.  This ensures that if the
        // admin changed a user's role/permissions, the next page load picks it up.
        const res = await fetch(`${AUTH_URL}/api/auth/me`, {
          credentials: 'include',
        });
        if (res.ok) {
          const data = await res.json();
          applySession(data);
        } else if (!stored) {
          // No stored session AND /me failed → not authenticated
          setIsInitialized(true);
        }
      } catch (error) {
        console.error('Failed to restore session:', error);
      } finally {
        setIsInitialized(true);
      }
    };

    restoreSession();
  }, [applySession]);

  const login = useCallback(
    async (email, password, rememberMe = false) => {
      setIsLoading(true);
      try {
        // Fetch CSRF token first (required by Django)
        await fetch(`${AUTH_URL}/api/auth/csrf/`, { credentials: 'include' }).catch(() => {});

        const res = await fetch(`${AUTH_URL}/api/auth/login/`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ email, password, rememberMe }),
        });

        const data = await res.json();

        if (res.ok) {
          // cspm-backend returns { message, expiresIn, user: { id, email, name, roles, permissions } }
          applySession(data);
          return { success: true };
        }

        // Handle specific error codes
        switch (res.status) {
          case 400:
            return { success: false, error: data.message || 'Email and password are required' };
          case 401:
            return { success: false, error: data.message || 'Incorrect password. Please try again.' };
          case 404:
            return { success: false, error: data.message || 'No account found for that email.' };
          case 429:
            return { success: false, error: 'Too many login attempts. Please try again later.' };
          default:
            return { success: false, error: data.message || 'Login failed. Please try again.' };
        }
      } catch (error) {
        console.error('Login failed:', error);
        return { success: false, error: 'Cannot reach the authentication server. Check your network or VPN.' };
      } finally {
        setIsLoading(false);
      }
    },
    [applySession]
  );

  const logout = useCallback(async () => {
    try {
      await fetch(`${AUTH_URL}/api/auth/logout/`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch (e) {
      // Ignore logout API errors
    }
    setUserState(null);
    setRole(null);
    setLevel(0);
    setRoles([]);
    setIsAuthenticated(false);
    setTenants([]);
    setSelectedTenant(null);
    setPermissions([]);
    sessionStorage.removeItem('auth_session');
  }, []);

  const refreshSession = useCallback(async () => {
    try {
      const res = await fetch(`${AUTH_URL}/api/auth/me`, {
        credentials: 'include',
      });
      if (res.ok) {
        const data = await res.json();
        applySession(data);
        return { success: true };
      }
    } catch (error) {
      console.error('Session refresh failed:', error);
    }
    setIsInitialized(true);
    return { success: false };
  }, [applySession]);

  const switchTenant = useCallback(async (tenantId) => {
    setIsLoading(true);
    try {
      setSelectedTenant(tenantId);
      const session = sessionStorage.getItem('auth_session');
      if (session) {
        const parsed = JSON.parse(session);
        parsed.selectedTenant = tenantId;
        sessionStorage.setItem('auth_session', JSON.stringify(parsed));
      }
      return { success: true };
    } catch (error) {
      console.error('Tenant switch failed:', error);
      return { success: false, error: error.message };
    } finally {
      setIsLoading(false);
    }
  }, []);

  const setUser = useCallback((newUser) => {
    setUserState(newUser);
    const session = sessionStorage.getItem('auth_session');
    if (session) {
      const parsed = JSON.parse(session);
      parsed.user = newUser;
      sessionStorage.setItem('auth_session', JSON.stringify(parsed));
    }
  }, []);

  /**
   * Convenience method — checks whether the current session includes a
   * specific permission key.  Sourced entirely from the API response;
   * never reads localStorage or URL params.
   *
   * @param {string|null} key - Permission key, e.g. 'threat:read'
   * @returns {boolean}
   */
  const checkHasPermission = useCallback((key) => {
    if (!key) return true;
    if (!permissions || permissions.length === 0) return false;
    return permissions.includes(key);
  }, [permissions]);

  const value = {
    user,
    role,
    level,
    roles,
    isAuthenticated,
    tenants,
    selectedTenant,
    customerId,
    permissions,
    isLoading,
    isInitialized,
    hasPermission: checkHasPermission,
    login,
    logout,
    refreshSession,
    switchTenant,
    setUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
