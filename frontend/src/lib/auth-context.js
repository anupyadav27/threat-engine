'use client';

import { createContext, useContext, useState, useEffect, useCallback } from 'react';

const AUTH_URL = process.env.NEXT_PUBLIC_AUTH_URL || process.env.NEXT_PUBLIC_API_BASE || '';

// ── Dev auth bypass ──────────────────────────────────────────────────────────
// When NEXT_PUBLIC_DEV_BYPASS_AUTH=true, skip Django auth entirely and inject
// a synthetic admin session. This survives HMR and page reloads because
// auth-context.js checks sessionStorage FIRST on every mount.
const DEV_BYPASS_AUTH = process.env.NEXT_PUBLIC_DEV_BYPASS_AUTH === 'true';
const DEV_TENANT_ID  = process.env.NEXT_PUBLIC_TENANT_ID || 'default-tenant';

const DEV_SESSION = {
  user: {
    id: 1,
    email: 'admin@cspm.local',
    first_name: 'Admin',
    last_name: 'User',
    name: 'Admin User',
    is_superuser: true,
    is_staff: true,
    role: 'platform_admin',
    roles: ['platform_admin'],
    tenants: [{ id: DEV_TENANT_ID, name: 'Default' }],
    selected_tenant: DEV_TENANT_ID,
    capabilities: [
      'view_dashboard', 'view_assets', 'view_threats', 'view_compliance',
      'view_iam', 'view_datasec', 'view_scans', 'create_scans', 'manage_tenants',
      'manage_users', 'manage_rules', 'manage_policies', 'view_risk',
    ],
    permissions: [
      'view_dashboard', 'view_assets', 'view_threats', 'view_compliance',
      'view_iam', 'view_datasec', 'view_scans', 'create_scans', 'manage_tenants',
      'manage_users', 'manage_rules', 'manage_policies', 'view_risk',
    ],
  },
  role: 'platform_admin',
  roles: ['platform_admin'],
  tenants: [{ id: DEV_TENANT_ID, name: 'Default' }],
  selectedTenant: DEV_TENANT_ID,
  capabilities: [
    'view_dashboard', 'view_assets', 'view_threats', 'view_compliance',
    'view_iam', 'view_datasec', 'view_scans', 'create_scans', 'manage_tenants',
    'manage_users', 'manage_rules', 'manage_policies', 'view_risk',
  ],
};

const AuthContext = createContext({
  user: null,
  role: null,
  roles: [],
  isAuthenticated: false,
  tenants: [],
  selectedTenant: null,
  capabilities: [],
  isLoading: false,
  isInitialized: false,
  login: async () => {},
  logout: () => {},
  refreshSession: async () => {},
  switchTenant: async () => {},
  setUser: () => {},
});

export function AuthProvider({ children }) {
  const [user, setUserState] = useState(null);
  const [role, setRole] = useState(null);
  const [roles, setRoles] = useState([]);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [tenants, setTenants] = useState([]);
  const [selectedTenant, setSelectedTenant] = useState(null);
  const [capabilities, setCapabilities] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);

  const applySession = useCallback((data) => {
    const u = data.user || data;
    setUserState(u);
    setRole(u.role || u.roles?.[0] || 'user');
    setRoles(u.roles || [u.role || 'user']);
    setIsAuthenticated(true);
    setTenants(u.tenants || []);
    setSelectedTenant(u.selected_tenant || u.tenants?.[0]?.id || null);
    setCapabilities(u.capabilities || u.permissions || [
      'view_dashboard', 'view_assets', 'view_threats', 'view_compliance',
      'view_iam', 'view_datasec', 'view_scans', 'create_scans', 'manage_tenants',
    ]);

    const session = {
      user: u,
      role: u.role || u.roles?.[0] || 'user',
      roles: u.roles || [u.role || 'user'],
      tenants: u.tenants || [],
      selectedTenant: u.selected_tenant || u.tenants?.[0]?.id || null,
      capabilities: u.capabilities || u.permissions || [],
    };
    sessionStorage.setItem('auth_session', JSON.stringify(session));
  }, []);

  // Restore session on mount — auto-login for dev (bypass Cognito)
  useEffect(() => {
    const restoreSession = async () => {
      try {
        // ── Dev bypass: inject synthetic session immediately ───────────
        if (DEV_BYPASS_AUTH) {
          console.info('[auth] DEV_BYPASS_AUTH enabled — using synthetic admin session');
          sessionStorage.setItem('auth_session', JSON.stringify(DEV_SESSION));
          setUserState(DEV_SESSION.user);
          setRole(DEV_SESSION.role);
          setRoles(DEV_SESSION.roles);
          setIsAuthenticated(true);
          setTenants(DEV_SESSION.tenants);
          setSelectedTenant(DEV_SESSION.selectedTenant);
          setCapabilities(DEV_SESSION.capabilities);
          setIsInitialized(true);
          return;
        }

        // First check sessionStorage
        const stored = sessionStorage.getItem('auth_session');
        if (stored) {
          const session = JSON.parse(stored);
          setUserState(session.user);
          setRole(session.role);
          setRoles(session.roles || []);
          setIsAuthenticated(true);
          setTenants(session.tenants || []);
          setSelectedTenant(session.selectedTenant);
          setCapabilities(session.capabilities || []);
          setIsInitialized(true);
          return;
        }

        // Try to get current user from backend (cookie-based auth)
        const res = await fetch(`${AUTH_URL}/api/auth/me/`, {
          credentials: 'include',
        });
        if (res.ok) {
          const data = await res.json();
          applySession(data);
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
          // cspm-backend returns { message, expiresIn, user: { id, email, name, roles } }
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
    setRoles([]);
    setIsAuthenticated(false);
    setTenants([]);
    setSelectedTenant(null);
    setCapabilities([]);
    sessionStorage.removeItem('auth_session');
  }, []);

  const refreshSession = useCallback(async () => {
    try {
      const res = await fetch(`${AUTH_URL}/api/auth/me/`, {
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

  const value = {
    user,
    role,
    roles,
    isAuthenticated,
    tenants,
    selectedTenant,
    capabilities,
    isLoading,
    isInitialized,
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
