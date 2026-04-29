'use client';

import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import Sidebar from './Sidebar';
import Header from './Header';
import GlobalFilterBar from './GlobalFilterBar';
import SecOpsFilterBar from './SecOpsFilterBar';
import PreLoader from '@/components/shared/PreLoader';
import { useAuth } from '@/lib/auth-context';
import { SecOpsFilterProvider } from '@/lib/secops-filter-context';

export default function AppShell({ children }) {
  const pathname = usePathname();
  const router = useRouter();
  const { isInitialized, isAuthenticated } = useAuth();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Check if current route is an auth route
  const isAuthRoute = pathname.startsWith('/auth/');

  // SecOps overview pages: show the scan-oriented filter bar
  // Detail pages (/secops/<uuid>, /secops/dast/<id>, /secops/sca/<id>, etc.)
  // have their own in-page filters and the global bar adds no value there.
  const SECOPS_OVERVIEW_PAGES = ['/secops', '/secops/projects', '/secops/reports'];
  const isSecOpsOverview    = SECOPS_OVERVIEW_PAGES.includes(pathname);
  const isSecOpsRoute       = pathname.startsWith('/secops');
  // Vulnerability pages have their own agent-scoped filters — skip the global bar
  const isVulnerabilityRoute = pathname.startsWith('/vulnerability');

  // Redirect to login if not authenticated and not on auth route
  useEffect(() => {
    if (isInitialized && !isAuthenticated && !isAuthRoute) {
      router.push('/auth/login');
    }
  }, [isInitialized, isAuthenticated, isAuthRoute, router]);

  // Show preloader while initializing
  if (!isInitialized) {
    return <PreLoader />;
  }

  // Auth pages don't need sidebar/header
  if (isAuthRoute) {
    return children;
  }

  // Main app layout with sidebar and header
  return (
    <SecOpsFilterProvider>
    <div className="flex" style={{ minHeight: '100vh', backgroundColor: 'var(--bg-primary)' }}>
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(p => !p)} />
      <div
        className="flex-1 flex flex-col min-h-screen min-w-0 overflow-x-hidden"
        style={{
          marginLeft: 'var(--sidebar-width, 240px)',
          width: 'calc(100vw - var(--sidebar-width, 240px))',
          transition: 'margin-left 200ms ease, width 200ms ease',
        }}
      >
        <Header />
        {isSecOpsOverview
          ? <SecOpsFilterBar />
          : (!isSecOpsRoute && !isVulnerabilityRoute)
            ? <GlobalFilterBar />
            : null   /* detail/vulnerability pages: no global bar, pages have their own filters */
        }
        <main
          className="flex-1 p-6 transition-colors duration-200 min-w-0 overflow-x-hidden"
          style={{ backgroundColor: 'var(--bg-primary)' }}
        >
          {children}
        </main>
      </div>
    </div>
    </SecOpsFilterProvider>
  );
}
