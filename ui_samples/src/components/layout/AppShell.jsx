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
  const isSecOpsOverview = SECOPS_OVERVIEW_PAGES.includes(pathname);
  const isSecOpsRoute    = pathname.startsWith('/secops');

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
    <div className="flex">
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(p => !p)} />
      <div
        className="flex-1 flex flex-col min-h-screen"
        style={{ marginLeft: 'var(--sidebar-width, 240px)', transition: 'margin-left 200ms ease' }}
      >
        <Header />
        {isSecOpsOverview
          ? <SecOpsFilterBar />
          : !isSecOpsRoute
            ? <GlobalFilterBar />
            : null   /* detail pages: no global bar, page has its own filters */
        }
        <main
          className="flex-1 px-0 pt-0 pb-6 transition-colors duration-200"
          style={{ backgroundColor: 'var(--bg-primary)' }}
        >
          {children}
        </main>
      </div>
    </div>
    </SecOpsFilterProvider>
  );
}
