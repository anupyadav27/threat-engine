'use client';

import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import Sidebar from './Sidebar';
import Header from './Header';
import GlobalFilterBar from './GlobalFilterBar';
import SecOpsFilterBar from './SecOpsFilterBar';
import PreLoader from '@/components/shared/PreLoader';
import { useAuth } from '@/lib/auth-context';

export default function AppShell({ children }) {
  const pathname = usePathname();
  const router = useRouter();
  const { isInitialized, isAuthenticated } = useAuth();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Check if current route is an auth route
  const isAuthRoute   = pathname.startsWith('/auth/');
  // SecOps pages use their own scan-specific filters, not cloud CSPM scope
  const isSecOpsRoute = pathname.startsWith('/secops');

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
    <div className="flex">
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(p => !p)} />
      <div
        className="flex-1 flex flex-col min-h-screen"
        style={{ marginLeft: 'var(--sidebar-width, 240px)', transition: 'margin-left 200ms ease' }}
      >
        <Header />
        {isSecOpsRoute ? <SecOpsFilterBar /> : <GlobalFilterBar />}
        <main
          className="flex-1 p-6 transition-colors duration-200"
          style={{ backgroundColor: 'var(--bg-primary)' }}
        >
          {children}
        </main>
      </div>
    </div>
  );
}
