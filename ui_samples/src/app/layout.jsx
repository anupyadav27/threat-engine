import './globals.css';
import AppShell from '@/components/layout/AppShell';
import { ThemeProvider } from '@/lib/theme-context';
import { AuthProvider } from '@/lib/auth-context';
import { ToastProvider } from '@/lib/toast-context';
import { GlobalFilterProvider } from '@/lib/global-filter-context';
import { SavedFiltersProvider } from '@/lib/saved-filters-context';
import ToastContainer from '@/components/shared/Toast';

export const metadata = {
  title: 'Threat Engine CSPM',
  description: 'Cloud Security Posture Management Platform',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Synchronous theme script — runs before first paint to prevent FOUC */}
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem('cspm-theme')||'dark';document.documentElement.classList.add(t)}catch(e){document.documentElement.classList.add('dark')}})()`,
          }}
        />
      </head>
      <body className="min-h-screen font-sans antialiased" suppressHydrationWarning>
        <ThemeProvider>
          <AuthProvider>
            <ToastProvider>
              <GlobalFilterProvider>
                <SavedFiltersProvider>
                  <AppShell>{children}</AppShell>
                </SavedFiltersProvider>
              </GlobalFilterProvider>
              <ToastContainer />
            </ToastProvider>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
