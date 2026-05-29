'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { Zap, RefreshCw, Plus, AlertTriangle } from 'lucide-react';
import AccountCard from '@/components/accounts/AccountCard';
import OnboardingWizard from '@/components/domain/OnboardingWizard';
import { fetchView } from '@/lib/api';
import { useTenant } from '@/lib/tenant-context';

export default function AccountsPage() {
  const router = useRouter();
  const { activeTenant } = useTenant();
  const [accounts, setAccounts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState('');
  const [error, setError] = useState('');
  const [configuringAccount, setConfiguringAccount] = useState(null);

  const fetchAccounts = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const data = await fetchView('onboarding/cloud_accounts', { limit: 200 });
      if (data?.error) throw new Error(data.error);
      setAccounts(data?.accounts || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAccounts(); }, [fetchAccounts, activeTenant?.tenant_id]);

  const handleScanAllNow = async () => {
    setScanning(true);
    setScanMsg('');
    try {
      const resp = await fetch('/gateway/api/v1/schedules/run-all', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (!resp.ok) throw new Error(`Error ${resp.status}`);
      const data = await resp.json();
      const msg = `Submitted ${data.triggered ?? 0} scan(s)`;
      const warning = data.triggered < accounts.length ? ` (capped at ${data.cap})` : '';
      setScanMsg(msg + warning);
      setTimeout(() => { setScanMsg(''); fetchAccounts(); }, 4000);
    } catch (e) {
      setScanMsg(`Failed: ${e.message}`);
    } finally {
      setScanning(false);
    }
  };

  function handleConfigure(account) {
    setConfiguringAccount(account);
  }

  function handleConfigureComplete() {
    setConfiguringAccount(null);
    fetchAccounts();
  }

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
            Cloud Accounts
          </h1>
          <div className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {accounts.length} account{accounts.length !== 1 ? 's' : ''} connected
          </div>
        </div>

        <div className="flex items-center gap-2">
          {scanMsg && (
            <span
              className="text-xs px-2 py-1 rounded-lg"
              style={{
                backgroundColor: scanMsg.startsWith('Failed') ? 'rgba(239,68,68,0.12)' : 'rgba(34,197,94,0.12)',
                color: scanMsg.startsWith('Failed') ? '#f87171' : '#22c55e',
              }}
            >
              {scanMsg}
            </span>
          )}
          <button
            onClick={handleScanAllNow}
            disabled={scanning || accounts.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl disabled:opacity-40 hover:opacity-90 transition-opacity"
            style={{ backgroundColor: 'rgba(245,158,11,0.15)', color: '#fbbf24', border: '1px solid rgba(245,158,11,0.3)' }}
          >
            {scanning ? <RefreshCw size={13} className="animate-spin" /> : <Zap size={13} />}
            Scan All Now
          </button>
          <button
            onClick={() => router.push('/onboarding/wizard')}
            className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl hover:opacity-90 transition-opacity"
            style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
          >
            <Plus size={13} /> Add Account
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div
          className="flex items-center gap-2 p-3 rounded-xl border text-sm"
          style={{ borderColor: 'rgba(239,68,68,0.3)', backgroundColor: 'rgba(239,68,68,0.08)', color: '#f87171' }}
        >
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {/* Loading skeleton */}
      {loading && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-40 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && accounts.length === 0 && !error && (
        <div className="text-center py-16 space-y-3">
          <div className="text-4xl">☁️</div>
          <div className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>No accounts connected yet</div>
          <button
            onClick={() => router.push('/onboarding/wizard')}
            className="px-4 py-2 text-sm font-medium rounded-xl hover:opacity-90 transition-opacity"
            style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
          >
            Add your first account
          </button>
        </div>
      )}

      {/* Account grid */}
      {!loading && accounts.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {accounts.map(account => (
            <AccountCard
              key={account.accountId || account.account_id}
              account={account}
              onRefresh={fetchAccounts}
              onConfigure={handleConfigure}
            />
          ))}
        </div>
      )}

      {/* Capability configure wizard — opened when user clicks "Configure" on a dormant card */}
      {configuringAccount && (
        <OnboardingWizard
          initialConfig={{
            accountId:   configuringAccount.accountId,
            accountType: configuringAccount.account_type,
            accountName: configuringAccount.accountName,
            tenantId:    configuringAccount.tenantId,
          }}
          onComplete={handleConfigureComplete}
          onCancel={() => setConfiguringAccount(null)}
        />
      )}
    </div>
  );
}
