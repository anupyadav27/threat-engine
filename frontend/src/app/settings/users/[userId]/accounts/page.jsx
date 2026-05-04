'use client';

import { useState, useEffect, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { fetchFromCspm } from '@/lib/api';
import { useTenant } from '@/lib/tenant-context';
import { useToast } from '@/lib/toast-context';
import { ArrowLeft, Shield, CheckCircle2, XCircle, Loader2 } from 'lucide-react';

const PROVIDER_COLORS = {
  aws:   { bg: 'bg-orange-500/10', text: 'text-orange-400', label: 'AWS' },
  azure: { bg: 'bg-blue-500/10',   text: 'text-blue-400',   label: 'Azure' },
  gcp:   { bg: 'bg-green-500/10',  text: 'text-green-400',  label: 'GCP' },
  oci:   { bg: 'bg-red-500/10',    text: 'text-red-400',    label: 'OCI' },
};

export default function UserAccountAccessPage() {
  const { userId } = useParams();
  const router = useRouter();
  const { activeTenant } = useTenant();
  const { showToast } = useToast();

  const [data, setData]         = useState(null);
  const [loading, setLoading]   = useState(true);
  const [saving, setSaving]     = useState(false);
  const [grants, setGrants]     = useState({});   // { account_id: bool }

  const tenantId = activeTenant?.tenant_id;

  const load = useCallback(async () => {
    if (!tenantId || !userId) return;
    setLoading(true);
    try {
      const res = await fetchFromCspm(
        `/api/users/${userId}/accounts/?tenant_id=${tenantId}`,
      );
      setData(res);
      const init = {};
      (res.accounts || []).forEach(a => { init[a.account_id] = a.granted; });
      setGrants(init);
    } catch (e) {
      showToast('Failed to load account access', 'error');
    } finally {
      setLoading(false);
    }
  }, [userId, tenantId]);

  useEffect(() => { load(); }, [load]);

  const toggle = (accountId) => {
    setGrants(prev => ({ ...prev, [accountId]: !prev[accountId] }));
  };

  const save = async () => {
    setSaving(true);
    try {
      const grantedIds = Object.entries(grants)
        .filter(([, v]) => v)
        .map(([k]) => k);
      await fetchFromCspm(`/api/users/${userId}/accounts/`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenant_id: tenantId, account_ids: grantedIds }),
      });
      showToast('Account access updated', 'success');
      await load();
    } catch (e) {
      showToast('Failed to save changes', 'error');
    } finally {
      setSaving(false);
    }
  };

  const grantedCount = Object.values(grants).filter(Boolean).length;
  const totalCount   = data?.accounts?.length ?? 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-slate-400">
        <Loader2 className="animate-spin mr-2 w-5 h-5" />
        Loading account access…
      </div>
    );
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <button
          onClick={() => router.push('/settings/users')}
          className="text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div>
          <h1 className="text-xl font-semibold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" />
            Account Access
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">
            {data?.user_email || userId} — {grantedCount} of {totalCount} accounts granted
          </p>
        </div>
      </div>

      {/* Info banner */}
      <div className="bg-slate-800/60 border border-slate-700 rounded-lg p-4 mb-6 text-sm text-slate-300">
        When account access is restricted, this user only sees findings from the granted accounts.
        If no accounts are granted, the user has unrestricted access to all tenant accounts.
      </div>

      {/* Account list */}
      {totalCount === 0 ? (
        <div className="text-slate-400 text-center py-16">
          No cloud accounts found for this tenant.
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-700 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-slate-400 text-left">
                <th className="px-4 py-3 font-medium">Account</th>
                <th className="px-4 py-3 font-medium">Provider</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium text-right">Access</th>
              </tr>
            </thead>
            <tbody>
              {(data?.accounts || []).map((acct) => {
                const granted = grants[acct.account_id] ?? false;
                const pc = PROVIDER_COLORS[acct.provider?.toLowerCase()] || {
                  bg: 'bg-slate-500/10', text: 'text-slate-400', label: acct.provider || '—',
                };
                return (
                  <tr
                    key={acct.account_id}
                    className="border-b border-slate-800 hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="px-4 py-3">
                      <div className="font-medium text-white">{acct.account_name}</div>
                      <div className="text-xs text-slate-500 font-mono">{acct.account_id}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${pc.bg} ${pc.text}`}>
                        {pc.label}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 capitalize">{acct.status}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => toggle(acct.account_id)}
                        className={`flex items-center gap-1.5 ml-auto px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                          granted
                            ? 'bg-green-500/20 text-green-400 hover:bg-red-500/20 hover:text-red-400'
                            : 'bg-slate-700 text-slate-400 hover:bg-green-500/20 hover:text-green-400'
                        }`}
                      >
                        {granted ? (
                          <><CheckCircle2 className="w-3.5 h-3.5" /> Granted</>
                        ) : (
                          <><XCircle className="w-3.5 h-3.5" /> Not granted</>
                        )}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Save bar */}
      <div className="flex justify-end gap-3 mt-6">
        <button
          onClick={() => router.push('/settings/users')}
          className="px-4 py-2 rounded-lg bg-slate-700 text-slate-300 hover:bg-slate-600 text-sm transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={save}
          disabled={saving}
          className="px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {saving && <Loader2 className="animate-spin w-4 h-4" />}
          Save changes
        </button>
      </div>
    </div>
  );
}
