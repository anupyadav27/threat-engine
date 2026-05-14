'use client';

import { useState, useEffect } from 'react';
import { X, Users, Building, Server } from 'lucide-react';
import { fetchView, deleteFromEngine } from '@/lib/api';

const TABS = [
  { id: 'members',  label: 'Members',  Icon: Users },
  { id: 'tenants',  label: 'Tenants',  Icon: Building },
  { id: 'accounts', label: 'Accounts', Icon: Server },
];

export default function EditGroupDrawer({ group, onClose, onSaved }) {
  const [tab, setTab] = useState('members');
  const [data, setData] = useState({ members: [], tenants: [], accounts: [] });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!group?.id) return;
    setLoading(true);
    fetchView(`settings/groups/${group.id}`)
      .then(d => setData(d || { members: [], tenants: [], accounts: [] }))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [group?.id]);

  const removeMember = async (userId) => {
    await deleteFromEngine('gateway', `/api/v1/groups/${group.id}/members/${userId}/`);
    setData(d => ({ ...d, members: d.members.filter(m => m.id !== userId) }));
    onSaved?.();
  };

  const items = data[tab] || [];

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="relative w-full max-w-md h-full flex flex-col shadow-2xl"
        style={{ backgroundColor: 'var(--bg-card)', borderLeft: '1px solid var(--border-primary)' }}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div>
            <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>{group?.name}</h2>
            <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>Group details</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/5 transition-colors">
            <X className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b px-5" style={{ borderColor: 'var(--border-primary)' }}>
          {TABS.map(({ id, label, Icon }) => (
            <button key={id} onClick={() => setTab(id)}
              className={`flex items-center gap-1.5 px-3 py-3 text-sm font-medium border-b-2 transition-colors ${
                tab === id ? 'border-blue-500 text-blue-400' : 'border-transparent'
              }`}
              style={tab !== id ? { color: 'var(--text-muted)' } : {}}>
              <Icon className="w-3.5 h-3.5" />{label}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5">
          {loading ? (
            <div className="space-y-2">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-10 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-secondary)' }} />
              ))}
            </div>
          ) : items.length === 0 ? (
            <p className="text-sm text-center py-8" style={{ color: 'var(--text-muted)' }}>No {tab} found.</p>
          ) : (
            <ul className="space-y-2">
              {items.map((item, i) => (
                <li key={item.id || i} className="flex items-center justify-between rounded-xl px-3 py-2.5 border"
                  style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-primary)' }}>
                  <div>
                    <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                      {item.name || item.email || item.account_name || item.id}
                    </p>
                    {item.email && item.name && (
                      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{item.email}</p>
                    )}
                  </div>
                  {tab === 'members' && (
                    <button onClick={() => removeMember(item.id)}
                      className="text-xs px-2 py-1 rounded-lg text-red-400 hover:bg-red-500/10 transition-colors">
                      Remove
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
