'use client';

import { useState, useEffect, useCallback } from 'react';
import { Users, Plus, Edit2, Trash2 } from 'lucide-react';
import GroupModal from '@/components/settings/GroupModal';

export default function GroupsPage() {
  const [groups, setGroups]     = useState([]);
  const [loading, setLoading]   = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editGroup, setEditGroup] = useState(null);
  const [error, setError]       = useState('');

  const fetchGroups = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await fetch('/gateway/api/v1/groups/', { credentials: 'include' });
      if (!resp.ok) throw new Error(`Error ${resp.status}`);
      const data = await resp.json();
      setGroups(data.results || data || []);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchGroups(); }, [fetchGroups]);

  const handleDelete = async (groupId) => {
    if (!confirm('Delete this group? Members will lose any access assigned through it.')) return;
    try {
      await fetch(`/gateway/api/v1/groups/${groupId}/`, { method: 'DELETE', credentials: 'include' });
      setGroups(g => g.filter(x => x.id !== groupId));
    } catch (_) {}
  };

  const openCreate = () => { setEditGroup(null); setShowModal(true); };
  const openEdit   = (g) => { setEditGroup(g); setShowModal(true); };

  return (
    <div className="p-6 space-y-5 max-w-4xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>Groups</h1>
          <div className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {groups.length} group{groups.length !== 1 ? 's' : ''}
          </div>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl hover:opacity-90"
          style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
        >
          <Plus size={13} /> Create Group
        </button>
      </div>

      {error && (
        <div className="text-sm p-3 rounded-xl border" style={{ borderColor: 'rgba(239,68,68,0.3)', backgroundColor: 'rgba(239,68,68,0.08)', color: '#f87171' }}>
          {error}
        </div>
      )}

      {loading ? (
        <div className="space-y-2">
          {[1,2,3].map(i => <div key={i} className="h-16 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />)}
        </div>
      ) : groups.length === 0 ? (
        <div className="text-center py-16 space-y-3">
          <Users size={40} className="mx-auto" style={{ color: 'var(--text-muted)' }} />
          <div className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>No groups yet</div>
          <button onClick={openCreate}
            className="px-4 py-2 text-sm font-medium rounded-xl hover:opacity-90"
            style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}>
            Create your first group
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {groups.map(g => (
            <div key={g.id}
              className="rounded-xl border p-4 space-y-2 hover:shadow-md transition-shadow"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center"
                    style={{ backgroundColor: 'rgba(59,130,246,0.15)', color: 'var(--accent-primary)' }}>
                    <Users size={14} />
                  </div>
                  <div>
                    <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{g.name}</div>
                    <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                      {g.member_count ?? 0} member{(g.member_count ?? 0) !== 1 ? 's' : ''}
                    </div>
                  </div>
                </div>
                <div className="flex gap-1">
                  <button onClick={() => openEdit(g)} className="p-1.5 rounded-lg hover:opacity-70" style={{ color: 'var(--text-muted)' }}>
                    <Edit2 size={12} />
                  </button>
                  <button onClick={() => handleDelete(g.id)} className="p-1.5 rounded-lg hover:opacity-70" style={{ color: 'var(--text-muted)' }}>
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
              {g.description && (
                <div className="text-xs" style={{ color: 'var(--text-muted)' }}>{g.description}</div>
              )}
            </div>
          ))}
        </div>
      )}

      {showModal && (
        <GroupModal
          group={editGroup}
          onClose={() => setShowModal(false)}
          onSaved={() => { setShowModal(false); fetchGroups(); }}
        />
      )}
    </div>
  );
}
