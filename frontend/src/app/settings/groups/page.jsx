'use client';

/**
 * Groups management page — onboarding-D12 AC5-AC11
 *
 * AC5:  Groups list with Name, Member Count, Tenants, Accounts
 * AC6:  New Group button → CreateGroupModal
 * AC7:  Click group → EditGroupDrawer (Members tab by default)
 * AC8:  EditGroupDrawer has Members | Tenants | Accounts tabs
 * AC9:  Remove member via DELETE /gateway/api/v1/groups/{id}/members/{user_id}/
 * AC10: Accessible only to org_admin and platform_admin
 * AC11: Loading skeleton while fetching
 */

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth-context';
import { fetchView } from '@/lib/api';
import { Users, Plus, Edit2, Trash2, Building, Server } from 'lucide-react';
import GroupModal from '@/components/settings/GroupModal';
import EditGroupDrawer from '@/components/settings/EditGroupDrawer';

const ALLOWED_ROLES = ['org_admin', 'platform_admin'];

// AC11: Loading skeleton
function GroupsSkeleton() {
  return (
    <div className="p-6 space-y-5 max-w-4xl">
      <div className="flex items-center justify-between">
        <div className="space-y-1.5">
          <div className="h-6 w-32 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          <div className="h-4 w-20 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        </div>
        <div className="h-9 w-32 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="h-24 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        ))}
      </div>
    </div>
  );
}

export default function GroupsPage() {
  const router = useRouter();
  const { role, isInitialized } = useAuth();

  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editGroup, setEditGroup] = useState(null);
  const [drawerGroup, setDrawerGroup] = useState(null);
  const [error, setError] = useState('');

  // AC10: role guard
  useEffect(() => {
    if (!isInitialized) return;
    if (role && !ALLOWED_ROLES.includes(role)) {
      router.replace('/403');
    }
  }, [role, isInitialized, router]);

  // AC5: fetch via BFF view, fallback to direct gateway call
  const fetchGroups = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      // Prefer BFF view for normalised shape
      const bffData = await fetchView('groups');
      if (bffData && !bffData.error) {
        setGroups(bffData.groups || []);
        return;
      }
      // Fallback: direct gateway endpoint (used when BFF not yet deployed)
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

  useEffect(() => {
    if (!isInitialized) return;
    if (!role || !ALLOWED_ROLES.includes(role)) return;
    fetchGroups();
  }, [isInitialized, role, fetchGroups]);

  const handleDelete = async (groupId) => {
    if (!confirm('Delete this group? Members will lose any access granted through it.')) return;
    try {
      await fetch(`/gateway/api/v1/groups/${groupId}/`, { method: 'DELETE', credentials: 'include' });
      setGroups(g => g.filter(x => (x.id || x.group_id) !== groupId));
    } catch (e) {
      setError(e.message);
    }
  };

  const openCreate = () => { setEditGroup(null); setShowModal(true); };
  const openEdit   = (g, evt) => { evt.stopPropagation(); setEditGroup(g); setShowModal(true); };
  // AC7: click row → drawer
  const openDrawer = (g) => {
    // Normalise shape — BFF uses group_id, direct gateway uses id
    setDrawerGroup({ ...g, id: g.id || g.group_id });
  };

  if (!isInitialized || loading) return <GroupsSkeleton />;
  if (!ALLOWED_ROLES.includes(role)) return null;

  return (
    <div className="p-6 space-y-5 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>Groups</h1>
          <div className="text-sm mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {groups.length} group{groups.length !== 1 ? 's' : ''}
          </div>
        </div>
        {/* AC6: New Group button */}
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

      {groups.length === 0 ? (
        <div className="text-center py-16 space-y-3">
          <Users size={40} className="mx-auto" style={{ color: 'var(--text-muted)' }} />
          <div className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>No groups yet</div>
          <button
            onClick={openCreate}
            className="px-4 py-2 text-sm font-medium rounded-xl hover:opacity-90"
            style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}
          >
            Create your first group
          </button>
        </div>
      ) : (
        // AC5: groups grid with Name, Member Count, Tenants, Accounts
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {groups.map(g => {
            const gid = g.id || g.group_id;
            const tenantCount = (g.tenant_assignments || []).length;
            const accountCount = (g.account_assignments || []).length;
            return (
              <div
                key={gid}
                onClick={() => openDrawer(g)}
                className="rounded-xl border p-4 space-y-2 hover:shadow-md transition-all cursor-pointer"
                style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
                title="Click to manage members and assignments"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <div
                      className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: 'rgba(59,130,246,0.15)', color: 'var(--accent-primary)' }}
                    >
                      <Users size={14} />
                    </div>
                    <div>
                      <div className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{g.name}</div>
                      <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                        {g.member_count ?? 0} member{(g.member_count ?? 0) !== 1 ? 's' : ''}
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-1" onClick={e => e.stopPropagation()}>
                    <button
                      onClick={(e) => openEdit(g, e)}
                      className="p-1.5 rounded-lg hover:opacity-70"
                      style={{ color: 'var(--text-muted)' }}
                      title="Edit group name/description"
                    >
                      <Edit2 size={12} />
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleDelete(gid); }}
                      className="p-1.5 rounded-lg hover:opacity-70"
                      style={{ color: 'var(--text-muted)' }}
                      title="Delete group"
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                </div>

                {/* AC5: Tenants + Accounts counts */}
                <div className="flex items-center gap-3 text-[11px]" style={{ color: 'var(--text-muted)' }}>
                  <span className="flex items-center gap-1">
                    <Building size={10} />
                    {tenantCount} tenant{tenantCount !== 1 ? 's' : ''}
                  </span>
                  <span className="flex items-center gap-1">
                    <Server size={10} />
                    {accountCount} account{accountCount !== 1 ? 's' : ''}
                  </span>
                </div>

                {g.description && (
                  <div className="text-xs line-clamp-2" style={{ color: 'var(--text-muted)' }}>{g.description}</div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* AC6: Create/Edit Group modal */}
      {showModal && (
        <GroupModal
          group={editGroup}
          onClose={() => setShowModal(false)}
          onSaved={() => { setShowModal(false); fetchGroups(); }}
        />
      )}

      {/* AC7-AC9: Edit Group Drawer */}
      {drawerGroup && (
        <EditGroupDrawer
          group={drawerGroup}
          onClose={() => setDrawerGroup(null)}
          onSaved={() => fetchGroups()}
        />
      )}
    </div>
  );
}
