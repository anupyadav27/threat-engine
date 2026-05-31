'use client';

import { useState, useEffect } from 'react';
import { X, Users, Plus, Trash2 } from 'lucide-react';

export default function GroupModal({ group, onClose, onSaved }) {
  const [name, setName]       = useState(group?.name || '');
  const [desc, setDesc]       = useState(group?.description || '');
  const [members, setMembers] = useState([]);
  const [emailInput, setEmailInput] = useState('');
  const [saving, setSaving]   = useState(false);
  const [error, setError]     = useState('');

  useEffect(() => {
    if (group?.id) {
      fetch(`/gateway/api/v1/groups/${group.id}/members/`, { credentials: 'include' })
        .then(r => r.ok ? r.json() : { results: [] })
        .then(d => setMembers(d.results || d || []))
        .catch(() => {});
    }
  }, [group?.id]);

  const handleSave = async () => {
    if (!name.trim()) return;
    setSaving(true);
    setError('');
    try {
      const method = group?.id ? 'PATCH' : 'POST';
      const url = group?.id ? `/gateway/api/v1/groups/${group.id}/` : '/gateway/api/v1/groups/';
      const resp = await fetch(url, {
        method,
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), description: desc.trim() }),
      });
      if (!resp.ok) {
        const d = await resp.json().catch(() => ({}));
        throw new Error(d.detail || `Error ${resp.status}`);
      }
      if (onSaved) onSaved();
      onClose();
    } catch (e) {
      setError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleAddMember = async () => {
    const email = emailInput.trim();
    if (!email || !group?.id) return;
    try {
      // Look up user by email first
      const userResp = await fetch(`/gateway/api/v1/users/?email=${encodeURIComponent(email)}`, { credentials: 'include' });
      const userData = await userResp.json();
      const user = (userData.results || userData)[0];
      if (!user) { setError(`User not found: ${email}`); return; }

      const resp = await fetch(`/gateway/api/v1/groups/${group.id}/members/`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: user.id }),
      });
      if (!resp.ok) throw new Error(`Error ${resp.status}`);
      setMembers(m => [...m, { id: user.id, user_email: email }]);
      setEmailInput('');
      setError('');
    } catch (e) {
      setError(e.message);
    }
  };

  const handleRemoveMember = async (memberId) => {
    if (!group?.id) return;
    try {
      await fetch(`/gateway/api/v1/groups/${group.id}/members/${memberId}/`, {
        method: 'DELETE',
        credentials: 'include',
      });
      setMembers(m => m.filter(x => x.id !== memberId));
    } catch (_) {}
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}>
      <div className="w-full max-w-md rounded-2xl border shadow-2xl flex flex-col max-h-[90vh]" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b flex-shrink-0" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="flex items-center gap-2">
            <Users size={15} style={{ color: 'var(--accent-primary)' }} />
            <span className="font-semibold text-sm" style={{ color: 'var(--text-primary)' }}>
              {group ? 'Edit Group' : 'Create Group'}
            </span>
          </div>
          <button onClick={onClose} className="hover:opacity-60" style={{ color: 'var(--text-muted)' }}><X size={15} /></button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Group Name <span className="text-red-400">*</span>
            </label>
            <input
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. Security Team"
              className="w-full px-3 py-2 text-sm rounded-lg border outline-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Description</label>
            <textarea
              value={desc}
              onChange={e => setDesc(e.target.value)}
              placeholder="Optional description"
              rows={2}
              className="w-full px-3 py-2 text-sm rounded-lg border outline-none resize-none"
              style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            />
          </div>

          {/* Members (only shown when editing an existing group) */}
          {group?.id && (
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>Members</label>
              <div className="space-y-1.5 mb-2 max-h-32 overflow-y-auto">
                {members.length === 0 && (
                  <div className="text-xs" style={{ color: 'var(--text-muted)' }}>No members yet</div>
                )}
                {members.map(m => (
                  <div key={m.id} className="flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs"
                    style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>{m.user_email}</span>
                    <button onClick={() => handleRemoveMember(m.id)} className="hover:opacity-60" style={{ color: 'var(--text-muted)' }}>
                      <Trash2 size={11} />
                    </button>
                  </div>
                ))}
              </div>
              <div className="flex gap-1.5">
                <input
                  value={emailInput}
                  onChange={e => setEmailInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleAddMember()}
                  placeholder="user@example.com"
                  className="flex-1 px-2.5 py-1.5 text-xs rounded-lg border outline-none"
                  style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
                />
                <button onClick={handleAddMember}
                  className="flex items-center gap-1 px-2.5 py-1.5 text-xs rounded-lg border hover:opacity-80"
                  style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
                  <Plus size={11} /> Add
                </button>
              </div>
            </div>
          )}

          {error && (
            <div className="text-xs p-2.5 rounded-lg border" style={{ borderColor: 'rgba(239,68,68,0.3)', backgroundColor: 'rgba(239,68,68,0.08)', color: '#f87171' }}>
              {error}
            </div>
          )}

        </div>

        <div className="flex gap-2 px-5 py-4 border-t flex-shrink-0" style={{ borderColor: 'var(--border-primary)' }}>
            <button onClick={onClose}
              className="flex-1 py-2 text-sm rounded-lg border hover:opacity-80"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}>
              Cancel
            </button>
            <button onClick={handleSave} disabled={saving || !name.trim()}
              className="flex-1 py-2 text-sm font-medium rounded-lg disabled:opacity-40 hover:opacity-90"
              style={{ backgroundColor: 'var(--accent-primary)', color: 'white' }}>
              {saving ? 'Saving…' : group ? 'Save Changes' : 'Create Group'}
            </button>
          </div>
      </div>
    </div>
  );
}
