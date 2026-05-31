'use client';

/**
 * SuppressPanel — role-aware slide-out panel for creating suppressions.
 *
 * Two modes:
 *   mode='finding'    → finding-level (resource-specific). Visible to analyst+.
 *                       POST /findings/suppress
 *   mode='rule'       → rule/service/technology scope. Visible to tenant_admin+.
 *   mode='service'    → same endpoint, scope_type='service'
 *   mode='technology' → same endpoint, scope_type='technology'
 *
 * RBAC enforced both here (UI) and at the engine (rules:read / rules:write).
 */

import { useState } from 'react';
import {
  X,
  Building2,
  Server,
  AlertTriangle,
  RefreshCw,
  Calendar,
  ShieldOff,
} from 'lucide-react';
import { postToEngine } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';

const PERMISSION = {
  // analyst+      → can suppress at finding level
  FINDING: 'rules:read',
  // tenant_admin+ → can suppress at rule/service/tech scope
  RULE_SCOPE: 'rules:write',
};

export default function SuppressPanel({ target, mode, onClose, onSuccess }) {
  const { hasPermission } = useAuth();
  const [form, setForm] = useState({
    scope_level: 'tenant',
    account_id: target?.account_id || '',
    reason: '',
    expires_at: '',
  });
  const [submitting, setSubmitting] = useState(false);

  if (!target) return null;

  const isFindingMode = mode === 'finding';
  const canSubmit = isFindingMode
    ? hasPermission(PERMISSION.FINDING)
    : hasPermission(PERMISSION.RULE_SCOPE);

  if (!canSubmit) {
    return (
      <PanelShell onClose={onClose}>
        <div className="flex-1 flex items-center justify-center p-8">
          <div className="text-center space-y-3">
            <ShieldOff className="w-10 h-10 mx-auto" style={{ color: 'var(--text-muted)' }} />
            <p className="font-semibold" style={{ color: 'var(--text-primary)' }}>
              Insufficient permissions
            </p>
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              {isFindingMode
                ? 'Analyst role or higher required to suppress findings.'
                : 'Tenant Admin role or higher required to suppress rules.'}
            </p>
          </div>
        </div>
      </PanelShell>
    );
  }

  const scopeLabel = mode === 'rule'       ? target.rule_id
                   : mode === 'service'    ? `All rules · service: ${target.service}`
                   : mode === 'technology' ? `All rules · technology: ${target.service}`
                   : `${target.rule_id} → ${target.resource_uid || target.resource_name || 'specific resource'}`;

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      let res;
      if (isFindingMode) {
        res = await postToEngine('rule', '/api/v1/findings/suppress', {
          account_id:   target.account_id,
          rule_id:      target.rule_id,
          resource_uid: target.resource_uid || null,
          finding_id:   target.finding_id   || null,
          reason:       form.reason || null,
          expires_at:   form.expires_at || null,
        });
      } else {
        res = await postToEngine('rule', '/api/v1/rules/suppress', {
          scope_level:  form.scope_level,
          account_id:   form.scope_level === 'account' ? form.account_id : null,
          scope_type:   mode,
          scope_value:  mode === 'rule'       ? target.rule_id
                      : mode === 'service'    ? target.service
                      : target.service,
          provider:     target.provider?.toLowerCase() || null,
          reason:       form.reason || null,
          expires_at:   form.expires_at || null,
        });
      }

      if (res?.error) {
        alert(`Suppress failed: ${res.error}`);
        return;
      }
      onSuccess?.(res);
      onClose();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <PanelShell onClose={onClose}>
      {/* Header */}
      <div className="flex items-start justify-between p-5 border-b" style={{ borderColor: 'var(--border-primary)' }}>
        <div>
          <h2 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
            {isFindingMode ? 'Suppress Finding' : 'Suppress Rule'}
          </h2>
          <p className="text-xs mt-1 font-mono break-all" style={{ color: 'var(--text-secondary)' }}>
            {scopeLabel}
          </p>
          <ScopeTypeBadge mode={mode} />
        </div>
        <button onClick={onClose} style={{ color: 'var(--text-muted)' }}>
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Scope level — only for rule-scope modes */}
        {!isFindingMode && (
          <div>
            <label className="text-sm font-semibold block mb-2" style={{ color: 'var(--text-primary)' }}>
              Scope Level
            </label>
            <div className="grid grid-cols-2 gap-2">
              {[
                { value: 'tenant',  label: 'Tenant-wide',      sub: 'All accounts', Icon: Building2 },
                { value: 'account', label: 'Specific Account',  sub: 'One account',  Icon: Server    },
              ].map(({ value, label, sub, Icon }) => (
                <button
                  key={value}
                  onClick={() => setForm(f => ({ ...f, scope_level: value, account_id: '' }))}
                  className="p-3 rounded-xl border text-left transition-all"
                  style={{
                    borderColor:     form.scope_level === value ? 'var(--accent-primary)' : 'var(--border-primary)',
                    backgroundColor: form.scope_level === value ? 'rgba(99,102,241,0.08)' : 'var(--bg-secondary)',
                  }}
                >
                  <Icon className="w-4 h-4 mb-1.5" style={{ color: form.scope_level === value ? 'var(--accent-primary)' : 'var(--text-muted)' }} />
                  <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{label}</p>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>{sub}</p>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Account ID for account-scoped rule suppression */}
        {!isFindingMode && form.scope_level === 'account' && (
          <div>
            <label className="text-sm font-semibold block mb-1.5" style={{ color: 'var(--text-primary)' }}>
              Account ID <span style={{ color: 'var(--accent-danger)' }}>*</span>
            </label>
            <input
              type="text"
              value={form.account_id}
              onChange={e => setForm(f => ({ ...f, account_id: e.target.value }))}
              placeholder="e.g. 588989875114"
              className="w-full px-3 py-2 rounded-lg border text-sm"
              style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
            />
          </div>
        )}

        {/* Finding context (read-only info) */}
        {isFindingMode && target.resource_uid && (
          <div className="rounded-lg p-3 border" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
            <p className="text-xs font-semibold mb-1" style={{ color: 'var(--text-muted)' }}>RESOURCE</p>
            <p className="text-sm font-mono break-all" style={{ color: 'var(--text-primary)' }}>{target.resource_uid}</p>
            {target.account_id && (
              <>
                <p className="text-xs font-semibold mt-2 mb-1" style={{ color: 'var(--text-muted)' }}>ACCOUNT</p>
                <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{target.account_id}</p>
              </>
            )}
          </div>
        )}

        {/* Reason */}
        <div>
          <label className="text-sm font-semibold block mb-1.5" style={{ color: 'var(--text-primary)' }}>
            Reason
          </label>
          <textarea
            value={form.reason}
            onChange={e => setForm(f => ({ ...f, reason: e.target.value }))}
            placeholder="Describe why this is being suppressed..."
            rows={3}
            className="w-full px-3 py-2 rounded-lg border text-sm resize-none"
            style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
          />
        </div>

        {/* Expiry */}
        <div>
          <label className="text-sm font-semibold block mb-1.5" style={{ color: 'var(--text-primary)' }}>
            <div className="flex items-center gap-1.5">
              <Calendar className="w-4 h-4" />
              Expires (leave blank for permanent)
            </div>
          </label>
          <input
            type="date"
            value={form.expires_at}
            onChange={e => setForm(f => ({ ...f, expires_at: e.target.value }))}
            min={new Date().toISOString().split('T')[0]}
            className="w-full px-3 py-2 rounded-lg border text-sm"
            style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
          />
        </div>

        {/* Warning */}
        <div className="rounded-lg p-3 border flex gap-2" style={{ backgroundColor: 'rgba(249,115,22,0.08)', borderColor: 'rgba(249,115,22,0.3)' }}>
          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: '#f97316' }} />
          <p className="text-xs" style={{ color: '#f97316' }}>
            Takes effect on the <strong>next scan</strong>. Existing findings remain until re-evaluated.
          </p>
        </div>
      </div>

      {/* Footer */}
      <div className="p-5 border-t flex gap-3" style={{ borderColor: 'var(--border-primary)' }}>
        <button
          onClick={onClose}
          className="flex-1 px-4 py-2 rounded-xl text-sm font-semibold border"
          style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
        >
          Cancel
        </button>
        <button
          onClick={handleSubmit}
          disabled={
            submitting ||
            (!isFindingMode && form.scope_level === 'account' && !form.account_id.trim())
          }
          className="flex-1 px-4 py-2 rounded-xl text-sm font-semibold text-white flex items-center justify-center gap-2"
          style={{
            backgroundColor: submitting ? 'var(--accent-muted)' : 'var(--accent-primary)',
            cursor: submitting ? 'not-allowed' : 'pointer',
          }}
        >
          {submitting && <RefreshCw className="w-4 h-4 animate-spin" />}
          {submitting ? 'Suppressing...' : isFindingMode ? 'Suppress Finding' : 'Suppress'}
        </button>
      </div>
    </PanelShell>
  );
}

function PanelShell({ onClose, children }) {
  return (
    <div className="fixed inset-0 z-50 flex" style={{ backgroundColor: 'rgba(0,0,0,0.4)' }}>
      <div className="flex-1" onClick={onClose} />
      <div
        className="w-full max-w-md flex flex-col shadow-2xl"
        style={{ backgroundColor: 'var(--bg-card)', borderLeft: '1px solid var(--border-primary)' }}
      >
        {children}
      </div>
    </div>
  );
}

function ScopeTypeBadge({ mode }) {
  const map = {
    finding:    { label: 'Resource-level',  bg: 'rgba(34,197,94,0.12)',   color: '#22c55e' },
    rule:       { label: 'Rule scope',      bg: 'rgba(59,130,246,0.12)',  color: '#3b82f6' },
    service:    { label: 'Service scope',   bg: 'rgba(16,185,129,0.12)',  color: '#10b981' },
    technology: { label: 'Tech scope',      bg: 'rgba(168,85,247,0.12)', color: '#a855f7' },
  };
  const { label, bg, color } = map[mode] || map.rule;
  return (
    <span
      className="inline-block text-xs px-2 py-0.5 rounded font-semibold mt-1.5"
      style={{ backgroundColor: bg, color }}
    >
      {label}
    </span>
  );
}
