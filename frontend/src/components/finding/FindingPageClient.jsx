'use client';

import { useEffect, useState } from 'react';
import { fetchView } from '@/lib/api';
import { emit } from '@/lib/telemetry';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import EmptyState from '@/components/shared/EmptyState';
import { AlertTriangle, ShieldOff } from 'lucide-react';
import FindingHeaderCard from './FindingHeaderCard';
import FindingTabsShell from './FindingTabsShell';
import { ENGINE_META } from './engine-meta';

/**
 * Defensive sanitizer — drops keys that look like credentials/raw events
 * even if BFF forgot to strip them. Per design §7 + ADR §3.1.c.
 */
const SENSITIVE_KEY_RE = /credential|secret|raw_event|cred_payload|actor_credentials|secret_ref/i;

function stripSensitive(obj, path = '') {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map((v, i) => stripSensitive(v, `${path}[${i}]`));
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (SENSITIVE_KEY_RE.test(k)) {
      if (process.env.NODE_ENV !== 'production') {
        // eslint-disable-next-line no-console
        console.warn(`[finding] dropped sensitive key "${k}" at ${path || 'root'}`);
      }
      continue;
    }
    out[k] = stripSensitive(v, path ? `${path}.${k}` : k);
  }
  return out;
}

export default function FindingPageClient({ engine, id }) {
  const [state, setState] = useState({ status: 'loading', data: null, error: null });

  useEffect(() => {
    let cancelled = false;
    setState({ status: 'loading', data: null, error: null });
    fetchView(`finding/${engine}/${id}`)
      .then((res) => {
        if (cancelled) return;
        if (res?.error) {
          // String errors don't carry a status; treat as 500-ish.
          setState({ status: 'error', data: null, error: { message: res.error } });
          return;
        }
        const clean = stripSensitive(res);
        setState({ status: 'ready', data: clean, error: null });
        emit('finding.page_view', {
          engine,
          finding_id: id,
          severity: clean?.header?.severity,
          status: clean?.header?.status,
          has_compliance_tab: clean?.tabPermissions?.compliance !== false,
        });
      })
      .catch((err) => {
        if (cancelled) return;
        setState({ status: 'error', data: null, error: err });
      });
    return () => {
      cancelled = true;
    };
  }, [engine, id]);

  if (state.status === 'loading') {
    return (
      <div className="p-6 space-y-4">
        <LoadingSkeleton rows={3} cols={6} />
        <LoadingSkeleton rows={6} cols={4} />
      </div>
    );
  }

  if (state.status === 'error') {
    const meta = ENGINE_META[engine];
    const msg = state.error?.message || '';
    const isForbidden = /403|forbidden/i.test(msg);
    const isNotFound = /404|not found/i.test(msg);

    if (isNotFound) {
      return (
        <div className="p-8">
          <EmptyState
            title="Finding not found"
            description="This finding either doesn't exist, has been resolved, or is outside your tenant scope."
            action={
              meta
                ? {
                    label: `Back to ${meta.label}`,
                    onClick: () => {
                      window.location.href = meta.route;
                    },
                  }
                : null
            }
          />
        </div>
      );
    }

    if (isForbidden) {
      return (
        <div className="p-6 max-w-3xl mx-auto">
          <div
            className="flex items-start gap-3 rounded-lg border p-4"
            style={{
              backgroundColor: 'rgba(245,158,11,0.08)',
              borderColor: 'rgba(245,158,11,0.4)',
              color: 'var(--text-primary)',
            }}
          >
            <ShieldOff className="w-5 h-5 mt-0.5" style={{ color: '#f59e0b' }} />
            <div>
              <div className="font-semibold mb-1">Access denied</div>
              <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
                You don&apos;t have access to this finding.
              </div>
            </div>
          </div>
        </div>
      );
    }

    // Other errors: throw so the route-level error.jsx boundary catches it
    throw Object.assign(new Error(msg || 'Failed to load finding'), {
      correlationId: state.error?.correlationId,
      traceId: state.error?.traceId,
    });
  }

  const { data } = state;
  const finding = data?.finding || data; // tolerate either {finding:{...}} or flat
  const header = finding?.header || data?.header;

  if (!header) {
    return (
      <div className="p-8">
        <EmptyState
          icon={<AlertTriangle className="w-10 h-10" />}
          title="Empty response"
          description="The BFF returned no header for this finding."
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <FindingHeaderCard header={header} engine={engine} id={id} />
      <FindingTabsShell finding={finding} engine={engine} id={id} data={data} />
    </div>
  );
}
