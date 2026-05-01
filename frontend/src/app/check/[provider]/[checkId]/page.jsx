'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, CheckCircle, XCircle, AlertTriangle,
  Shield, Download, Copy,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import { TENANT_ID, CLOUD_PROVIDERS } from '@/lib/constants';
import SeverityBadge from '@/components/shared/SeverityBadge';

const C = {
  pass: '#22c55e', fail: '#ef4444', partial: '#f59e0b', na: '#6b7280',
  blue: '#3b82f6', bg: 'var(--bg-card)', border: 'var(--border-primary)',
};

export default function CheckDetailPage() {
  const { provider, checkId } = useParams();
  const router = useRouter();

  const [check, setCheck]         = useState(null);
  const [mappings, setMappings]   = useState([]);
  const [assets, setAssets]       = useState([]);
  const [loading, setLoading]     = useState(true);
  const [copied, setCopied]       = useState(false);

  useEffect(() => {
    if (!provider || !checkId) return;
    setLoading(true);
    Promise.all([
      getFromEngine('compliance', `/api/v1/check/${provider}/${checkId}`, { tenant_id: TENANT_ID || 'default-tenant' }).catch(() => null),
      getFromEngine('compliance', `/api/v1/check/${provider}/${checkId}/mappings`, {}).catch(() => ({ mappings: [] })),
      getFromEngine('compliance', `/api/v1/check/${provider}/${checkId}/failing-assets`, { limit: 50 }).catch(() => ({ assets: [] })),
    ]).then(([checkData, mappingData, assetData]) => {
      setCheck(checkData);
      setMappings(mappingData?.mappings || []);
      setAssets(assetData?.assets || []);
    }).finally(() => setLoading(false));
  }, [provider, checkId]);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  };

  const providerMeta = CLOUD_PROVIDERS[provider?.toLowerCase()] || { name: provider?.toUpperCase(), color: C.blue };

  if (loading) {
    return <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-muted)' }}>Loading check...</div>;
  }

  const failing = check?.resources_failing ?? assets.length;
  const total   = check?.resources_total ?? 0;
  const passing = total - failing;

  return (
    <div style={{ padding: '20px 24px', maxWidth: 1100 }}>
      {/* ── Breadcrumb ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
        <button onClick={() => router.back()}
          style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 12px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 13 }}>
          <ArrowLeft size={14} /> Back
        </button>
        <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>
          Check Detail
        </span>
      </div>

      {/* ── Check Header ── */}
      <div style={{ padding: '20px 24px', borderRadius: 12, border: `1px solid ${C.border}`, backgroundColor: C.bg, marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
            <span style={{ fontSize: 10, padding: '3px 10px', borderRadius: 4, fontWeight: 700, backgroundColor: `${providerMeta.color}20`, color: providerMeta.color, whiteSpace: 'nowrap', marginTop: 2 }}>
              {providerMeta.name}
            </span>
            <div>
              <h1 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 6px', fontFamily: 'monospace' }}>
                {checkId}
              </h1>
              {check?.title && (
                <p style={{ fontSize: 13, color: 'var(--text-secondary)', margin: 0 }}>{check.title}</p>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {check?.severity && <SeverityBadge severity={check.severity} />}
            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, fontWeight: 700, padding: '4px 10px', borderRadius: 6,
              backgroundColor: check?.status === 'PASS' ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
              color: check?.status === 'PASS' ? C.pass : C.fail }}>
              {check?.status === 'PASS'
                ? <CheckCircle size={13} />
                : <XCircle size={13} />}
              {check?.status || (failing > 0 ? 'FAIL' : 'PASS')}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 24, marginTop: 16, flexWrap: 'wrap' }}>
          <Kpi label="Resources checked" value={total || '—'} />
          <Kpi label="Passing" value={passing} color={C.pass} />
          <Kpi label="Failing" value={failing} color={failing > 0 ? C.fail : C.pass} />
          {check?.scan_timestamp && (
            <Kpi label="Last scan" value={new Date(check.scan_timestamp).toLocaleString()} />
          )}
        </div>
      </div>

      {/* ── Mapped Controls ── */}
      {mappings.length > 0 && (
        <Card title={`Mapped Compliance Controls (${mappings.length})`} mb={20}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {['Framework', 'Control', 'Title', 'Section', 'Severity'].map(h => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {mappings.map((m, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${C.border}` }}
                  onClick={() => router.push(`/compliance?fw=${m.framework}&control=${m.unique_compliance_id}`)}
                  onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--bg-secondary)'}
                  onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                  style={{ cursor: 'pointer' }}>
                  <td style={{ padding: '10px 12px', fontSize: 12, fontWeight: 600, color: 'var(--accent-primary)' }}>{m.framework}</td>
                  <td style={{ padding: '10px 12px' }}><code style={{ fontSize: 11 }}>{m.control_id}</code></td>
                  <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-secondary)', maxWidth: 300 }}>{m.title}</td>
                  <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-muted)' }}>{m.section}</td>
                  <td style={{ padding: '10px 12px' }}>{m.severity && <SeverityBadge severity={m.severity} />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {/* ── Failing Assets ── */}
      <Card title={`Failing Assets (${failing})`} mb={20}>
        {assets.length === 0 ? (
          <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
            {failing === 0 ? 'No failing assets — this check is passing.' : 'Asset list not available.'}
          </div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                {['Asset ID', 'Type', 'Region', 'Account'].map(h => (
                  <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {assets.map((a, i) => (
                <tr key={a.asset_id || i}
                  onClick={() => router.push(`/inventory/${a.asset_id}`)}
                  onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--bg-secondary)'}
                  onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                  style={{ borderBottom: `1px solid ${C.border}`, cursor: 'pointer' }}>
                  <td style={{ padding: '10px 12px' }}>
                    <code style={{ fontSize: 11, color: 'var(--accent-primary)' }}>{a.asset_id || a.resource_uid}</code>
                  </td>
                  <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-secondary)' }}>{a.asset_type || a.resource_type}</td>
                  <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-muted)' }}>{a.region || '—'}</td>
                  <td style={{ padding: '10px 12px', fontSize: 12, color: 'var(--text-muted)' }}>{a.account_id || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {/* ── Remediation ── */}
      {(check?.remediation || check?.implementation_guidance) && (
        <Card title="Remediation" mb={20}>
          <div style={{ position: 'relative' }}>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, margin: '0 0 12px', whiteSpace: 'pre-wrap' }}>
              {check.remediation || check.implementation_guidance}
            </p>
            <button onClick={() => copyToClipboard(check.remediation || check.implementation_guidance)}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px', borderRadius: 6, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12 }}>
              <Copy size={13} /> {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </Card>
      )}

      {/* ── Evidence ── */}
      <Card title="Evidence">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <InfoBox label="Scan ID" value={check?.scan_id || '—'} />
          <InfoBox label="Timestamp" value={check?.scan_timestamp || '—'} />
          <InfoBox label="Check ID" value={checkId} mono />
          <InfoBox label="Provider" value={providerMeta.name} />
        </div>
        <button style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 6, padding: '7px 16px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12 }}>
          <Download size={13} /> Download evidence JSON
        </button>
      </Card>
    </div>
  );
}

/* ─── Sub-components ─────────────────────────────────────── */

function Card({ title, children, mb = 0 }) {
  return (
    <div style={{ borderRadius: 12, border: `1px solid ${C.border}`, backgroundColor: C.bg, marginBottom: mb, overflow: 'hidden' }}>
      <div style={{ padding: '12px 20px', borderBottom: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)' }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>{title}</span>
      </div>
      <div style={{ padding: 20 }}>{children}</div>
    </div>
  );
}

function Kpi({ label, value, color }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 18, fontWeight: 700, color: color || 'var(--text-primary)' }}>{value}</div>
    </div>
  );
}

function InfoBox({ label, value, mono }) {
  return (
    <div style={{ padding: '10px 12px', borderRadius: 8, backgroundColor: 'var(--bg-secondary)', border: `1px solid ${C.border}` }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>{label}</div>
      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', wordBreak: 'break-all', fontFamily: mono ? 'monospace' : undefined }}>{value || '—'}</div>
    </div>
  );
}
