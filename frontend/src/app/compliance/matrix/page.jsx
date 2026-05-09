'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { ArrowLeft, Download, Info } from 'lucide-react';
import Tooltip from '@/components/shared/Tooltip';
import { TENANT_ID, FRAMEWORKS, CLOUD_PROVIDERS } from '@/lib/constants';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';

const C = {
  pass: '#22c55e', fail: '#ef4444', partial: '#f59e0b', na: '#6b7280',
  border: 'var(--border-primary)', bg: 'var(--bg-card)',
};

const PROVIDERS = Object.keys(CLOUD_PROVIDERS);

// Score → background color
function scoreColor(score) {
  if (score == null) return null;
  if (score >= 90) return 'rgba(34,197,94,0.18)';
  if (score >= 75) return 'rgba(59,130,246,0.18)';
  if (score >= 50) return 'rgba(245,158,11,0.18)';
  return 'rgba(239,68,68,0.18)';
}
function scoreText(score) {
  if (score == null) return null;
  if (score >= 90) return C.pass;
  if (score >= 75) return '#3b82f6';
  if (score >= 50) return C.partial;
  return C.fail;
}

export default function ComplianceMatrixPage() {
  const router = useRouter();
  const { provider: gProvider, account: gAccount } = useGlobalFilter();

  const [matrix, setMatrix] = useState({});       // { fw_key: { provider: score } }
  const [frameworkIds, setFrameworkIds] = useState({}); // { fw_key: { provider: engine_id } }
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState('config'); // config | ciem | combined

  useEffect(() => {
    setLoading(true);
    const params = { view };
    if (gProvider) params.provider = gProvider;
    if (gAccount)  params.account  = gAccount;
    fetchView('compliance/matrix', params)
      .then(d => {
        setMatrix(d?.matrix || {});
        setFrameworkIds(d?.frameworkIds || {});
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [view, gProvider, gAccount]);

  const handleCellClick = (fwId, provider) => {
    const score = matrix[fwId]?.[provider];
    if (score == null) return;
    // Navigate directly to the framework detail page using the engine's actual framework_id
    const engineId = frameworkIds[fwId]?.[provider];
    if (engineId) {
      router.push(`/compliance/${engineId}`);
    } else {
      router.push(`/compliance?fw=${fwId}&provider=${provider}`);
    }
  };

  const exportCsv = () => {
    const rows = [['Framework', ...PROVIDERS.map(p => CLOUD_PROVIDERS[p].name)]];
    FRAMEWORKS.forEach(fw => {
      rows.push([fw.name, ...PROVIDERS.map(p => matrix[fw.id]?.[p] != null ? `${matrix[fw.id][p]}%` : '—')]);
    });
    const csv = rows.map(r => r.join(',')).join('\n');
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
    a.download = 'compliance-matrix.csv'; a.click();
  };

  return (
    <div style={{ padding: '20px 24px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
        <button onClick={() => router.push('/compliance')}
          style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '6px 12px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 13 }}>
          <ArrowLeft size={14} /> Frameworks
        </button>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>Multi-Cloud Compliance Matrix</h1>
          <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>{FRAMEWORKS.length} frameworks × {PROVIDERS.length} providers</p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          {/* View toggle */}
          {['config', 'ciem', 'combined'].map(v => (
            <button key={v} onClick={() => setView(v)}
              style={{ padding: '6px 14px', borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: 'pointer',
                border: view === v ? '2px solid var(--accent-primary)' : `1px solid ${C.border}`,
                backgroundColor: view === v ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                color: view === v ? 'white' : 'var(--text-secondary)' }}>
              {v.charAt(0).toUpperCase() + v.slice(1)}
            </button>
          ))}
          <button onClick={exportCsv}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px', borderRadius: 8, border: `1px solid ${C.border}`, backgroundColor: 'var(--bg-card)', color: 'var(--text-secondary)', cursor: 'pointer', fontSize: 12 }}>
            <Download size={13} /> CSV
          </button>
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 16, marginBottom: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        {[['90%+', '#22c55e'], ['75–89%', '#3b82f6'], ['50–74%', '#f59e0b'], ['<50%', '#ef4444']].map(([l, c]) => (
          <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 12, height: 12, borderRadius: 2, backgroundColor: c, opacity: 0.6 }} />
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{l}</span>
          </div>
        ))}
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>— N/A (no data)</span>
        <Tooltip
          text="Each cell shows the Assessed Score for that framework on that cloud provider — the percentage of tested controls that are implemented, including partial credit for partly-met controls. Controls with no applicable resources are excluded. Click any coloured cell to see the full control-by-control breakdown."
          position="bottom"
          maxWidth={300}
        >
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--accent-primary)', cursor: 'help', marginLeft: 8 }}>
            <Info size={12} /> What do these scores mean?
          </span>
        </Tooltip>
      </div>

      {/* Matrix table */}
      <div style={{ overflowX: 'auto', borderRadius: 12, border: `1px solid ${C.border}`, backgroundColor: C.bg }}>
        {loading ? (
          <div style={{ padding: 60, textAlign: 'center', color: 'var(--text-muted)' }}>Loading matrix...</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 700 }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${C.border}`, backgroundColor: 'var(--bg-secondary)' }}>
                <th style={{ padding: '10px 16px', textAlign: 'left', fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', minWidth: 180, position: 'sticky', left: 0, backgroundColor: 'var(--bg-secondary)', zIndex: 1 }}>
                  Framework
                </th>
                {PROVIDERS.map(p => (
                  <th key={p} style={{ padding: '10px 12px', textAlign: 'center', fontSize: 10, fontWeight: 700, color: CLOUD_PROVIDERS[p].color, textTransform: 'uppercase', minWidth: 72 }}>
                    {CLOUD_PROVIDERS[p].name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {FRAMEWORKS.map((fw, fi) => (
                <tr key={fw.id} style={{ borderBottom: `1px solid ${C.border}` }}>
                  <td style={{ padding: '10px 16px', position: 'sticky', left: 0, backgroundColor: fi % 2 === 0 ? C.bg : 'var(--bg-secondary)', zIndex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <div style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: fw.color, flexShrink: 0 }} />
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>{fw.shortName || fw.name}</div>
                        {fw.group && <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{fw.group}</div>}
                      </div>
                    </div>
                  </td>
                  {PROVIDERS.map(p => {
                    const score = matrix[fw.id]?.[p];
                    const clickable = score != null;
                    return (
                      <td key={p} onClick={() => clickable && handleCellClick(fw.id, p)}
                        style={{ padding: '10px 12px', textAlign: 'center', backgroundColor: scoreColor(score) || 'transparent',
                          cursor: clickable ? 'pointer' : 'default', transition: 'filter 0.1s' }}
                        onMouseEnter={e => { if (clickable) e.currentTarget.style.filter = 'brightness(1.15)'; }}
                        onMouseLeave={e => { e.currentTarget.style.filter = 'none'; }}>
                        {score != null ? (
                          <span style={{ fontSize: 12, fontWeight: 700, color: scoreText(score) }}>{score}%</span>
                        ) : (
                          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>—</span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
