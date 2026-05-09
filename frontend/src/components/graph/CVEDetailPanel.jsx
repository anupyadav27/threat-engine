'use client';
export function CVEDetailPanel({ cve = null, onClose }) {
    if (!cve) return null;
    return (
        <div style={{ position: 'absolute', top: 0, right: 0, bottom: 0, width: 360, backgroundColor: 'var(--bg-card)', borderLeft: '1px solid var(--border-primary)', display: 'flex', flexDirection: 'column', zIndex: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 16px', borderBottom: '1px solid var(--border-primary)' }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>{cve.cve_id || 'CVE Details'}</div>
                {onClose && <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 4 }}>✕</button>}
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
                {cve.description && <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 12 }}>{cve.description}</p>}
                {cve.cvss_score != null && <div style={{ fontSize: 12, marginBottom: 8 }}><span style={{ color: 'var(--text-muted)' }}>CVSS Score: </span><span style={{ fontWeight: 700 }}>{cve.cvss_score}</span></div>}
                {cve.severity && <div style={{ fontSize: 12 }}><span style={{ color: 'var(--text-muted)' }}>Severity: </span><span style={{ fontWeight: 700, textTransform: 'uppercase' }}>{cve.severity}</span></div>}
            </div>
        </div>
    );
}
export default CVEDetailPanel;
