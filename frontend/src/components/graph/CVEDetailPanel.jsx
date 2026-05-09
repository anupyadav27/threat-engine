'use client';

/**
 * CVEDetailPanel — slide-in detail panel for CVE diamond nodes in the security graph.
 *
 * RBAC rules (GRAPH-S3-02):
 *   - All authenticated users: see cve_id, cvss_score, severity
 *   - org_admin and above (level <= 2): additionally see epss_score, in_kev badge
 *   - viewer: epss_score and in_kev are hidden
 *
 * @param {Object}   props.node      - The CVE node object from Neo4j graph data
 * @param {string}   props.userRole  - Auth role string (e.g. 'org_admin', 'viewer', 'tenant_admin')
 * @param {Function} props.onClose   - Called when the panel is dismissed
 */

import { X, Shield, AlertTriangle } from 'lucide-react';

const SEVERITY_COLORS = {
  critical: '#d32f2f',
  high:     '#f57c00',
  medium:   '#f9a825',
  low:      '#388e3c',
};

function getSeverityColor(severity) {
  const sev = (severity || '').toLowerCase();
  return SEVERITY_COLORS[sev] || '#9e9e9e';
}

function CvssBar({ score }) {
  if (score == null) return null;
  const pct = Math.min(100, (score / 10) * 100);
  const color =
    score >= 9 ? SEVERITY_COLORS.critical
    : score >= 7 ? SEVERITY_COLORS.high
    : score >= 4 ? SEVERITY_COLORS.medium
    : SEVERITY_COLORS.low;

  return (
    <div
      className="w-full h-2 rounded-full overflow-hidden"
      style={{ backgroundColor: 'var(--bg-secondary)' }}
    >
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${pct}%`, backgroundColor: color }}
      />
    </div>
  );
}

export function CVEDetailPanel({ node, userRole, onClose }) {
  if (!node) return null;

  // viewer role cannot see EPSS score or CISA KEV status (story AC #3).
  // tenant_admin, analyst, org_admin, platform_admin all see full fields (story AC #4).
  const canSeePrivileged = userRole !== 'viewer';

  const severity      = node.severity || 'unknown';
  const sevColor      = getSeverityColor(severity);
  const cvssScore     = node.cvss_score ?? node.cvssScore ?? null;
  const epssScore     = node.epss_score ?? node.epssScore ?? null;
  const inKev         = node.in_kev ?? node.inKev ?? false;
  const cveId         = node.cve_id || node.label || node.id || 'Unknown CVE';
  const description   = node.description || null;
  const affectedResource = node.connected_resource_name || node.resource_name || null;
  const publishedDate = node.published_date || null;

  return (
    <div
      className="absolute top-0 right-0 h-full w-[340px] border-l overflow-y-auto z-20
                 transition-transform duration-300 ease-out"
      style={{
        backgroundColor: 'var(--bg-card)',
        borderColor: 'var(--border-primary)',
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3 border-b sticky top-0 z-10"
        style={{
          borderColor: 'var(--border-primary)',
          backgroundColor: 'var(--bg-card)',
        }}
      >
        <div className="flex items-center gap-2">
          {/* Diamond shape indicator */}
          <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
            <polygon
              points="8,1 15,8 8,15 1,8"
              fill={sevColor}
              opacity={0.9}
            />
          </svg>
          <h3
            className="text-sm font-semibold"
            style={{ color: 'var(--text-primary)' }}
          >
            CVE Details
          </h3>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded hover:opacity-70 transition-opacity"
          style={{ color: 'var(--text-secondary)' }}
          title="Close (Esc)"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 space-y-5">
        {/* CVE ID + severity badge */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span
              className="text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wide"
              style={{
                backgroundColor: `${sevColor}22`,
                color: sevColor,
                border: `1px solid ${sevColor}44`,
              }}
            >
              {severity}
            </span>
            {inKev && canSeePrivileged && (
              <span
                className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wide"
                style={{
                  backgroundColor: 'rgba(239,68,68,0.15)',
                  color: '#ef4444',
                  border: '1px solid rgba(239,68,68,0.3)',
                }}
              >
                <AlertTriangle className="w-2.5 h-2.5" />
                CISA KEV
              </span>
            )}
          </div>
          <p
            className="text-base font-bold leading-tight font-mono break-all"
            style={{ color: 'var(--text-primary)' }}
          >
            {cveId}
          </p>
          {description && (
            <p
              className="text-xs mt-2 leading-relaxed"
              style={{ color: 'var(--text-secondary)' }}
            >
              {description.slice(0, 200)}{description.length > 200 ? '…' : ''}
            </p>
          )}
        </div>

        {/* CVSS Score */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <span
              className="text-xs font-medium"
              style={{ color: 'var(--text-secondary)' }}
            >
              CVSS Score
            </span>
            <span
              className="text-lg font-bold"
              style={{ color: cvssScore != null ? getSeverityColor(severity) : 'var(--text-secondary)' }}
            >
              {cvssScore != null ? cvssScore.toFixed(1) : '—'}
            </span>
          </div>
          <CvssBar score={cvssScore} />
        </div>

        {/* Score details table */}
        <div
          className="rounded-lg border overflow-hidden"
          style={{ borderColor: 'var(--border-primary)' }}
        >
          <table className="w-full text-xs">
            <tbody>
              {/* CVSS row */}
              <tr
                className="border-b"
                style={{ borderColor: 'var(--border-primary)' }}
              >
                <td
                  className="px-3 py-2 font-medium"
                  style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-secondary)', width: '50%' }}
                >
                  CVSS Score
                </td>
                <td className="px-3 py-2 font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>
                  {cvssScore != null ? cvssScore.toFixed(1) : '—'}
                </td>
              </tr>
              {/* Severity row */}
              <tr
                className="border-b"
                style={{ borderColor: 'var(--border-primary)' }}
              >
                <td
                  className="px-3 py-2 font-medium"
                  style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-secondary)' }}
                >
                  Severity
                </td>
                <td className="px-3 py-2">
                  <span
                    className="text-[10px] font-bold px-1.5 py-0.5 rounded-full uppercase"
                    style={{ backgroundColor: `${sevColor}22`, color: sevColor }}
                  >
                    {severity}
                  </span>
                </td>
              </tr>
              {/* EPSS row — org_admin and above only */}
              {canSeePrivileged && (
                <tr
                  className="border-b"
                  style={{ borderColor: 'var(--border-primary)' }}
                >
                  <td
                    className="px-3 py-2 font-medium"
                    style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-secondary)' }}
                  >
                    EPSS Score
                  </td>
                  <td className="px-3 py-2 font-mono font-semibold" style={{ color: 'var(--text-primary)' }}>
                    {epssScore != null ? epssScore.toFixed(4) : '—'}
                  </td>
                </tr>
              )}
              {/* In CISA KEV row — org_admin and above only */}
              {canSeePrivileged && (
                <tr>
                  <td
                    className="px-3 py-2 font-medium"
                    style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-secondary)' }}
                  >
                    In CISA KEV
                  </td>
                  <td className="px-3 py-2">
                    {inKev ? (
                      <span
                        className="flex items-center gap-1 text-[10px] font-bold px-1.5 py-0.5 rounded-full w-fit"
                        style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#ef4444' }}
                      >
                        <AlertTriangle className="w-2.5 h-2.5" />
                        Yes
                      </span>
                    ) : (
                      <span className="text-[10px]" style={{ color: 'var(--text-secondary)' }}>No</span>
                    )}
                  </td>
                </tr>
              )}
              {/* Published date if present */}
              {publishedDate && (
                <tr>
                  <td
                    className="px-3 py-2 font-medium"
                    style={{ color: 'var(--text-secondary)', backgroundColor: 'var(--bg-secondary)' }}
                  >
                    Published
                  </td>
                  <td className="px-3 py-2 font-mono text-[10px]" style={{ color: 'var(--text-secondary)' }}>
                    {publishedDate}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Affected resource */}
        {affectedResource && (
          <div>
            <p
              className="text-xs font-semibold uppercase tracking-wider mb-2"
              style={{ color: 'var(--text-secondary)' }}
            >
              Affected Resource
            </p>
            <div
              className="flex items-center gap-2 px-3 py-2 rounded-lg border"
              style={{
                backgroundColor: 'var(--bg-secondary)',
                borderColor: 'var(--border-primary)',
              }}
            >
              <Shield className="w-4 h-4 flex-shrink-0" style={{ color: '#f97316' }} />
              <span
                className="text-xs font-medium truncate"
                style={{ color: 'var(--text-primary)' }}
              >
                {affectedResource}
              </span>
            </div>
          </div>
        )}

        {/* RBAC note for viewer role */}
        {!canSeePrivileged && (
          <div
            className="rounded-lg px-3 py-2 text-xs border"
            style={{
              backgroundColor: 'rgba(100,116,139,0.08)',
              borderColor: 'rgba(100,116,139,0.2)',
              color: 'var(--text-secondary)',
            }}
          >
            Additional fields (EPSS score, KEV status) require analyst role or above.
          </div>
        )}

        {/* NVD link */}
        {cveId && cveId.startsWith('CVE-') && (
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center justify-center gap-2 text-xs py-2 rounded-lg border hover:opacity-75 transition-opacity w-full"
            style={{
              borderColor: 'var(--border-primary)',
              color: 'var(--text-secondary)',
            }}
          >
            View on NVD
          </a>
        )}
      </div>
    </div>
  );
}
