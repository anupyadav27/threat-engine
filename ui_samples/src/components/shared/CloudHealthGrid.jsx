'use client';

import { CheckCircle, AlertTriangle, XCircle } from 'lucide-react';
import CloudProviderBadge from './CloudProviderBadge';

/**
 * CloudHealthGrid — per-provider health summary table.
 *
 * @param {{ clouds: Array<{
 *   provider: string,
 *   accounts: number,
 *   resources: number,
 *   findings: number,
 *   compliance: number,
 *   lastScan: string,
 *   credStatus: 'valid'|'expired'|'warning',
 * }> }} props
 */
export default function CloudHealthGrid({ clouds = [] }) {
  return (
    <div
      className="rounded-xl border overflow-hidden transition-colors duration-200"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
        <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
          Multi-Cloud Health
        </h3>
        <p className="text-xs mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
          Real-time posture across all connected cloud providers
        </p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr style={{ borderBottomColor: 'var(--border-primary)' }} className="border-b">
              {['Provider','Accounts','Resources','Active Findings','Compliance','Last Scan','Status'].map(h => (
                <th key={h} className="text-left py-2.5 px-4 text-xs font-semibold uppercase tracking-wider"
                  style={{ color: 'var(--text-muted)' }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {clouds.map((cloud) => {
              const isExpired = cloud.credStatus === 'expired';
              const isWarning = cloud.credStatus === 'warning';
              const complianceColor = cloud.compliance >= 80 ? '#22c55e' : cloud.compliance >= 60 ? '#f97316' : '#ef4444';

              return (
                <tr
                  key={cloud.provider}
                  className="border-b hover:opacity-80 transition-opacity"
                  style={{ borderColor: 'var(--border-primary)' }}
                >
                  <td className="py-3 px-4">
                    <CloudProviderBadge provider={cloud.provider} />
                  </td>
                  <td className="py-3 px-4" style={{ color: 'var(--text-secondary)' }}>
                    {cloud.accounts}
                  </td>
                  <td className="py-3 px-4" style={{ color: 'var(--text-primary)' }}>
                    {isExpired ? '—' : cloud.resources.toLocaleString()}
                  </td>
                  <td className="py-3 px-4">
                    {isExpired ? (
                      <span style={{ color: 'var(--text-muted)' }}>—</span>
                    ) : (
                      <span className="font-semibold" style={{ color: cloud.findings > 20 ? '#ef4444' : cloud.findings > 5 ? '#f97316' : '#22c55e' }}>
                        {cloud.findings}
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4">
                    {isExpired ? (
                      <span style={{ color: 'var(--text-muted)' }}>—</span>
                    ) : (
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
                          <div className="h-full rounded-full" style={{ width: `${cloud.compliance}%`, backgroundColor: complianceColor }} />
                        </div>
                        <span className="text-xs font-semibold" style={{ color: complianceColor }}>
                          {cloud.compliance}%
                        </span>
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-4 text-xs" style={{ color: isExpired ? '#ef4444' : 'var(--text-tertiary)' }}>
                    {cloud.lastScan}
                  </td>
                  <td className="py-3 px-4">
                    {isExpired ? (
                      <span className="flex items-center gap-1 text-xs font-semibold" style={{ color: '#ef4444' }}>
                        <XCircle className="w-3.5 h-3.5" /> Creds Expired
                      </span>
                    ) : isWarning ? (
                      <span className="flex items-center gap-1 text-xs font-semibold" style={{ color: '#f97316' }}>
                        <AlertTriangle className="w-3.5 h-3.5" /> Warning
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-xs font-semibold" style={{ color: '#22c55e' }}>
                        <CheckCircle className="w-3.5 h-3.5" /> Active
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
