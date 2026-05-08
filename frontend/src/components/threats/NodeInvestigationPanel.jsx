'use client';

import { useState, useEffect, useCallback } from 'react';
import { X, Copy, Check, ExternalLink, Globe, AlertTriangle, ChevronDown, ChevronRight } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { fetchView } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';
import SeverityBadge from '@/components/shared/SeverityBadge';
import { ConfigPropertiesTable } from '@/components/graph/ConfigPropertiesTable';

function PanelSkeleton() {
  return (
    <div className="space-y-4 animate-pulse p-6">
      <div className="h-5 rounded w-48" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      <div className="h-4 rounded w-32" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      <div className="h-px w-full" style={{ backgroundColor: 'var(--border-primary)' }} />
      <div className="space-y-2">
        {[1, 2, 3].map((n) => (
          <div key={n} className="h-8 rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CollapsibleSection — expandable/collapsible wrapper used for the new sections
// ---------------------------------------------------------------------------
function CollapsibleSection({ title, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="border-b" style={{ borderColor: 'var(--border-primary)' }}>
      <button
        className="w-full flex items-center justify-between px-6 py-3 text-left hover:opacity-80 transition-opacity"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <span className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>
          {title}
        </span>
        {open
          ? <ChevronDown className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
          : <ChevronRight className="w-3.5 h-3.5 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
        }
      </button>
      {open && (
        <div className="px-6 pb-4">
          {children}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// CVEMiniList — compact CVE list for the panel (distinct from graph CVEDetailPanel)
// ---------------------------------------------------------------------------

const SEV_COLORS = {
  critical: '#d32f2f',
  high: '#f57c00',
  medium: '#f9a825',
  low: '#388e3c',
};

function CveSeverityBadge({ severity }) {
  const color = SEV_COLORS[(severity || '').toLowerCase()] || '#9e9e9e';
  return (
    <span
      className="inline-block text-[10px] font-bold px-1.5 py-0.5 rounded-full uppercase"
      style={{ backgroundColor: `${color}22`, color, border: `1px solid ${color}44` }}
    >
      {severity || 'unknown'}
    </span>
  );
}

function CVEMiniList({ cves, userRole }) {
  const canSeePrivileged = userRole !== 'viewer' && userRole !== 'analyst';

  return (
    <div className="space-y-1.5">
      {cves.map((cve, idx) => {
        const isCritical = (cve.severity || '').toLowerCase() === 'critical';
        return (
          <div
            key={cve.cve_id || idx}
            className="flex items-center gap-2 px-2 py-1.5 rounded"
            style={{ backgroundColor: isCritical ? '#ffebee' : 'var(--bg-secondary)' }}
          >
            <code
              className="text-[11px] font-mono flex-1 truncate"
              style={{ color: 'var(--text-primary)' }}
              title={cve.cve_id}
            >
              {cve.cve_id}
            </code>
            <CveSeverityBadge severity={cve.severity} />
            {cve.cvss_score != null && (
              <span className="text-[10px] font-mono whitespace-nowrap" style={{ color: 'var(--text-secondary)' }}>
                CVSS {cve.cvss_score.toFixed(1)}
              </span>
            )}
            {canSeePrivileged && cve.in_kev && (
              <span
                className="text-[10px] font-bold px-1 py-0.5 rounded"
                style={{ backgroundColor: 'rgba(239,68,68,0.15)', color: '#ef4444' }}
              >
                KEV
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main panel
// ---------------------------------------------------------------------------

/**
 * Slide-over panel that opens when a node in the Attack Path SVG is clicked.
 *
 * Props:
 *   step     {object|null}  — Enriched attack chain step (from attackPath.steps[n])
 *   mitre    {object}       — Full mitre object from BFF (mitre.allTechniques array)
 *   onClose  {func}         — Called to close panel
 *   isOpen   {bool}         — Controls panel visibility
 */
export default function NodeInvestigationPanel({ step, mitre, onClose, isOpen }) {
  const router = useRouter();
  const { role: userRole } = useAuth();
  const [misconfigs, setMisconfigs] = useState([]);
  const [loadingMisconfigs, setLoadingMisconfigs] = useState(false);
  const [misconfigError, setMisconfigError] = useState(false);
  const [copied, setCopied] = useState(false);
  const [securityData, setSecurityData] = useState(null);

  // Load misconfigs for this node when the panel opens
  useEffect(() => {
    if (!isOpen || !step || step.isInternetReachable) return;

    const resourceUid = step.to || step.from || '';
    if (!resourceUid) return;

    setLoadingMisconfigs(true);
    setMisconfigError(false);
    setMisconfigs([]);

    fetchView(`threats/resources/${encodeURIComponent(resourceUid)}/posture`)
      .then((data) => {
        const findings = Array.isArray(data)
          ? data
          : data?.findings || data?.check_findings || [];
        setMisconfigs(findings.slice(0, 10));
        setLoadingMisconfigs(false);
      })
      .catch(() => {
        setMisconfigError(true);
        setLoadingMisconfigs(false);
      });
  }, [isOpen, step]);

  // Fetch node security data (config properties + CVEs) when the panel opens
  useEffect(() => {
    if (!isOpen || !step) {
      setSecurityData(null);
      return;
    }
    const resourceUid = step.to || step.from || '';
    if (!resourceUid) return;

    fetchView(`threats/graph/node-security/${encodeURIComponent(resourceUid)}`)
      .then((data) => {
        if (data && typeof data === 'object') {
          setSecurityData(data);
        }
      })
      .catch(() => {
        // Non-critical — silently ignore; sections simply won't appear
      });
  }, [isOpen, step]);

  // Close on Escape key
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape' && isOpen) onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [isOpen, onClose]);

  // Reset state when closed
  useEffect(() => {
    if (!isOpen) {
      setMisconfigs([]);
      setMisconfigError(false);
      setCopied(false);
      setSecurityData(null);
    }
  }, [isOpen]);

  const handleCopyArn = useCallback(() => {
    const arn = step?.to || step?.from || '';
    if (!arn) return;
    navigator.clipboard.writeText(arn).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [step]);

  const handleViewFullAsset = useCallback(() => {
    const arn = step?.to || '';
    if (!arn) return;
    router.push(`/inventory/${encodeURIComponent(arn)}`);
  }, [step, router]);

  if (!isOpen) return null;

  // Internet entry node — special view (no ARN, no misconfigs, no "View Full Asset")
  if (step?.isInternetReachable && step?.isEntry) {
    return (
      <>
        {/* Backdrop */}
        <div className="fixed inset-0 z-40 bg-black/30" onClick={onClose} />
        {/* Panel */}
        <div
          className="fixed right-0 top-0 h-full w-96 z-50 shadow-2xl flex flex-col"
          style={{ backgroundColor: 'var(--bg-card)', borderLeft: '1px solid var(--border-primary)' }}
        >
          <div className="flex items-center justify-between p-6 border-b" style={{ borderColor: 'var(--border-primary)' }}>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg" style={{ backgroundColor: 'rgba(59,130,246,0.1)' }}>
                <Globe className="w-5 h-5" style={{ color: '#60a5fa' }} />
              </div>
              <div>
                <h2 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>Internet</h2>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Entry point</p>
              </div>
            </div>
            <button onClick={onClose} className="p-1 rounded hover:opacity-70">
              <X className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
            </button>
          </div>
          <div className="p-6">
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              This threat originates from the public internet. The first hop represents
              an externally accessible resource that serves as the attacker entry point.
            </p>
          </div>
        </div>
      </>
    );
  }

  if (!step) return null;

  const resourceUid = step.to || '';
  const resourceName = step.toName || step.fromName || resourceUid.split('/').pop() || resourceUid.split(':').pop() || resourceUid;
  const resourceType = step.toResourceType || step.fromResourceType || '';
  const provider = step.provider || (resourceUid.startsWith('arn:aws') ? 'AWS' : '');
  const region = step.region || '';
  const techniqueId = step.technique || '';

  // Look up technique name from the mitre.allTechniques array
  const techniqueRecord = mitre?.allTechniques?.find((t) => t.id === techniqueId);
  const techniqueName = techniqueRecord?.name || techniqueId;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40 bg-black/30" onClick={onClose} />
      {/* Panel */}
      <div
        className="fixed right-0 top-0 h-full w-96 z-50 shadow-2xl flex flex-col overflow-hidden"
        style={{ backgroundColor: 'var(--bg-card)', borderLeft: '1px solid var(--border-primary)' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b flex-shrink-0" style={{ borderColor: 'var(--border-primary)' }}>
          <div className="min-w-0">
            <h2
              className="text-base font-bold truncate"
              title={resourceName}
              style={{ color: 'var(--text-primary)' }}
            >
              {resourceName}
            </h2>
            <div className="flex items-center gap-2 mt-1 flex-wrap">
              {resourceType && (
                <span className="text-xs px-2 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}>
                  {resourceType.split('::').pop() || resourceType}
                </span>
              )}
              {provider && (
                <span className="text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>
                  {provider}
                </span>
              )}
              {region && (
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  {region}
                </span>
              )}
            </div>
          </div>
          <button onClick={onClose} className="ml-4 p-1 rounded hover:opacity-70 flex-shrink-0">
            <X className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto">
          {/* ARN section */}
          {resourceUid && (
            <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
              <p className="text-xs font-medium mb-1.5" style={{ color: 'var(--text-muted)' }}>Resource ARN</p>
              <div className="flex items-center gap-2">
                <code
                  className="text-xs break-all leading-relaxed flex-1"
                  style={{ color: 'var(--text-secondary)', fontFamily: 'ui-monospace, monospace' }}
                >
                  {resourceUid}
                </code>
                <button
                  onClick={handleCopyArn}
                  className="flex-shrink-0 p-1.5 rounded hover:opacity-70"
                  title="Copy ARN"
                >
                  {copied
                    ? <Check className="w-4 h-4" style={{ color: 'var(--accent-success)' }} />
                    : <Copy className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
                  }
                </button>
              </div>
            </div>
          )}

          {/* Technique section */}
          {techniqueId && (
            <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
              <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-muted)' }}>
                Technique enabling this hop
              </p>
              <div className="flex items-start gap-2">
                <code
                  className="text-xs font-mono px-1.5 py-0.5 rounded"
                  style={{ backgroundColor: 'rgba(139,92,246,0.12)', color: '#a78bfa' }}
                >
                  {techniqueId}
                </code>
                <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                  {techniqueName !== techniqueId ? techniqueName : ''}
                </span>
              </div>
            </div>
          )}

          {/* Misconfigurations section */}
          <div className="px-6 py-4">
            <p className="text-xs font-medium mb-3" style={{ color: 'var(--text-muted)' }}>
              Misconfigurations on this resource
              {misconfigs.length > 0 && (
                <span className="ml-2 text-xs" style={{ color: 'var(--text-tertiary)' }}>
                  ({misconfigs.length}{misconfigs.length === 10 ? '+' : ''})
                </span>
              )}
            </p>

            {loadingMisconfigs && (
              <div className="space-y-2 animate-pulse">
                {[1, 2, 3].map((n) => (
                  <div key={n} className="h-8 rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
                ))}
              </div>
            )}

            {misconfigError && (
              <div className="flex items-center gap-2 py-3" style={{ color: 'var(--text-muted)' }}>
                <AlertTriangle className="w-4 h-4" />
                <span className="text-xs">Could not load misconfigurations</span>
              </div>
            )}

            {!loadingMisconfigs && !misconfigError && misconfigs.length === 0 && (
              <p className="text-xs py-2" style={{ color: 'var(--text-muted)' }}>
                No active misconfigurations found
              </p>
            )}

            {!loadingMisconfigs && !misconfigError && misconfigs.length > 0 && (
              <div className="space-y-2">
                {misconfigs.map((m, idx) => (
                  <div
                    key={m.id || m.rule_id || idx}
                    className="flex items-center justify-between gap-3 px-3 py-2 rounded-lg"
                    style={{ backgroundColor: 'var(--bg-secondary)' }}
                  >
                    <span
                      className="text-xs font-mono truncate"
                      style={{ color: 'var(--text-secondary)' }}
                      title={m.title || m.rule_id}
                    >
                      {m.title || m.rule_id}
                    </span>
                    <SeverityBadge severity={m.severity} />
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Config Properties — collapsed by default when no FAILs */}
          {securityData?.configProperties?.length > 0 && (
            <CollapsibleSection
              title={`Config Properties${securityData.failCount > 0 ? ` (${securityData.failCount} FAIL)` : ''}`}
              defaultOpen={securityData.failCount > 0}
            >
              <ConfigPropertiesTable nodeProperties={
                // configProperties is already an array from BFF; convert to nodeProperties flat map
                // by rebuilding the prop_* key structure ConfigPropertiesTable expects
                Object.fromEntries(
                  securityData.configProperties.flatMap((p) => {
                    const key = `prop_${(p.name || '').toLowerCase().replace(/\s+/g, '_')}`;
                    const passKey = `${key}_pass`;
                    return [[key, p.value], [passKey, p.pass]];
                  })
                )
              } />
            </CollapsibleSection>
          )}

          {/* CVEs — hidden entirely for viewer role; collapsed by default when no CRITICALs */}
          {userRole !== 'viewer' &&
           securityData?.cves?.length > 0 && (
            <CollapsibleSection
              title={`CVEs (${securityData.cveCount ?? securityData.cves.length} total${
                securityData.criticalCveCount ? ` — ${securityData.criticalCveCount} CRITICAL` : ''
              })`}
              defaultOpen={securityData.criticalCveCount > 0}
            >
              <CVEMiniList
                cves={[...securityData.cves]
                  .sort((a, b) => (b.cvss_score ?? 0) - (a.cvss_score ?? 0))
                  .slice(0, 10)}
                userRole={userRole}
              />
            </CollapsibleSection>
          )}
        </div>

        {/* Footer — View Full Asset */}
        {resourceUid && (
          <div className="flex-shrink-0 p-6 border-t" style={{ borderColor: 'var(--border-primary)' }}>
            <button
              onClick={handleViewFullAsset}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-opacity hover:opacity-80"
              style={{ backgroundColor: 'var(--accent-primary)', color: '#fff' }}
            >
              View Full Asset
              <ExternalLink className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </>
  );
}
