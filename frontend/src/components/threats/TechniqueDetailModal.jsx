'use client';

import { useState, useEffect } from 'react';
import { X, ExternalLink } from 'lucide-react';
import { fetchView } from '@/lib/api';

function ModalSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="h-4 rounded w-24" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      <div className="h-16 rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      <div className="h-4 rounded w-48" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      <div className="h-4 rounded w-36" style={{ backgroundColor: 'var(--bg-secondary)' }} />
    </div>
  );
}

/**
 * Props:
 *   techniqueId  {string|null}  — MITRE technique ID e.g. "T1530" or null when closed
 *   onClose      {func}         — Called to close the modal
 *   isOpen       {bool}         — Controls modal visibility
 */
export default function TechniqueDetailModal({ techniqueId, onClose, isOpen }) {
  const [techniqueData, setTechniqueData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!isOpen || !techniqueId) return;

    setLoading(true);
    setError(null);
    setTechniqueData(null);

    fetchView(`threats/technique/${techniqueId}`)
      .then((data) => {
        if (data?.detail === 'Technique not found' || !data?.techniqueId) {
          setError('Technique details not available');
        } else {
          setTechniqueData(data);
        }
        setLoading(false);
      })
      .catch(() => {
        setError('Technique details not available');
        setLoading(false);
      });
  }, [isOpen, techniqueId]);

  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape' && isOpen) onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-lg rounded-2xl shadow-2xl"
        style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <div>
            <h2 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>
              {loading ? techniqueId : `${techniqueData?.techniqueId || techniqueId} — ${techniqueData?.techniqueName || ''}`}
            </h2>
            {techniqueData?.tactics?.length > 0 && (
              <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
                Tactic: {techniqueData.tactics.join(', ')}
              </p>
            )}
          </div>
          <button onClick={onClose} className="ml-4 p-1 rounded hover:bg-opacity-10 flex-shrink-0">
            <X className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 max-h-[60vh] overflow-y-auto">
          {loading && <ModalSkeleton />}

          {error && (
            <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>
              {error}
            </p>
          )}

          {!loading && !error && techniqueData && (
            <>
              <a
                href={techniqueData.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-sm font-medium"
                style={{ color: 'var(--accent-primary)' }}
              >
                View on MITRE ATT&CK
                <ExternalLink className="w-3 h-3" />
              </a>

              <div className="p-4 rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }}>
                <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-muted)' }}>
                  In your environment
                </p>
                <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
                  {techniqueData.affectedResources}
                  <span className="text-sm font-normal ml-2" style={{ color: 'var(--text-secondary)' }}>
                    resources affected
                  </span>
                </p>
                <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
                  {techniqueData.detectionCount} detections
                </p>
              </div>

              {techniqueData.d3fendMappings?.length > 0 && (
                <div>
                  <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-muted)' }}>
                    D3FEND Countermeasures
                  </p>
                  <ul className="space-y-1">
                    {techniqueData.d3fendMappings.map((m) => (
                      <li key={m.id} className="text-sm flex items-start gap-2" style={{ color: 'var(--text-secondary)' }}>
                        <span className="mt-1 flex-shrink-0 w-1.5 h-1.5 rounded-full" style={{ backgroundColor: 'var(--accent-primary)' }} />
                        <span>
                          <code className="text-xs mr-2" style={{ color: 'var(--text-muted)' }}>{m.id}</code>
                          {m.label}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {techniqueData.complianceControls && Object.keys(techniqueData.complianceControls).length > 0 && (
                <div>
                  <p className="text-xs font-medium mb-2" style={{ color: 'var(--text-muted)' }}>
                    Compliance Controls
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(techniqueData.complianceControls).map(([framework, control]) => (
                      <span
                        key={framework}
                        className="text-xs px-2 py-1 rounded"
                        style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)' }}
                      >
                        {framework}: {typeof control === 'string' ? control : JSON.stringify(control)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
