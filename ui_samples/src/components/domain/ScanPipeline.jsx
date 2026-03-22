'use client';

import { useMemo } from 'react';

/**
 * ScanPipeline Component
 * Horizontal pipeline visualization showing scan stages and their statuses
 *
 * @param {Object} props
 * @param {Array<{name: string, status: 'completed'|'running'|'pending'|'failed', duration?: string}>} props.stages - Pipeline stages
 * @returns {JSX.Element}
 */
export default function ScanPipeline({
  stages = [
    { name: 'Discovery', status: 'completed' },
    { name: 'Check', status: 'completed' },
    { name: 'Inventory', status: 'running' },
    { name: 'Threat', status: 'pending' },
    { name: 'Compliance', status: 'pending' }
  ]
}) {
  const getStatusColor = (status) => {
    switch (status) {
      case 'completed':
        return { circle: 'bg-green-400', icon: '✓' };
      case 'running':
        return { circle: 'bg-blue-400 animate-pulse', icon: '⟳' };
      case 'pending':
        return { circle: 'bg-slate-600', icon: '-' };
      case 'failed':
        return { circle: 'bg-red-400', icon: '✕' };
      default:
        return { circle: 'bg-slate-600', icon: '-' };
    }
  };

  const getConnectorStyle = (index, stages) => {
    const currentStage = stages[index];
    const isCompleted = currentStage?.status === 'completed';
    return {
      connector: isCompleted ? 'bg-green-400' : 'bg-slate-600',
      dashed: !isCompleted
    };
  };

  return (
    <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }} className="rounded-xl p-6 border transition-colors duration-200">
      <h3 style={{ color: 'var(--text-primary)' }} className="text-sm font-semibold mb-6">Scan Pipeline</h3>
      <div className="flex items-center justify-between gap-2">
        {stages.map((stage, index) => {
          const statusColor = getStatusColor(stage.status);
          const connector = getConnectorStyle(index, stages);
          const isLastStage = index === stages.length - 1;

          return (
            <div key={`stage-${index}`} className="flex items-center flex-1">
              {/* Stage Circle */}
              <div className="flex flex-col items-center">
                <div
                  className={`w-10 h-10 rounded-full ${statusColor.circle} flex items-center justify-center text-white font-bold text-sm transition-all duration-300 flex-shrink-0`}
                >
                  {statusColor.icon}
                </div>
                <div className="mt-2 text-center">
                  <p style={{ color: 'var(--text-primary)' }} className="text-xs font-medium whitespace-nowrap">
                    {stage.name}
                  </p>
                  {stage.duration && (
                    <p style={{ color: 'var(--text-tertiary)' }} className="text-xs mt-1">{stage.duration}</p>
                  )}
                </div>
                {stage.status === 'running' && (
                  <div className="mt-2 text-xs text-blue-400 font-medium">
                    Running
                  </div>
                )}
              </div>

              {/* Connector Line */}
              {!isLastStage && (
                <div className="flex-1 h-1 mx-2 mt-(-4) relative" style={{ marginTop: '-40px' }}>
                  <div
                    className={`h-full ${connector.connector} transition-all duration-300`}
                    style={{
                      backgroundImage: connector.dashed
                        ? 'repeating-linear-gradient(90deg, currentColor, currentColor 2px, transparent 2px, transparent 6px)'
                        : undefined
                    }}
                  />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Status Summary */}
      <div style={{ borderTopColor: 'var(--border-primary)' }} className="mt-6 pt-6 border-t flex justify-between text-xs transition-colors duration-200">
        <div className="flex gap-4">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-green-400 rounded-full" />
            <span style={{ color: 'var(--text-tertiary)' }}>
              Completed: {stages.filter(s => s.status === 'completed').length}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
            <span style={{ color: 'var(--text-tertiary)' }}>
              Running: {stages.filter(s => s.status === 'running').length}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 bg-slate-600 rounded-full" />
            <span style={{ color: 'var(--text-tertiary)' }}>
              Pending: {stages.filter(s => s.status === 'pending').length}
            </span>
          </div>
          {stages.some(s => s.status === 'failed') && (
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 bg-red-400 rounded-full" />
              <span style={{ color: 'var(--text-tertiary)' }}>
                Failed: {stages.filter(s => s.status === 'failed').length}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
