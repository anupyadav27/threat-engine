'use client';

import { CheckCircle2, Loader2, Clock, XCircle, ChevronRight } from 'lucide-react';

const PIPELINE_STAGES = [
  { key: 'discovery',  label: 'Discovery',  layer: 1 },
  { key: 'inventory',  label: 'Inventory',  layer: 1 },
  { key: 'check',      label: 'Check',      layer: 2 },
  { key: 'threat',     label: 'Threat',     layer: 3 },
  { key: 'compliance', label: 'Compliance', layer: 4 },
  { key: 'iam',        label: 'IAM',        layer: 4 },
  { key: 'network',    label: 'Network',    layer: 4 },
  { key: 'datasec',    label: 'DataSec',    layer: 4 },
  { key: 'risk',       label: 'Risk',       layer: 5 },
];

const STAGE_STATUS = {
  completed: { icon: CheckCircle2, color: '#22c55e',  bg: 'rgba(34,197,94,0.12)',   label: 'Done' },
  running:   { icon: Loader2,      color: '#60a5fa',  bg: 'rgba(96,165,250,0.12)',  label: 'Running', spin: true },
  failed:    { icon: XCircle,      color: '#ef4444',  bg: 'rgba(239,68,68,0.12)',   label: 'Failed' },
  pending:   { icon: Clock,        color: '#6b7280',  bg: 'var(--bg-tertiary)',     label: 'Waiting' },
};

function getEngineStatus(key, progress) {
  if (!progress) return 'pending';
  const engineStatuses = progress.engine_statuses || {};
  if (engineStatuses[key]?.status === 'completed') return 'completed';
  if (engineStatuses[key]?.status === 'failed')    return 'failed';
  if (engineStatuses[key]?.status === 'running')   return 'running';
  if (progress.current_engine === key)             return 'running';
  if ((progress.engines_completed || []).includes(key)) return 'completed';
  return 'pending';
}

function StageBadge({ stage, status, findings }) {
  const s   = STAGE_STATUS[status] || STAGE_STATUS.pending;
  const Icon = s.icon;

  return (
    <div
      className="flex flex-col items-center gap-1.5 p-3 rounded-xl border min-w-[72px] text-center"
      style={{ backgroundColor: s.bg, borderColor: status === 'pending' ? 'var(--border-primary)' : `${s.color}40` }}
    >
      <Icon
        size={18}
        style={{ color: s.color }}
        className={s.spin ? 'animate-spin' : ''}
      />
      <span className="text-[11px] font-medium" style={{ color: 'var(--text-secondary)' }}>
        {stage.label}
      </span>
      {findings != null && (
        <span className="text-[10px]" style={{ color: s.color }}>
          {findings} findings
        </span>
      )}
      <span className="text-[9px] uppercase tracking-wide" style={{ color: s.color }}>
        {s.label}
      </span>
    </div>
  );
}

export default function ScanPipelineProgress({ scanRunId, progress }) {
  const overallDone = progress?.overall_status === 'completed';
  const overallFailed = progress?.overall_status === 'failed';

  return (
    <div className="space-y-4">
      {/* Overall status banner */}
      {(overallDone || overallFailed) && (
        <div
          className="flex items-center gap-2.5 p-3 rounded-xl border text-sm font-medium"
          style={{
            borderColor: overallDone ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)',
            backgroundColor: overallDone ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
            color: overallDone ? '#22c55e' : '#ef4444',
          }}
        >
          {overallDone ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
          {overallDone ? 'Scan completed successfully' : 'Scan failed — see engine details below'}
        </div>
      )}

      {/* Pipeline stages */}
      <div className="flex items-start gap-2 flex-wrap">
        {PIPELINE_STAGES.map((stage, idx) => {
          const status = getEngineStatus(stage.key, progress);
          const findings = progress?.engine_statuses?.[stage.key]?.findings;
          const isParallel = stage.layer === 4;
          const prevIsParallel = idx > 0 && PIPELINE_STAGES[idx - 1].layer === 4;

          return (
            <div key={stage.key} className="flex items-center gap-2">
              {idx > 0 && !isParallel && !prevIsParallel && (
                <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />
              )}
              {isParallel && idx > 0 && PIPELINE_STAGES[idx - 1].layer !== 4 && (
                <ChevronRight size={14} style={{ color: 'var(--text-muted)' }} />
              )}
              <StageBadge stage={stage} status={status} findings={findings} />
            </div>
          );
        })}
      </div>

      {/* Duration / timestamps */}
      {progress && (
        <div className="text-[11px] space-y-0.5" style={{ color: 'var(--text-muted)' }}>
          {progress.started_at && <div>Started: {new Date(progress.started_at).toLocaleString()}</div>}
          {progress.completed_at && <div>Completed: {new Date(progress.completed_at).toLocaleString()}</div>}
          <div>Scan ID: <span className="font-mono">{scanRunId}</span></div>
        </div>
      )}
    </div>
  );
}
