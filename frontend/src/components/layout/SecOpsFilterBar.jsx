'use client';

/**
 * SecOpsFilterBar — SecOps-specific scope bar.
 *
 * Replaces the cloud-infrastructure GlobalFilterBar on /secops/* routes.
 * Shows: Project · Scanner type · Severity · Status · Date Range
 *
 * All state lives in SecOpsFilterContext so that secops/page.jsx
 * can react to filter changes.
 */

import { Code2, ShieldAlert, CheckCircle, Clock, ChevronDown, X, GitBranch } from 'lucide-react';
import { useSecOpsFilters } from '@/lib/secops-filter-context';

function FilterSelect({ icon: Icon, value, onChange, children, defaultVal = '' }) {
  const active = value && value !== defaultVal;
  return (
    <div className="relative flex-shrink-0">
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="appearance-none pl-7 pr-6 py-1.5 text-xs rounded-lg border cursor-pointer transition-colors"
        style={{
          backgroundColor: active ? 'var(--accent-primary)18' : 'var(--bg-secondary)',
          borderColor:     active ? 'var(--accent-primary)' : 'var(--border-primary)',
          color:           active ? 'var(--accent-primary)' : 'var(--text-muted)',
          minWidth: 140,
        }}
      >
        {children}
      </select>
      <Icon
        className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 pointer-events-none"
        style={{ color: active ? 'var(--accent-primary)' : 'var(--text-muted)' }}
      />
      <ChevronDown
        className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 pointer-events-none"
        style={{ color: active ? 'var(--accent-primary)' : 'var(--text-muted)' }}
      />
    </div>
  );
}

export default function SecOpsFilterBar() {
  const {
    scanner,   setScanner,
    severity,  setSeverity,
    status,    setStatus,
    timeRange, setTimeRange,
    project,   setProject,
    availableProjects,
    clearAll,
  } = useSecOpsFilters();

  const hasActive = scanner || severity || status || project || timeRange !== '30d';

  return (
    <div
      className="border-b"
      style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
    >
      <div className="flex items-center gap-2 px-4 py-2 flex-wrap">

        {/* Label */}
        <span
          className="text-[10px] font-bold uppercase tracking-widest flex-shrink-0 mr-1"
          style={{ color: 'var(--text-muted)' }}
        >
          Filters
        </span>

        {/* Project / Repo */}
        {availableProjects.length > 0 && (
          <FilterSelect icon={GitBranch} value={project} onChange={setProject}>
            <option value="">All Projects</option>
            {availableProjects.map(p => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </FilterSelect>
        )}

        {/* Scanner type */}
        <FilterSelect icon={Code2} value={scanner} onChange={setScanner}>
          <option value="">All Scanners</option>
          <option value="sast">SAST — Code Analysis</option>
          <option value="dast">DAST — Runtime Testing</option>
          <option value="sca">SCA — Dependencies</option>
        </FilterSelect>

        {/* Severity */}
        <FilterSelect icon={ShieldAlert} value={severity} onChange={setSeverity}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </FilterSelect>

        {/* Status */}
        <FilterSelect icon={CheckCircle} value={status} onChange={setStatus}>
          <option value="">All Status</option>
          <option value="completed">Completed</option>
          <option value="running">Running</option>
          <option value="failed">Failed</option>
          <option value="pending">Pending</option>
        </FilterSelect>

        {/* Divider */}
        <div className="h-5 w-px flex-shrink-0" style={{ backgroundColor: 'var(--border-primary)' }} />

        {/* Time range */}
        <FilterSelect icon={Clock} value={timeRange} onChange={setTimeRange} defaultVal="30d">
          <option value="7d">Last 7 Days</option>
          <option value="30d">Last 30 Days</option>
          <option value="90d">Last 90 Days</option>
          <option value="180d">Last 6 Months</option>
          <option value="365d">Last Year</option>
        </FilterSelect>

        {/* Clear button */}
        {hasActive && (
          <div className="ml-auto flex-shrink-0">
            <button
              onClick={clearAll}
              className="flex items-center gap-1 text-[11px] font-medium px-2 py-1 rounded-lg transition-opacity hover:opacity-70"
              style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-tertiary)' }}
            >
              <X className="w-3 h-3" />
              Reset
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
