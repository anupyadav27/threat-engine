'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Shield, ChevronRight, AlertTriangle, Activity,
  ChevronDown, ChevronUp, Clock, Users, Target, ArrowRight,
  ExternalLink,
} from 'lucide-react';
import { getFromEngine } from '@/lib/api';
import KpiCard from '@/components/shared/KpiCard';
import SeverityBadge from '@/components/shared/SeverityBadge';
import CloudServiceIcon, { getServiceColor } from '@/components/shared/CloudServiceIcon';

const parseTechniqueCode  = t => { const m = t.match(/T\d{4}/);  return m ? m[0] : t.split(' - ')[0]; };
const parseTechniqueLabel = t => { const p = t.split(' - '); return p.length > 1 ? p.slice(1).join(' - ') : t; };


// ── Blast radius badge ────────────────────────────────────────────────────────
function BlastRadius({ level }) {
  const styles = {
    CRITICAL: { bg: 'rgba(239,68,68,0.15)',  text: '#ef4444', border: 'rgba(239,68,68,0.35)'  },
    HIGH:     { bg: 'rgba(249,115,22,0.15)', text: '#f97316', border: 'rgba(249,115,22,0.35)' },
    MEDIUM:   { bg: 'rgba(234,179,8,0.15)',  text: '#eab308', border: 'rgba(234,179,8,0.35)'  },
    LOW:      { bg: 'rgba(34,197,94,0.15)',  text: '#22c55e', border: 'rgba(34,197,94,0.35)'  },
  };
  const s = styles[level] || styles.MEDIUM;
  return (
    <span className="text-[10px] px-2 py-0.5 rounded border font-semibold uppercase tracking-wide"
      style={{ backgroundColor: s.bg, color: s.text, borderColor: s.border }}>
      {level} Blast Radius
    </span>
  );
}

// ── Single step node + connector ──────────────────────────────────────────────
function StepNode({ step, edgeTechnique, isLast }) {
  const color     = getServiceColor(step.resource_type);
  const riskColor = step.risk_score >= 80 ? '#ef4444' : step.risk_score >= 60 ? '#f97316' : '#22c55e';

  return (
    <div className="flex items-start gap-0 flex-shrink-0">
      {/* Node */}
      <div className="flex flex-col items-center gap-1.5" style={{ minWidth: 106 }}>
        {/* Circle with service icon */}
        <div className="relative w-14 h-14 rounded-full flex items-center justify-center border-2 shadow-lg"
          style={{ backgroundColor: color + '18', borderColor: color, boxShadow: `0 0 18px ${color}33` }}>
          <CloudServiceIcon service={step.resource_type} size={28} />
          {/* Risk score pill */}
          <div className="absolute -top-1.5 -right-1.5 min-w-[22px] h-[18px] px-1 rounded-full text-[9px] font-bold flex items-center justify-center border border-black/30"
            style={{ backgroundColor: riskColor, color: '#fff' }}>
            {step.risk_score}
          </div>
        </div>
        {/* Labels */}
        <div className="text-center max-w-[106px]">
          <p className="text-[10px] font-bold uppercase tracking-wider leading-none" style={{ color }}>
            {step.resource_type}
          </p>
          <p className="text-xs font-semibold mt-0.5 leading-tight truncate max-w-[102px]"
            style={{ color: 'var(--text-primary)' }} title={step.resource_name}>
            {step.resource_name}
          </p>
        </div>
      </div>

      {/* Connector: edge with technique label */}
      {!isLast && (
        <div className="flex flex-col items-center flex-shrink-0 pt-5" style={{ minWidth: 110 }}>
          {/* Technique code badge */}
          <span className="text-[10px] px-2 py-0.5 rounded-full font-bold mb-1"
            style={{ backgroundColor: 'rgba(239,68,68,0.12)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.25)' }}>
            {parseTechniqueCode(edgeTechnique)}
          </span>
          {/* Arrow line */}
          <div className="flex items-center w-full">
            <div className="flex-1 h-px" style={{ backgroundColor: 'var(--border-primary)' }} />
            <ArrowRight className="w-4 h-4 flex-shrink-0" style={{ color: 'var(--text-muted)' }} />
          </div>
          {/* Technique label */}
          <p className="text-[10px] text-center mt-0.5 px-1" style={{ color: 'var(--text-muted)', lineHeight: 1.3 }}>
            {parseTechniqueLabel(edgeTechnique)}
          </p>
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function AttackPathsPage() {
  const router = useRouter();
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState(null);
  const [attackPaths, setAttackPaths]   = useState([]);
  const [expandedPath, setExpandedPath] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const res = await getFromEngine('threat', '/api/v1/graph/attack-paths', { scan_run_id: 'latest' });
        if (res && !res.error && res.attack_paths) {
          setAttackPaths(res.attack_paths);
        }
      } catch (err) {
        setError('Failed to load attack paths. Please check that the Threat engine is running.');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const criticalPaths = attackPaths.filter(p => p.severity === 'critical').length;
  const highPaths     = attackPaths.filter(p => p.severity === 'high').length;
  const activePaths   = attackPaths.filter(p => p.status === 'active').length;

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2">
        <button onClick={() => router.push('/threats')} className="text-sm hover:opacity-80 transition-opacity"
          style={{ color: 'var(--text-muted)' }}>
          Threats
        </button>
        <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Attack Paths</h1>
      </div>

      {/* Error state */}
      {error && attackPaths.length === 0 && (
        <div className="rounded-lg p-4 border" style={{ backgroundColor: '#dc26262a', borderColor: '#ef4444' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error}</p>
        </div>
      )}

      {/* No data empty state */}
      {!loading && !error && attackPaths.length === 0 && (
        <div className="rounded-lg p-6 border text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No attack paths detected</p>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Paths"  value={attackPaths.length} subtitle="Attack chains detected" icon={<Shield className="w-5 h-5" />}       color="blue"   />
        <KpiCard title="Critical"     value={criticalPaths}       subtitle="Immediate remediation"  icon={<AlertTriangle className="w-5 h-5" />} color="red"    />
        <KpiCard title="High"         value={highPaths}           subtitle="High severity"          icon={<AlertTriangle className="w-5 h-5" />} color="orange" />
        <KpiCard title="Active"       value={activePaths}         subtitle="Currently active"       icon={<Activity className="w-5 h-5" />}      color="red"    />
      </div>

      {/* Attack Path Cards */}
      <div className="space-y-5">
        {loading
          ? [...Array(3)].map((_, i) => (
              <div key={i} className="h-44 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)' }} />
            ))
          : attackPaths.map(path => {
              const isExpanded   = expandedPath === path.path_id;
              const sevColor     = path.severity === 'critical' ? '#ef4444' : path.severity === 'high' ? '#f97316' : '#eab308';

              return (
                <div key={path.path_id}
                  className="rounded-xl border overflow-hidden transition-all duration-200"
                  style={{
                    backgroundColor: 'var(--bg-card)',
                    borderColor: isExpanded ? sevColor : 'var(--border-primary)',
                    boxShadow: isExpanded ? `0 0 0 1px ${sevColor}33, 0 4px 24px ${sevColor}11` : 'none',
                  }}>

                  {/* ── Card header ── */}
                  <div className="p-5 border-b" style={{ borderColor: 'var(--border-primary)' }}>
                    <div className="flex items-start justify-between gap-4">
                      {/* Left: severity stripe + title block */}
                      <div className="flex items-start gap-3 flex-1 min-w-0">
                        {/* Severity accent bar */}
                        <div className="w-1 self-stretch rounded-full flex-shrink-0 mt-0.5" style={{ backgroundColor: sevColor }} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center flex-wrap gap-2 mb-1">
                            <SeverityBadge severity={path.severity} />
                            <code className="text-xs" style={{ color: 'var(--text-muted)' }}>{path.path_id}</code>
                          </div>
                          <h3 className="text-base font-bold leading-snug" style={{ color: 'var(--text-primary)' }}>{path.title}</h3>
                          <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>{path.description}</p>
                        </div>
                      </div>

                      {/* Right: status + expand */}
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <span className="text-xs px-2.5 py-1 rounded-full font-semibold"
                          style={{
                            backgroundColor: path.status === 'active' ? 'rgba(239,68,68,0.12)' : 'rgba(59,130,246,0.12)',
                            color: path.status === 'active' ? '#ef4444' : 'var(--accent-primary)',
                          }}>
                          {path.status}
                        </span>
                        <button
                          onClick={() => setExpandedPath(isExpanded ? null : path.path_id)}
                          className="p-1.5 rounded-lg transition-colors hover:opacity-80"
                          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>

                    {/* Metadata row */}
                    <div className="flex items-center flex-wrap gap-4 mt-3 pl-4">
                      <span className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                        <Target className="w-3.5 h-3.5" />
                        {path.steps.length}-hop chain
                      </span>
                      <span className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                        <Users className="w-3.5 h-3.5" />
                        {path.affected_resources} affected resources
                      </span>
                      <BlastRadius level={path.blast_radius} />
                      <span className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--text-muted)' }}>
                        <Clock className="w-3.5 h-3.5" />
                        {new Date(path.detected_at).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  {/* ── Visual attack chain ── */}
                  <div className="px-5 pt-4 pb-5">
                    {/* MITRE tactics pills */}
                    <div className="flex items-center flex-wrap gap-2 mb-4">
                      <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                        MITRE Tactics:
                      </span>
                      {path.mitre_tactics.map((tactic, i) => (
                        <span key={i} className="text-[10px] px-2 py-0.5 rounded font-medium"
                          style={{ backgroundColor: 'rgba(99,102,241,0.12)', color: '#818cf8', border: '1px solid rgba(99,102,241,0.25)' }}>
                          {tactic}
                        </span>
                      ))}
                    </div>

                    {/* Chain nodes */}
                    <div className="flex items-start overflow-x-auto pb-2">
                      {path.steps.map((step, idx) => (
                        <StepNode
                          key={idx}
                          step={step}
                          isLast={idx === path.steps.length - 1}
                          edgeTechnique={idx < path.steps.length - 1 ? path.steps[idx + 1].technique : ''}
                        />
                      ))}
                    </div>
                  </div>

                  {/* ── Expanded remediation detail ── */}
                  {isExpanded && (
                    <div className="border-t p-5 space-y-3"
                      style={{ borderColor: 'var(--border-primary)', backgroundColor: 'var(--bg-secondary)' }}>
                      <p className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                        Step-by-Step Details
                      </p>
                      {path.steps.map((step, idx) => {
                        const stepColor = getServiceColor(step.resource_type);
                        const riskColor = step.risk_score >= 80 ? '#ef4444' : step.risk_score >= 60 ? '#f97316' : '#22c55e';
                        return (
                          <div key={idx} className="flex gap-3">
                            {/* Step number + connector line */}
                            <div className="flex flex-col items-center flex-shrink-0">
                              <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold text-white"
                                style={{ backgroundColor: sevColor }}>
                                {idx + 1}
                              </div>
                              {idx < path.steps.length - 1 && (
                                <div className="w-px flex-1 mt-1" style={{ backgroundColor: 'var(--border-primary)', minHeight: 20 }} />
                              )}
                            </div>

                            {/* Step detail card */}
                            <div className="flex-1 rounded-lg p-3 border mb-2"
                              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
                              <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                                <CloudServiceIcon service={step.resource_type} size={16} />
                                <span className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
                                  {step.resource_name}
                                </span>
                                <span className="text-[10px] px-2 py-0.5 rounded font-medium"
                                  style={{ backgroundColor: stepColor + '22', color: stepColor }}>
                                  {step.resource_type}
                                </span>
                                <span className="ml-auto text-sm font-bold" style={{ color: riskColor }}>
                                  Risk {step.risk_score}
                                </span>
                              </div>
                              <p className="text-[11px] font-mono mb-2" style={{ color: 'var(--text-muted)' }}>
                                {step.resource_arn}
                              </p>
                              <span className="text-[10px] px-2 py-0.5 rounded font-medium"
                                style={{ backgroundColor: 'rgba(239,68,68,0.1)', color: '#ef4444', border: '1px solid rgba(239,68,68,0.2)' }}>
                                {step.technique}
                              </span>
                            </div>
                          </div>
                        );
                      })}

                      <a href="/misconfig"
                        className="inline-flex items-center gap-1.5 text-xs font-medium hover:opacity-75 transition-opacity"
                        style={{ color: 'var(--accent-primary)' }}>
                        <ExternalLink className="w-3.5 h-3.5" />
                        View related misconfigurations →
                      </a>
                    </div>
                  )}
                </div>
              );
            })}
      </div>
    </div>
  );
}
