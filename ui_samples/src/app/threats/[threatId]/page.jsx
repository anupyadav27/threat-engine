'use client';

import { useEffect, useState, useCallback, useMemo, useRef, Component } from 'react';
import { useRouter, useParams } from 'next/navigation';
import {
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Shield,
  ShieldAlert,
  Globe,
  Lock,
  Key,
  Database,
  AlertTriangle,
  CheckCircle,
  Clock,
  Copy,
  Check,
  ExternalLink,
  UserPlus,
  RefreshCw,
  EyeOff,
  Download,
  Target,
  Zap,
  Activity,
  Search,
  Crosshair,
  Layers,
  ArrowRight,
  Circle,
  Server,
  Cloud,
  XCircle,
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { fetchView, postToEngine } from '@/lib/api';
import SeverityBadge from '@/components/shared/SeverityBadge';
import DataTable from '@/components/shared/DataTable';
import EmptyState from '@/components/shared/EmptyState';
import LoadingSkeleton from '@/components/shared/LoadingSkeleton';
import SlaStatusBadge from '@/components/shared/SlaStatusBadge';

// ---------------------------------------------------------------------------
// Error Boundary: class component wrapper for catching render errors
// ---------------------------------------------------------------------------
class SectionErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-4 text-center rounded-lg" style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-secondary)' }}>
          <AlertTriangle className="w-5 h-5 mx-auto mb-2" style={{ color: 'var(--accent-warning)' }} />
          <p className="text-sm">{this.props.fallbackMessage || 'Failed to load this section'}</p>
        </div>
      );
    }
    return this.props.children;
  }
}

function SafeSection({ children, fallbackMessage }) {
  return (
    <SectionErrorBoundary fallbackMessage={fallbackMessage}>
      {children}
    </SectionErrorBoundary>
  );
}

// ---------------------------------------------------------------------------
// Toast notification component
// ---------------------------------------------------------------------------
function Toast({ message, type = 'success', onDismiss }) {
  useEffect(() => {
    const timer = setTimeout(onDismiss, 3000);
    return () => clearTimeout(timer);
  }, [onDismiss]);

  const bgColor = type === 'success' ? 'var(--accent-success)' : type === 'error' ? 'var(--accent-danger)' : 'var(--accent-primary)';

  return (
    <div
      className="fixed top-4 right-4 z-[100] flex items-center gap-2 px-4 py-2.5 rounded-lg shadow-2xl text-sm font-medium animate-in slide-in-from-right"
      style={{ backgroundColor: bgColor, color: '#fff' }}
      role="status"
      aria-live="polite"
    >
      {type === 'success' && <CheckCircle className="w-4 h-4" />}
      {type === 'error' && <XCircle className="w-4 h-4" />}
      {message}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Inline helper: CollapsibleSection
// ---------------------------------------------------------------------------
function CollapsibleSection({ title, icon, badge, defaultOpen = true, children }) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div
      className="rounded-xl border overflow-hidden"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      <button
        type="button"
        onClick={() => setIsOpen((p) => !p)}
        className="w-full flex items-center justify-between px-6 py-4 hover:opacity-90 transition-opacity"
        style={{ backgroundColor: 'var(--bg-card)' }}
      >
        <div className="flex items-center gap-3">
          {icon && <span style={{ color: 'var(--text-muted)' }}>{icon}</span>}
          <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
            {title}
          </h3>
          {badge !== undefined && badge !== null && (
            <span
              className="text-xs font-medium px-2 py-0.5 rounded-full"
              style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-muted)' }}
            >
              {badge}
            </span>
          )}
        </div>
        {isOpen ? (
          <ChevronUp className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
        ) : (
          <ChevronDown className="w-5 h-5" style={{ color: 'var(--text-muted)' }} />
        )}
      </button>
      <div
        className="transition-all duration-200 ease-in-out"
        style={{
          maxHeight: isOpen ? '5000px' : '0px',
          opacity: isOpen ? 1 : 0,
          overflow: 'hidden',
        }}
      >
        <div className="px-6 pb-6">{children}</div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Inline helper: CopyButton
// ---------------------------------------------------------------------------
function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* silent */
    }
  };

  return (
    <button
      onClick={handleCopy}
      className="p-1.5 rounded hover:opacity-75 transition-opacity"
      style={{ color: 'var(--text-muted)' }}
      title="Copy to clipboard"
    >
      {copied ? <Check className="w-3.5 h-3.5" style={{ color: 'var(--accent-success)' }} /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Inline helper: Dropdown (for Assign / Change Status)
// ---------------------------------------------------------------------------
function ActionDropdown({ label, icon, options, onSelect }) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen((p) => !p)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg border text-sm font-medium hover:opacity-80 transition-opacity"
        style={{
          backgroundColor: 'var(--bg-secondary)',
          borderColor: 'var(--border-primary)',
          color: 'var(--text-secondary)',
        }}
      >
        {icon}
        {label}
        <ChevronDown className="w-3.5 h-3.5" />
      </button>
      {isOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
          <div
            className="absolute right-0 mt-1 z-50 min-w-[180px] rounded-lg border shadow-xl py-1"
            style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
          >
            {options.map((opt) => (
              <button
                key={opt.value}
                onClick={() => {
                  onSelect(opt.value);
                  setIsOpen(false);
                }}
                className="w-full text-left px-4 py-2 text-sm hover:opacity-75 transition-opacity"
                style={{ color: 'var(--text-secondary)' }}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function formatDate(iso) {
  if (!iso) return '--';
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function riskScoreColor(score) {
  if (score >= 80) return 'var(--accent-danger)';
  if (score >= 60) return 'var(--accent-warning)';
  if (score >= 40) return '#eab308';
  return 'var(--accent-success)';
}

const STATUS_OPTIONS = [
  { value: 'active', label: 'Active' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'suppressed', label: 'Suppressed' },
  { value: 'false_positive', label: 'False Positive' },
];

const ASSIGNEE_OPTIONS = [
  { value: 'security-team', label: 'Security Team' },
  { value: 'devops-team', label: 'DevOps Team' },
  { value: 'cloud-team', label: 'Cloud Team' },
  { value: 'soc-analyst', label: 'SOC Analyst' },
  { value: '', label: 'Unassign' },
];

// Tabs removed — detail page now shows content directly (no tab switching)

const RESOURCE_TYPE_ICONS = {
  internet: <Globe className="w-5 h-5" />,
  's3.bucket': <Database className="w-5 h-5" />,
  'ec2.instance': <Server className="w-5 h-5" />,
  'iam.role': <Key className="w-5 h-5" />,
  'elasticloadbalancing.loadbalancer': <Layers className="w-5 h-5" />,
  'lambda.function': <Zap className="w-5 h-5" />,
};

function getResourceIcon(resourceType) {
  return RESOURCE_TYPE_ICONS[resourceType] || <Cloud className="w-5 h-5" />;
}

// ---------------------------------------------------------------------------
// MAIN PAGE COMPONENT
// ---------------------------------------------------------------------------
export default function ThreatDetailPage() {
  const router = useRouter();
  const params = useParams();
  const threatId = params?.threatId;

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [toast, setToast] = useState(null);

  // Fetch threat detail from BFF
  const fetchData = useCallback(async () => {
    if (!threatId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetchView(`threats/${threatId}`);
      if (res && !res.error) {
        setData(res);
      } else {
        setError(res?.error || 'Failed to load threat data');
      }
    } catch (err) {
      setError(err?.message || 'Failed to load threat data');
    } finally {
      setLoading(false);
    }
  }, [threatId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Action handlers
  const handleStatusChange = async (newStatus) => {
    setActionLoading(true);
    try {
      await postToEngine('threat', `/api/v1/threat/${threatId}`, { status: newStatus });
      setData((prev) => prev ? { ...prev, threat: { ...prev.threat, status: newStatus } } : prev);
      setToast({ message: `Status updated to ${newStatus}`, type: 'success' });
    } catch {
      setToast({ message: 'Failed to update status', type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleAssigneeChange = async (newAssignee) => {
    setActionLoading(true);
    try {
      await postToEngine('threat', `/api/v1/threat/${threatId}`, { assignee: newAssignee });
      setData((prev) => prev ? { ...prev, threat: { ...prev.threat, assignee: newAssignee } } : prev);
      setToast({ message: newAssignee ? `Assigned to ${newAssignee}` : 'Unassigned', type: 'success' });
    } catch {
      setToast({ message: 'Failed to update assignee', type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleSuppress = async () => {
    await handleStatusChange('suppressed');
  };

  const handleExport = useCallback(() => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-${threatId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [data, threatId]);

  const handleBackNavigation = useCallback(() => {
    if (typeof document !== 'undefined' && document.referrer && document.referrer.includes('/threats')) {
      router.back();
    } else {
      router.push('/threats');
    }
  }, [router]);

  // Global Escape key handler
  useEffect(() => {
    const handleGlobalKeyDown = (e) => {
      if (e.key === 'Escape' && !loading && !error) {
        handleBackNavigation();
      }
    };
    document.addEventListener('keydown', handleGlobalKeyDown);
    return () => document.removeEventListener('keydown', handleGlobalKeyDown);
  }, [loading, error, handleBackNavigation]);

  // --- LOADING STATE ---
  if (loading) {
    return (
      <div className="space-y-6 p-6" role="status" aria-label="Loading threat details">
        {/* Breadcrumb skeleton */}
        <div className="flex items-center gap-2">
          <div className="h-4 w-16 animate-pulse rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
          <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
          <div className="h-4 w-48 animate-pulse rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
        </div>

        {/* Header card skeleton */}
        <div className="rounded-xl border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          {/* Badges */}
          <div className="flex items-center gap-3 mb-3">
            <div className="h-5 w-16 animate-pulse rounded-full" style={{ backgroundColor: 'var(--bg-secondary)' }} />
            <div className="h-5 w-20 animate-pulse rounded-full" style={{ backgroundColor: 'var(--bg-secondary)' }} />
          </div>
          {/* Title */}
          <div className="h-6 w-3/4 animate-pulse rounded mb-2" style={{ backgroundColor: 'var(--bg-secondary)' }} />
          {/* Description */}
          <div className="h-4 w-full animate-pulse rounded mb-1" style={{ backgroundColor: 'var(--bg-secondary)' }} />
          <div className="h-4 w-2/3 animate-pulse rounded mb-6" style={{ backgroundColor: 'var(--bg-secondary)' }} />
          {/* Metadata cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 mb-6">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="rounded-lg p-4 border" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}>
                <div className="h-3 w-16 animate-pulse rounded mb-2" style={{ backgroundColor: 'var(--bg-primary)' }} />
                <div className="h-7 w-12 animate-pulse rounded" style={{ backgroundColor: 'var(--bg-primary)' }} />
              </div>
            ))}
          </div>
          {/* Action buttons */}
          <div className="flex items-center gap-3">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-9 w-24 animate-pulse rounded-lg" style={{ backgroundColor: 'var(--bg-secondary)' }} />
            ))}
          </div>
        </div>

        {/* Tab bar skeleton */}
        <div className="h-10 animate-pulse rounded-lg w-full max-w-xl" style={{ backgroundColor: 'var(--bg-secondary)' }} />

        {/* Content skeleton: table rows */}
        <div className="rounded-xl border p-6" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <div className="space-y-3">
            {[100, 85, 92, 78, 88, 70].map((w, i) => (
              <div key={i} className="flex items-center gap-4">
                <div className="h-4 animate-pulse rounded" style={{ backgroundColor: 'var(--bg-secondary)', width: `${w * 0.3}%` }} />
                <div className="h-4 animate-pulse rounded flex-1" style={{ backgroundColor: 'var(--bg-secondary)', maxWidth: `${w}%` }} />
                <div className="h-4 w-16 animate-pulse rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // --- ERROR STATE ---
  if (error) {
    return (
      <div className="p-6 space-y-4">
        <button
          onClick={() => router.push('/threats')}
          className="text-sm hover:underline"
          style={{ color: 'var(--accent-primary)' }}
        >
          &larr; Back to Threats
        </button>
        <div
          className="rounded-xl p-6 border flex items-center gap-3"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--accent-danger)' }}
        >
          <AlertTriangle className="w-5 h-5 flex-shrink-0" style={{ color: 'var(--accent-danger)' }} />
          <div>
            <p className="text-sm font-medium" style={{ color: 'var(--accent-danger)' }}>
              Error loading threat
            </p>
            <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
              {error}
            </p>
          </div>
          <button
            onClick={fetchData}
            className="ml-auto px-3 py-1.5 rounded-lg border text-sm hover:opacity-80 transition-opacity"
            style={{
              borderColor: 'var(--border-primary)',
              color: 'var(--text-secondary)',
              backgroundColor: 'var(--bg-secondary)',
            }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!data || !data.threat) {
    return (
      <div className="p-6">
        <EmptyState
          icon={<ShieldAlert className="w-12 h-12" />}
          title="Threat not found"
          description="The requested threat could not be found. It may have been resolved or removed."
          action={{ label: 'Back to Threats', onClick: () => router.push('/threats') }}
        />
      </div>
    );
  }

  const { threat, exposure, mitre, affectedResources, supportingFindings, attackPath, blastRadius, remediation, timeline, evidence, riskBreakdown } = data;

  return (
    <div className="space-y-6 p-6">
      {/* Toast notification */}
      {toast && <Toast message={toast.message} type={toast.type} onDismiss={() => setToast(null)} />}

      {/* ── BREADCRUMB ── */}
      <nav className="flex items-center gap-2" aria-label="Breadcrumb">
        <button
          onClick={handleBackNavigation}
          className="text-sm hover:underline transition-opacity"
          style={{ color: 'var(--accent-primary)' }}
        >
          Threats
        </button>
        <ChevronRight className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
        <span className="text-sm truncate max-w-md" style={{ color: 'var(--text-secondary)' }}>
          {threat.title || threatId}
        </span>
      </nav>

      {/* ── THREAT HEADER ── */}
      <div
        className="rounded-xl border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div className="p-6">
          {/* Badges row — severity + status only (MITRE is shown in overview section) */}
          <div className="flex items-center gap-3 mb-3 flex-wrap">
            <SeverityBadge severity={threat.severity} />
            <span
              className="text-xs font-medium px-2 py-0.5 rounded capitalize"
              style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}
            >
              {threat.status || 'open'}
            </span>
            {threat.threatCategory && (
              <span
                className="text-xs px-2 py-0.5 rounded"
                style={{ backgroundColor: 'rgba(139,92,246,0.10)', color: '#a78bfa' }}
              >
                {threat.threatCategory.replace(/_/g, ' ')}
              </span>
            )}
          </div>

          {/* Title + description */}
          <h1 className="text-xl font-bold mb-1" style={{ color: 'var(--text-primary)' }}>
            {threat.title}
          </h1>
          <p className="text-sm leading-relaxed mb-4" style={{ color: 'var(--text-secondary)' }}>
            {threat.description}
          </p>

          {/* Compact inline metadata — single row instead of big cards */}
          <div
            className="flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-2.5 rounded-lg mb-4"
            style={{ backgroundColor: 'var(--bg-secondary)' }}
          >
            {/* Risk Score */}
            <div className="flex items-center gap-2">
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Risk</span>
              <span className="text-sm font-bold tabular-nums" style={{ color: riskScoreColor(threat.riskScore) }}>
                {threat.riskScore ?? '--'}
              </span>
              <div className="w-12 h-1.5 rounded-full" style={{ backgroundColor: 'var(--bg-primary)' }}>
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${Math.min(threat.riskScore || 0, 100)}%`,
                    backgroundColor: riskScoreColor(threat.riskScore),
                  }}
                />
              </div>
            </div>
            <span style={{ color: 'var(--border-primary)' }}>|</span>
            {/* Provider */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Provider</span>
              <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
                {(threat.provider || '--').toUpperCase()}
              </span>
            </div>
            <span style={{ color: 'var(--border-primary)' }}>|</span>
            {/* Account */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Account</span>
              <span className="text-xs font-mono font-medium truncate max-w-[140px]" style={{ color: 'var(--text-primary)' }} title={threat.account}>
                {threat.account || '--'}
              </span>
            </div>
            <span style={{ color: 'var(--border-primary)' }}>|</span>
            {/* Region */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Region</span>
              <span className="text-xs font-medium" style={{ color: 'var(--text-primary)' }}>
                {threat.region || '--'}
              </span>
            </div>
            <span style={{ color: 'var(--border-primary)' }}>|</span>
            {/* Resource */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>Resource</span>
              <span className="text-xs font-mono font-medium truncate max-w-[200px]" style={{ color: 'var(--text-primary)' }} title={threat.resourceUid}>
                {threat.resourceUid ? threat.resourceUid.split('/').pop() : '--'}
              </span>
            </div>
            {threat.lastSeen && (
              <>
                <span style={{ color: 'var(--border-primary)' }}>|</span>
                <div className="flex items-center gap-1.5">
                  <Clock className="w-3 h-3" style={{ color: 'var(--text-muted)' }} />
                  <span className="text-xs" style={{ color: 'var(--text-muted)' }}>{formatDate(threat.lastSeen)}</span>
                </div>
              </>
            )}
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-2 flex-wrap">
            <ActionDropdown
              label="Assign"
              icon={<UserPlus className="w-3.5 h-3.5" />}
              options={ASSIGNEE_OPTIONS}
              onSelect={handleAssigneeChange}
            />
            <ActionDropdown
              label="Status"
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              options={STATUS_OPTIONS}
              onSelect={handleStatusChange}
            />
            <button
              onClick={handleSuppress}
              disabled={actionLoading}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-medium hover:opacity-80 transition-opacity disabled:opacity-50"
              style={{
                backgroundColor: 'var(--bg-secondary)',
                borderColor: 'var(--border-primary)',
                color: 'var(--text-secondary)',
              }}
            >
              <EyeOff className="w-3.5 h-3.5" />
              Suppress
            </button>
            <button
              onClick={handleExport}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-medium hover:opacity-80 transition-opacity"
              style={{
                backgroundColor: 'var(--bg-secondary)',
                borderColor: 'var(--border-primary)',
                color: 'var(--text-secondary)',
              }}
            >
              <Download className="w-3.5 h-3.5" />
              Export
            </button>
          </div>
        </div>
      </div>

      {/* ── DETAIL CONTENT (no tabs — direct layout) ── */}
      <SafeSection fallbackMessage="Failed to load detail data">
        <OverviewTab
          supportingFindings={supportingFindings}
          router={router}
        />
      </SafeSection>
    </div>
  );
}

// ===========================================================================
// TAB: OVERVIEW
// ===========================================================================
function OverviewTab({ supportingFindings, router }) {
  // Affected resources table columns — no redundant Account/Region (shown in header)
  // Misconfig rule columns — shows rule_id + resource so user can drill into inventory
  const findingColumns = useMemo(
    () => [
      {
        id: 'provider',
        header: 'Provider',
        size: 80,
        cell: ({ row }) => {
          const p = row.original.provider || '';
          return p ? (
            <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
              {p.toUpperCase()}
            </span>
          ) : <span className="text-xs" style={{ color: 'var(--text-muted)' }}>--</span>;
        },
      },
      {
        id: 'account',
        header: 'Account',
        size: 130,
        cell: ({ row }) => {
          const a = row.original.account_id || row.original.hierarchy_id || '';
          return (
            <span className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }} title={a}>
              {a || '--'}
            </span>
          );
        },
      },
      {
        accessorKey: 'region',
        header: 'Region',
        size: 110,
        cell: ({ getValue }) => (
          <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            {getValue() || '--'}
          </span>
        ),
      },
      {
        accessorKey: 'ruleId',
        header: 'Rule ID',
        cell: ({ getValue, row }) => {
          const v = getValue() || row.original.rule_id || '';
          const service = row.original.service || '';
          return (
            <button
              onClick={(e) => {
                e.stopPropagation();
                router.push(`/misconfig?rule_id=${encodeURIComponent(v)}`);
              }}
              className="text-left hover:underline"
              style={{ color: 'var(--accent-primary)' }}
            >
              <span className="text-xs font-mono font-medium">
                {v || '--'}
              </span>
              {service && (
                <span className="text-[10px] ml-2 px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}>
                  {service}
                </span>
              )}
            </button>
          );
        },
      },
      {
        accessorKey: 'status',
        header: 'Result',
        size: 80,
        cell: ({ getValue }) => {
          const s = getValue();
          const isFail = s === 'FAIL';
          return (
            <span
              className="inline-flex items-center gap-1 text-xs font-medium"
              style={{ color: isFail ? 'var(--accent-danger)' : 'var(--accent-success)' }}
            >
              {isFail ? <XCircle className="w-3.5 h-3.5" /> : <CheckCircle className="w-3.5 h-3.5" />}
              {s}
            </span>
          );
        },
      },
      {
        accessorKey: 'severity',
        header: 'Severity',
        size: 100,
        cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
      },
      {
        id: 'affected_resource',
        header: 'Impacted Resource',
        cell: ({ row }) => {
          const uid = row.original.resource_uid || row.original.resourceUid || '';
          const resourceId = row.original.resource_id || '';
          if (!uid) return <span className="text-xs" style={{ color: 'var(--text-muted)' }}>--</span>;
          const name = resourceId || uid.split('/').pop() || uid.split(':').pop() || uid;
          return (
            <button
              onClick={(e) => {
                e.stopPropagation();
                router.push(`/inventory/${encodeURIComponent(uid)}`);
              }}
              className="text-left hover:underline group"
              title={uid}
            >
              <p className="text-xs font-medium" style={{ color: 'var(--accent-primary)' }}>
                {name}
              </p>
              <p
                className="text-[10px] font-mono truncate max-w-[340px] mt-0.5 px-1.5 py-0.5 rounded inline-block"
                style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}
              >
                {uid}
              </p>
            </button>
          );
        },
      },
    ],
    [router]
  );

  return (
    <div className="space-y-6">
      {/* ── Misconfig Rules (rule_ids mapped to this threat detection) ── */}
      <CollapsibleSection
        title="Misconfig Rules"
        icon={<Search className="w-5 h-5" />}
        badge={supportingFindings?.length || 0}
        defaultOpen={true}
      >
        {supportingFindings && supportingFindings.length > 0 ? (
          <>
            <p className="text-xs mb-3" style={{ color: 'var(--text-muted)' }}>
              Misconfiguration rules (rule_id) from the check engine that were correlated to produce this threat detection.
            </p>
            <DataTable
              data={supportingFindings}
              columns={findingColumns}
              pageSize={10}
              emptyMessage="No misconfig rules"
            />
            <div className="mt-3">
              <button
                onClick={() => router.push('/misconfig')}
                className="text-xs font-medium flex items-center gap-1 hover:underline"
                style={{ color: 'var(--accent-primary)' }}
              >
                View All Misconfigs <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </>
        ) : (
          <EmptyState
            icon={<Search className="w-10 h-10" />}
            title="No misconfig rules"
            description="No check engine rules are linked to this threat detection."
          />
        )}
      </CollapsibleSection>


    </div>
  );
}

// ---------------------------------------------------------------------------
// Exposure card sub-component
// ---------------------------------------------------------------------------
function ExposureCard({ icon, label, value, reason }) {
  const isYes = Boolean(value);

  return (
    <div
      className="rounded-lg px-3 py-2.5 border"
      style={{
        backgroundColor: 'var(--bg-secondary)',
        borderColor: isYes ? 'rgba(239,68,68,0.3)' : 'var(--border-primary)',
      }}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          <span style={{ color: isYes ? 'var(--accent-danger)' : 'var(--accent-success)' }}>
            {icon}
          </span>
          <span className="text-xs font-medium" style={{ color: 'var(--text-muted)' }}>
            {label}
          </span>
        </div>
        <span
          className="text-xs font-bold"
          style={{ color: isYes ? 'var(--accent-danger)' : 'var(--accent-success)' }}
        >
          {isYes ? 'YES' : 'NO'}
        </span>
      </div>
      {reason && (
        <p className="text-[10px] mt-1 leading-relaxed" style={{ color: 'var(--text-muted)' }}>
          {reason}
        </p>
      )}
    </div>
  );
}

// ===========================================================================
// TAB: ATTACK PATH
// ===========================================================================
function AttackPathTab({ attackPath }) {
  if (!attackPath || !attackPath.exists || !attackPath.steps || attackPath.steps.length === 0) {
    return (
      <EmptyState
        icon={<Activity className="w-12 h-12" />}
        title="No attack paths detected"
        description="No attack path chains have been identified for this threat."
      />
    );
  }

  const { steps, title: pathTitle, severity, hops } = attackPath;
  const NODE_WIDTH = 160;
  const NODE_HEIGHT = 120;
  const H_GAP = 80;
  const V_GAP = 50;
  const PADDING = 40;

  // Layout: simple horizontal with wrapping after 4 per row
  const MAX_PER_ROW = 4;
  const positions = steps.map((_, i) => {
    const row = Math.floor(i / MAX_PER_ROW);
    const col = i % MAX_PER_ROW;
    return {
      x: PADDING + col * (NODE_WIDTH + H_GAP),
      y: PADDING + row * (NODE_HEIGHT + V_GAP),
    };
  });

  const rows = Math.ceil(steps.length / MAX_PER_ROW);
  const svgWidth = PADDING * 2 + Math.min(steps.length, MAX_PER_ROW) * (NODE_WIDTH + H_GAP) - H_GAP;
  const svgHeight = PADDING * 2 + rows * (NODE_HEIGHT + V_GAP) - V_GAP;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div
        className="rounded-xl border p-5"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div className="flex items-center justify-between flex-wrap gap-3 mb-2">
          <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
            Attack Path Visualization
          </h3>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={severity || 'high'} />
            <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {hops || steps.length - 1} hops
            </span>
          </div>
        </div>
        {pathTitle && (
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
            {pathTitle}
          </p>
        )}
      </div>

      {/* SVG Attack Chain */}
      <div
        className="rounded-xl border overflow-x-auto"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <svg width={svgWidth} height={svgHeight} viewBox={`0 0 ${svgWidth} ${svgHeight}`} className="min-w-full">
          <defs>
            <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="#3b82f6" />
            </marker>
          </defs>

          {/* Edges */}
          {steps.slice(0, -1).map((_, i) => {
            const from = positions[i];
            const to = positions[i + 1];
            const fromX = from.x + NODE_WIDTH;
            const fromY = from.y + NODE_HEIGHT / 2;
            const toX = to.x;
            const toY = to.y + NODE_HEIGHT / 2;

            // Same row: straight line; different row: curved
            if (Math.abs(from.y - to.y) < 5) {
              return (
                <g key={`edge-${i}`}>
                  <line
                    x1={fromX}
                    y1={fromY}
                    x2={toX - 2}
                    y2={toY}
                    stroke="#3b82f6"
                    strokeWidth="2"
                    markerEnd="url(#arrowhead)"
                    opacity="0.6"
                  />
                  {steps[i + 1].technique && (
                    <text
                      x={(fromX + toX) / 2}
                      y={fromY - 8}
                      textAnchor="middle"
                      fill="#3b82f6"
                      fontSize="10"
                      fontFamily="monospace"
                    >
                      {steps[i + 1].technique}
                    </text>
                  )}
                </g>
              );
            }

            // Different row: path down then across
            const midY = (fromY + toY) / 2;
            return (
              <g key={`edge-${i}`}>
                <path
                  d={`M${fromX},${fromY} C${fromX + 30},${fromY} ${fromX + 30},${midY} ${(fromX + toX) / 2},${midY} S${toX - 30},${toY} ${toX - 2},${toY}`}
                  fill="none"
                  stroke="#3b82f6"
                  strokeWidth="2"
                  markerEnd="url(#arrowhead)"
                  opacity="0.6"
                />
              </g>
            );
          })}

          {/* Nodes */}
          {steps.map((step, i) => {
            const pos = positions[i];
            const isTarget = step.isTarget;
            const borderColor = isTarget ? '#ef4444' : '#3b82f6';

            return (
              <g key={`node-${i}`}>
                <rect
                  x={pos.x}
                  y={pos.y}
                  width={NODE_WIDTH}
                  height={NODE_HEIGHT}
                  rx="12"
                  fill="#141414"
                  stroke={borderColor}
                  strokeWidth={isTarget ? 2.5 : 1.5}
                  opacity="0.95"
                />
                {/* Resource type icon placeholder */}
                <text
                  x={pos.x + NODE_WIDTH / 2}
                  y={pos.y + 28}
                  textAnchor="middle"
                  fill="#f5f5f5"
                  fontSize="12"
                  fontWeight="600"
                >
                  {step.resourceName || step.resourceType}
                </text>
                <text
                  x={pos.x + NODE_WIDTH / 2}
                  y={pos.y + 48}
                  textAnchor="middle"
                  fill="#737373"
                  fontSize="10"
                >
                  {step.resourceType}
                </text>
                {step.technique && (
                  <g>
                    <rect
                      x={pos.x + NODE_WIDTH / 2 - 24}
                      y={pos.y + 58}
                      width="48"
                      height="18"
                      rx="4"
                      fill="rgba(59,130,246,0.2)"
                    />
                    <text
                      x={pos.x + NODE_WIDTH / 2}
                      y={pos.y + 71}
                      textAnchor="middle"
                      fill="#3b82f6"
                      fontSize="10"
                      fontFamily="monospace"
                    >
                      {step.technique}
                    </text>
                  </g>
                )}
                {step.riskScore > 0 && (
                  <text
                    x={pos.x + NODE_WIDTH / 2}
                    y={pos.y + 100}
                    textAnchor="middle"
                    fill={riskScoreColor(step.riskScore)}
                    fontSize="11"
                    fontWeight="600"
                  >
                    Risk: {step.riskScore}
                  </text>
                )}
                {isTarget && (
                  <text
                    x={pos.x + NODE_WIDTH / 2}
                    y={pos.y + NODE_HEIGHT + 16}
                    textAnchor="middle"
                    fill="#ef4444"
                    fontSize="10"
                    fontWeight="700"
                  >
                    TARGET
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

// ===========================================================================
// TAB: BLAST RADIUS
// ===========================================================================
function BlastRadiusTab({ blastRadius, resourceUid, router }) {
  if (!blastRadius || blastRadius.reachableCount === 0) {
    return (
      <EmptyState
        icon={<Activity className="w-12 h-12" />}
        title="No blast radius data"
        description="Blast radius analysis has not been performed for this resource."
      />
    );
  }

  const { reachableCount, resourcesWithThreats, depthDistribution, maxDepth } = blastRadius;

  // Chart data from depthDistribution
  const chartData = Object.entries(depthDistribution || {}).map(([depth, count]) => ({
    depth: `Depth ${depth}`,
    count,
  }));

  const DEPTH_COLORS = ['#3b82f6', '#8b5cf6', '#f97316', '#ef4444'];

  // Simple force-directed mini-graph (deterministic layout)
  const graphNodes = [];
  const graphEdges = [];
  let nodeId = 0;
  const centerX = 200;
  const centerY = 150;

  // Center node
  graphNodes.push({ id: nodeId++, x: centerX, y: centerY, depth: 0, hasThreats: true });

  // Generate nodes per depth ring
  Object.entries(depthDistribution || {}).forEach(([depth, count]) => {
    const d = parseInt(depth);
    if (d === 0) return;
    const radius = d * 70;
    for (let j = 0; j < count; j++) {
      const angle = (j / count) * Math.PI * 2 - Math.PI / 2;
      graphNodes.push({
        id: nodeId,
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        depth: d,
        hasThreats: j < Math.ceil(count * (resourcesWithThreats / reachableCount)),
      });
      // Connect to a random node in previous depth
      const prevDepthNodes = graphNodes.filter((n) => n.depth === d - 1);
      if (prevDepthNodes.length > 0) {
        graphEdges.push({
          from: prevDepthNodes[j % prevDepthNodes.length].id,
          to: nodeId,
        });
      }
      nodeId++;
    }
  });

  const graphWidth = 400;
  const graphHeight = 300;

  return (
    <div className="space-y-6">
      {/* Stats cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div
          className="rounded-xl p-5 border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          <p className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
            Reachable Resources
          </p>
          <p className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
            {reachableCount}
          </p>
        </div>
        <div
          className="rounded-xl p-5 border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          <p className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
            Resources with Threats
          </p>
          <p className="text-2xl font-bold" style={{ color: 'var(--accent-danger)' }}>
            {resourcesWithThreats}
          </p>
        </div>
        <div
          className="rounded-xl p-5 border"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          <p className="text-xs mb-1" style={{ color: 'var(--text-muted)' }}>
            Max Depth
          </p>
          <p className="text-2xl font-bold" style={{ color: 'var(--accent-primary)' }}>
            {maxDepth}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Mini graph */}
        <div
          className="rounded-xl border p-5"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
            Blast Radius Graph
          </h3>
          <svg width="100%" viewBox={`0 0 ${graphWidth} ${graphHeight}`}>
            {/* Edges */}
            {graphEdges.map((edge, i) => {
              const from = graphNodes.find((n) => n.id === edge.from);
              const to = graphNodes.find((n) => n.id === edge.to);
              if (!from || !to) return null;
              return (
                <line
                  key={`ge-${i}`}
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke="rgba(255,255,255,0.1)"
                  strokeWidth="1"
                />
              );
            })}
            {/* Nodes */}
            {graphNodes.map((node) => (
              <g key={`gn-${node.id}`}>
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={node.depth === 0 ? 12 : 8}
                  fill={
                    node.depth === 0
                      ? '#3b82f6'
                      : node.hasThreats
                        ? '#ef4444'
                        : '#737373'
                  }
                  opacity={0.85}
                />
                {node.depth === 0 && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={16}
                    fill="none"
                    stroke="#3b82f6"
                    strokeWidth="1.5"
                    opacity="0.4"
                  />
                )}
              </g>
            ))}
            {/* Legend */}
            <g transform={`translate(10, ${graphHeight - 40})`}>
              <circle cx={6} cy={6} r={5} fill="#3b82f6" />
              <text x={16} y={10} fill="#a3a3a3" fontSize="9">Source</text>
              <circle cx={66} cy={6} r={5} fill="#ef4444" />
              <text x={76} y={10} fill="#a3a3a3" fontSize="9">Threat</text>
              <circle cx={126} cy={6} r={5} fill="#737373" />
              <text x={136} y={10} fill="#a3a3a3" fontSize="9">Normal</text>
            </g>
          </svg>
        </div>

        {/* Depth distribution chart */}
        <div
          className="rounded-xl border p-5"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          <h3 className="text-sm font-semibold mb-4" style={{ color: 'var(--text-primary)' }}>
            Depth Distribution
          </h3>
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={chartData}>
                <XAxis
                  dataKey="depth"
                  tick={{ fill: '#a3a3a3', fontSize: 12 }}
                  axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#a3a3a3', fontSize: 12 }}
                  axisLine={{ stroke: 'rgba(255,255,255,0.1)' }}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1a1a1a',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    color: '#f5f5f5',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {chartData.map((_, idx) => (
                    <Cell key={idx} fill={DEPTH_COLORS[idx % DEPTH_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
              No depth data available.
            </p>
          )}

          {/* Depth breakdown list */}
          <div className="mt-4 space-y-2">
            {Object.entries(depthDistribution || {}).map(([depth, count]) => (
              <div key={depth} className="flex items-center justify-between">
                <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                  Depth {depth}
                </span>
                <span className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
                  {count} resource{count !== 1 ? 's' : ''}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Link to full blast radius */}
      {resourceUid && (
        <div className="flex justify-end">
          <button
            onClick={() =>
              router.push(`/threats/blast-radius?resource_uid=${encodeURIComponent(resourceUid)}`)
            }
            className="text-sm font-medium flex items-center gap-1.5 hover:underline"
            style={{ color: 'var(--accent-primary)' }}
          >
            View Full Blast Radius <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}

// ===========================================================================
// TAB: EVIDENCE
// ===========================================================================
function EvidenceTab({ threat, evidence }) {
  // Use BFF-provided evidence array first, then extract from threat object
  const evidenceData = useMemo(() => {
    // If we have evidence from the BFF (from detection's JSONB evidence field)
    if (evidence && Array.isArray(evidence) && evidence.length > 0) {
      // Flatten evidence array into a displayable object
      const merged = {};
      evidence.forEach((entry, idx) => {
        if (typeof entry === 'object' && entry !== null) {
          Object.entries(entry).forEach(([k, v]) => {
            if (v !== null && v !== undefined && v !== '') {
              merged[k] = v;
            }
          });
        } else {
          merged[`evidence_${idx}`] = entry;
        }
      });
      return merged;
    }
    // Fallback: extract evidence-like fields from threat object
    const fields = {};
    const skipKeys = new Set([
      'id', 'title', 'description', 'severity', 'riskScore', 'status', 'assignee',
      'provider', 'account', 'region', 'detected', 'lastSeen', 'environment',
      'threatCategory', 'ruleId', 'resourceType', 'resourceUid',
    ]);
    Object.entries(threat).forEach(([key, value]) => {
      if (!skipKeys.has(key) && value !== null && value !== undefined && value !== '') {
        fields[key] = value;
      }
    });
    return fields;
  }, [threat, evidence]);

  const keys = Object.keys(evidenceData);

  if (keys.length === 0) {
    return (
      <EmptyState
        icon={<Search className="w-12 h-12" />}
        title="No evidence data"
        description="No additional evidence data is available for this threat."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div
        className="rounded-xl border p-5"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
            Evidence Data
          </h3>
          <CopyButton text={JSON.stringify(evidenceData, null, 2)} />
        </div>
        <div className="space-y-3">
          {keys.map((key) => (
            <EvidenceSection key={key} label={key} value={evidenceData[key]} />
          ))}
        </div>
      </div>
    </div>
  );
}

function EvidenceSection({ label, value }) {
  const [isOpen, setIsOpen] = useState(false);
  const isComplex = typeof value === 'object';

  return (
    <div
      className="rounded-lg border"
      style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-primary)' }}
    >
      <button
        onClick={() => isComplex && setIsOpen((p) => !p)}
        className={`w-full flex items-center justify-between px-4 py-3 ${isComplex ? 'cursor-pointer' : ''}`}
      >
        <span className="text-xs font-mono font-medium" style={{ color: 'var(--accent-primary)' }}>
          {label}
        </span>
        <div className="flex items-center gap-2">
          {!isComplex && (
            <span className="text-sm text-right truncate max-w-sm" style={{ color: 'var(--text-secondary)' }}>
              {String(value)}
            </span>
          )}
          <CopyButton text={isComplex ? JSON.stringify(value, null, 2) : String(value)} />
          {isComplex && (
            isOpen ? (
              <ChevronUp className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
            ) : (
              <ChevronDown className="w-4 h-4" style={{ color: 'var(--text-muted)' }} />
            )
          )}
        </div>
      </button>
      {isComplex && isOpen && (
        <div className="px-4 pb-3">
          <pre
            className="text-xs overflow-x-auto p-3 rounded-lg"
            style={{
              backgroundColor: 'var(--bg-primary)',
              color: 'var(--text-secondary)',
              fontFamily: 'ui-monospace, monospace',
            }}
          >
            {JSON.stringify(value, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

// ===========================================================================
// TAB: REMEDIATION
// ===========================================================================
function RemediationTab({ remediation }) {
  if (!remediation || !remediation.steps || remediation.steps.length === 0) {
    return (
      <EmptyState
        icon={<CheckCircle className="w-12 h-12" />}
        title="No remediation steps"
        description="No remediation guidance is available for this threat yet."
      />
    );
  }

  const { steps, sla, totalSteps, completedSteps } = remediation;

  const effortColors = {
    low: { bg: 'rgba(34,197,94,0.12)', text: '#22c55e' },
    medium: { bg: 'rgba(234,179,8,0.12)', text: '#eab308' },
    high: { bg: 'rgba(239,68,68,0.12)', text: '#ef4444' },
  };

  return (
    <div className="space-y-6">
      {/* SLA banner */}
      {sla && (
        <div
          className="rounded-xl border p-5 flex items-center justify-between flex-wrap gap-4"
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
        >
          <div>
            <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-primary)' }}>
              SLA Compliance
            </p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              {sla.daysElapsed} of {sla.targetDays} days elapsed &middot; {sla.daysRemaining} days remaining
            </p>
          </div>
          <div className="flex items-center gap-3">
            <SlaStatusBadge
              status={sla.status}
              daysInfo={`${sla.daysRemaining}d left`}
            />
            {totalSteps !== undefined && (
              <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                {completedSteps || 0}/{totalSteps} steps completed
              </span>
            )}
          </div>
        </div>
      )}

      {/* Steps list */}
      <div
        className="rounded-xl border"
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
      >
        <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border-primary)' }}>
          <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
            Recommended Actions (Priority Order)
          </h3>
        </div>
        <div className="divide-y" style={{ borderColor: 'var(--border-primary)' }}>
          {steps.map((step, idx) => {
            const effortStyle = effortColors[step.effort] || effortColors.medium;

            return (
              <div
                key={step.order || idx}
                className="px-6 py-5"
                style={{ borderColor: 'var(--border-primary)' }}
              >
                <div className="flex items-start gap-4">
                  {/* Step number circle */}
                  <div
                    className="w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0"
                    style={{ backgroundColor: 'rgba(59,130,246,0.15)', color: '#3b82f6' }}
                  >
                    {step.order || idx + 1}
                  </div>

                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium mb-2" style={{ color: 'var(--text-primary)' }}>
                      {step.action}
                    </p>

                    {/* Impact */}
                    {step.impact && (
                      <p className="text-xs mb-3" style={{ color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Impact:</span> {step.impact}
                      </p>
                    )}

                    {/* Badges row */}
                    <div className="flex items-center gap-2 flex-wrap">
                      {step.effort && (
                        <span
                          className="text-xs font-medium px-2 py-0.5 rounded capitalize"
                          style={{ backgroundColor: effortStyle.bg, color: effortStyle.text }}
                        >
                          {step.effort} Effort
                        </span>
                      )}
                      {step.risk && (
                        <span
                          className="text-xs px-2 py-0.5 rounded capitalize"
                          style={{
                            backgroundColor: 'var(--bg-secondary)',
                            color: 'var(--text-muted)',
                          }}
                        >
                          Risk: {step.risk}
                        </span>
                      )}
                      {step.autoRemediable && (
                        <span
                          className="text-xs font-medium px-2 py-0.5 rounded flex items-center gap-1"
                          style={{ backgroundColor: 'rgba(59,130,246,0.12)', color: '#3b82f6' }}
                        >
                          <Zap className="w-3 h-3" />
                          Auto-Remediable
                        </span>
                      )}
                    </div>

                    {/* CLI command if present */}
                    {step.command && (
                      <div className="mt-3 flex items-center gap-2">
                        <code
                          className="text-xs px-3 py-2 rounded-lg flex-1 overflow-x-auto"
                          style={{
                            backgroundColor: 'var(--bg-primary)',
                            color: 'var(--text-secondary)',
                            fontFamily: 'ui-monospace, monospace',
                          }}
                        >
                          {step.command}
                        </code>
                        <CopyButton text={step.command} />
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ===========================================================================
// TAB: TIMELINE
// ===========================================================================
function TimelineTab({ timeline }) {
  if (!timeline || timeline.length === 0) {
    return (
      <EmptyState
        icon={<Clock className="w-12 h-12" />}
        title="No timeline events"
        description="No activity has been recorded for this threat yet."
      />
    );
  }

  const typeIcons = {
    detection: <ShieldAlert className="w-4 h-4" />,
    enrichment: <Zap className="w-4 h-4" />,
    analysis: <Activity className="w-4 h-4" />,
    status_change: <RefreshCw className="w-4 h-4" />,
    assignment: <UserPlus className="w-4 h-4" />,
    resolution: <CheckCircle className="w-4 h-4" />,
  };

  const typeColors = {
    detection: 'var(--accent-danger)',
    enrichment: 'var(--accent-primary)',
    analysis: 'var(--accent-warning)',
    status_change: '#8b5cf6',
    assignment: '#06b6d4',
    resolution: 'var(--accent-success)',
  };

  return (
    <div
      className="rounded-xl border p-6"
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}
    >
      <h3 className="text-base font-semibold mb-6" style={{ color: 'var(--text-primary)' }}>
        Activity Timeline
      </h3>
      <div className="relative">
        {/* Vertical line */}
        <div
          className="absolute left-[19px] top-0 bottom-0 w-px"
          style={{ backgroundColor: 'var(--border-primary)' }}
        />

        <div className="space-y-6">
          {timeline.map((event, idx) => {
            const icon = typeIcons[event.type] || <Circle className="w-4 h-4" />;
            const color = typeColors[event.type] || 'var(--text-muted)';
            const isLast = idx === timeline.length - 1;

            return (
              <div key={idx} className="flex items-start gap-4 relative">
                {/* Dot */}
                <div
                  className="w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0 z-10"
                  style={{ backgroundColor: 'var(--bg-card)', border: `2px solid ${color}`, color }}
                >
                  {icon}
                </div>

                {/* Content */}
                <div className="flex-1 pb-2">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                      {event.event}
                    </p>
                    {event.actor && (
                      <span
                        className="text-xs px-1.5 py-0.5 rounded"
                        style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-muted)' }}
                      >
                        {event.actor}
                      </span>
                    )}
                  </div>
                  {event.detail && (
                    <p className="text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>
                      {event.detail}
                    </p>
                  )}
                  <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    {formatDate(event.timestamp)}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
