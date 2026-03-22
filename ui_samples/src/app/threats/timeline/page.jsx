'use client';

import { useEffect, useState, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import {
  AlertTriangle,
  Shield,
  ShieldCheck,
  ShieldX,
  UserCheck,
  Eye,
  XCircle,
  Clock,
  Filter,
  ChevronDown,
  Search,
} from 'lucide-react';
import { fetchView } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { SEVERITY_COLORS } from '@/lib/constants';
import MetricStrip from '@/components/shared/MetricStrip';
import SeverityBadge from '@/components/shared/SeverityBadge';
import ThreatsSubNav from '@/components/shared/ThreatsSubNav';


// ── Event type config ───────────────────────────────────────────────────────

const EVENT_TYPES = {
  detected: {
    icon: ShieldX,
    color: '#ef4444',
    bg: 'rgba(239,68,68,0.10)',
    label: 'Detected',
  },
  escalated: {
    icon: AlertTriangle,
    color: '#f97316',
    bg: 'rgba(249,115,22,0.10)',
    label: 'Escalated',
  },
  assigned: {
    icon: UserCheck,
    color: '#3b82f6',
    bg: 'rgba(59,130,246,0.10)',
    label: 'Assigned',
  },
  investigating: {
    icon: Eye,
    color: '#8b5cf6',
    bg: 'rgba(139,92,246,0.10)',
    label: 'Investigating',
  },
  resolved: {
    icon: ShieldCheck,
    color: '#22c55e',
    bg: 'rgba(34,197,94,0.10)',
    label: 'Resolved',
  },
  suppressed: {
    icon: XCircle,
    color: '#6b7280',
    bg: 'rgba(107,114,128,0.10)',
    label: 'Suppressed',
  },
  reopened: {
    icon: ShieldX,
    color: '#ef4444',
    bg: 'rgba(239,68,68,0.10)',
    label: 'Reopened',
  },
};

function relativeTime(dateStr) {
  if (!dateStr) return '—';
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffMs = now - then;
  const mins = Math.floor(diffMs / 60000);
  const hours = Math.floor(mins / 60);
  const days = Math.floor(hours / 24);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 7) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

function formatDate(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
}


// ── Main Page ───────────────────────────────────────────────────────────────

export default function ThreatTimelinePage() {
  const router = useRouter();
  const { provider, account, region } = useGlobalFilter();

  const [loading, setLoading] = useState(true);
  const [events, setEvents] = useState([]);
  const [kpi, setKpi] = useState(null);

  // Filters
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  // Fetch
  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const data = await fetchView('threats/timeline', {
          provider: provider || undefined,
          account: account || undefined,
          region: region || undefined,
        });
        if (data.events) setEvents(data.events);
        if (data.kpi) setKpi(data.kpi);
      } catch (err) {
        console.warn('[timeline] fetch error:', err);
        // Fallback: build timeline from threats BFF data
        try {
          const threatData = await fetchView('threats', {
            provider: provider || undefined,
            account: account || undefined,
            region: region || undefined,
          });
          if (threatData.threats) {
            const fallbackEvents = [];
            threatData.threats.slice(0, 100).forEach((t) => {
              // Detection event (always present)
              fallbackEvents.push({
                id: `evt-det-${t.id}`,
                type: 'detected',
                timestamp: t.detected || t.detected_at || '',
                threatId: t.id,
                threatTitle: t.title,
                severity: t.severity,
                actor: 'system',
                account: t.account,
                details: t.mitreTechnique ? `MITRE: ${t.mitreTechnique}` : null,
              });
              // Status-based events from real data
              const status = (t.status || 'active').toLowerCase();
              if (status === 'resolved') {
                fallbackEvents.push({
                  id: `evt-res-${t.id}`, type: 'resolved',
                  timestamp: t.lastSeen || t.detected || '',
                  threatId: t.id, threatTitle: t.title, severity: t.severity,
                  actor: t.assignee || 'system', account: t.account, details: null,
                });
              } else if (status === 'investigating') {
                fallbackEvents.push({
                  id: `evt-inv-${t.id}`, type: 'investigating',
                  timestamp: t.lastSeen || t.detected || '',
                  threatId: t.id, threatTitle: t.title, severity: t.severity,
                  actor: t.assignee || 'soc-analyst', account: t.account, details: null,
                });
              }
              if (t.assignee) {
                fallbackEvents.push({
                  id: `evt-asg-${t.id}`, type: 'assigned',
                  timestamp: t.lastSeen || t.detected || '',
                  threatId: t.id, threatTitle: t.title, severity: t.severity,
                  actor: t.assignee, account: t.account, details: `Assigned to ${t.assignee}`,
                });
              }
            });
            setEvents(fallbackEvents);
            setKpi({
              totalEvents: fallbackEvents.length,
              detected: fallbackEvents.filter((e) => e.type === 'detected').length,
              resolved: fallbackEvents.filter((e) => e.type === 'resolved').length,
              avgResponseTime: '—',
              openInvestigations: fallbackEvents.filter((e) => e.type === 'investigating').length,
            });
          }
        } catch {
          // no data at all
        }
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, [provider, account, region]);

  // Computed stats
  const stats = useMemo(() => {
    if (kpi) return kpi;
    return {
      totalEvents: events.length,
      detected: events.filter((e) => e.type === 'detected').length,
      resolved: events.filter((e) => e.type === 'resolved').length,
      avgResponseTime: '—',
      openInvestigations: events.filter((e) => e.type === 'investigating').length,
    };
  }, [kpi, events]);

  // Filtered events
  const filteredEvents = useMemo(() => {
    let result = events;
    if (eventTypeFilter) result = result.filter((e) => e.type === eventTypeFilter);
    if (severityFilter) result = result.filter((e) => e.severity === severityFilter);
    if (searchTerm) {
      const s = searchTerm.toLowerCase();
      result = result.filter((e) =>
        (e.threatTitle || '').toLowerCase().includes(s) ||
        (e.actor || '').toLowerCase().includes(s) ||
        (e.details || '').toLowerCase().includes(s)
      );
    }
    return result.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }, [events, eventTypeFilter, severityFilter, searchTerm]);

  // Group by date
  const groupedEvents = useMemo(() => {
    const groups = {};
    filteredEvents.forEach((evt) => {
      const dateKey = formatDate(evt.timestamp);
      if (!groups[dateKey]) groups[dateKey] = [];
      groups[dateKey].push(evt);
    });
    return Object.entries(groups);
  }, [filteredEvents]);

  // Loading
  if (loading) {
    return (
      <div className="space-y-4">
        <div className="space-y-2">
          <div className="h-7 w-48 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          <div className="h-4 w-80 rounded animate-pulse" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        </div>
        <div className="h-20 rounded-xl animate-pulse" style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }} />
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="h-16 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-primary)' }} />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>
          Activity Timeline
        </h1>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
          Chronological audit trail of threat detection, investigation, and resolution
        </p>
      </div>

      <ThreatsSubNav />

      {/* MetricStrip */}
      <MetricStrip groups={[
        {
          label: '🔴 ACTIVITY',
          color: 'var(--accent-danger)',
          cells: [
            { label: 'TOTAL EVENTS', value: stats.totalEvents ?? 0, valueColor: 'var(--text-primary)', context: 'all time' },
            { label: 'DETECTED', value: stats.detected ?? 0, valueColor: 'var(--severity-critical)', context: 'new threats' },
            { label: 'RESOLVED', value: stats.resolved ?? 0, valueColor: 'var(--accent-success)', context: 'closed' },
          ],
        },
        {
          label: '🟡 RESPONSE',
          color: '#eab308',
          cells: [
            { label: 'AVG RESPONSE', value: stats.avgResponseTime ?? '—', noTrend: true, context: 'time to resolve' },
            { label: 'OPEN', value: stats.openInvestigations ?? 0, valueColor: stats.openInvestigations > 0 ? 'var(--severity-high)' : 'var(--accent-success)', context: 'investigating' },
          ],
        },
      ]} />

      {/* Filters row */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5" style={{ color: 'var(--text-muted)' }} />
          <input
            type="text"
            placeholder="Search events..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-500"
            style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
          />
        </div>
        <select
          value={eventTypeFilter}
          onChange={(e) => setEventTypeFilter(e.target.value)}
          className="border rounded-lg px-3 py-1.5 text-xs cursor-pointer"
          style={{ backgroundColor: eventTypeFilter ? 'rgba(59,130,246,0.12)' : 'var(--bg-tertiary)', borderColor: eventTypeFilter ? 'rgba(59,130,246,0.5)' : 'var(--border-primary)', color: 'var(--text-primary)' }}
        >
          <option value="">All Events</option>
          {Object.entries(EVENT_TYPES).map(([key, cfg]) => (
            <option key={key} value={key}>{cfg.label}</option>
          ))}
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="border rounded-lg px-3 py-1.5 text-xs cursor-pointer"
          style={{ backgroundColor: severityFilter ? 'rgba(59,130,246,0.12)' : 'var(--bg-tertiary)', borderColor: severityFilter ? 'rgba(59,130,246,0.5)' : 'var(--border-primary)', color: 'var(--text-primary)' }}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <span className="text-xs ml-auto" style={{ color: 'var(--text-muted)' }}>
          {filteredEvents.length} events
        </span>
      </div>

      {/* Timeline */}
      {groupedEvents.length === 0 ? (
        <div className="rounded-xl border p-12 text-center" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <Clock className="w-12 h-12 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
          <p className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>No activity events</p>
          <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
            Timeline will populate as threats are detected and managed
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {groupedEvents.map(([dateLabel, dayEvents]) => (
            <div key={dateLabel}>
              {/* Date header */}
              <div className="flex items-center gap-3 mb-3">
                <span className="text-xs font-bold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                  {dateLabel}
                </span>
                <div className="flex-1 h-px" style={{ backgroundColor: 'var(--border-primary)' }} />
                <span className="text-[10px] font-medium px-2 py-0.5 rounded-full" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
                  {dayEvents.length} events
                </span>
              </div>

              {/* Events */}
              <div className="space-y-1">
                {dayEvents.map((evt) => {
                  const cfg = EVENT_TYPES[evt.type] || EVENT_TYPES.detected;
                  const Icon = cfg.icon;
                  return (
                    <div
                      key={evt.id}
                      className="flex items-start gap-3 px-4 py-3 rounded-lg border cursor-pointer transition-all hover:scale-[1.002]"
                      style={{
                        backgroundColor: 'var(--bg-card)',
                        borderColor: 'var(--border-primary)',
                        borderLeftWidth: 3,
                        borderLeftColor: cfg.color,
                      }}
                      onClick={() => evt.threatId && router.push(`/threats/${evt.threatId}`)}
                    >
                      {/* Icon */}
                      <div className="flex-shrink-0 mt-0.5 p-1.5 rounded-lg" style={{ backgroundColor: cfg.bg }}>
                        <Icon className="w-3.5 h-3.5" style={{ color: cfg.color }} />
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded" style={{ backgroundColor: cfg.bg, color: cfg.color }}>
                            {cfg.label}
                          </span>
                          {evt.severity && <SeverityBadge severity={evt.severity} />}
                          <span className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                            {evt.threatTitle || 'Unknown threat'}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 mt-1">
                          {evt.actor && (
                            <span className="text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                              by <strong style={{ color: 'var(--text-secondary)' }}>{evt.actor}</strong>
                            </span>
                          )}
                          {evt.account && (
                            <span className="text-[10px] font-mono" style={{ color: 'var(--text-muted)' }}>
                              {evt.account}
                            </span>
                          )}
                          {evt.details && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-tertiary)' }}>
                              {evt.details}
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Timestamp */}
                      <span className="text-[10px] flex-shrink-0 whitespace-nowrap" style={{ color: 'var(--text-muted)' }}>
                        {relativeTime(evt.timestamp)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
