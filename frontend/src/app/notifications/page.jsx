'use client';

import { useState, useEffect } from 'react';
import { getFromEngine } from '@/lib/api';
import {
  Bell,
  AlertTriangle,
  CheckCircle,
  Trash2,
  Eye,
  Settings,
} from 'lucide-react';


const getSeverityIcon = (severity) => {
  const icons = {
    critical: <AlertTriangle className="w-5 h-5 text-red-500" />,
    high: <AlertTriangle className="w-5 h-5 text-orange-500" />,
    medium: <AlertTriangle className="w-5 h-5 text-yellow-500" />,
    info: <CheckCircle className="w-5 h-5 text-green-500" />,
  };
  return icons[severity] || icons.info;
};

const getSeverityColor = (severity) => {
  const colors = {
    critical: { bg: '#ef4444', light: '#fca5a5' },
    high: { bg: '#f97316', light: '#fed7aa' },
    medium: { bg: '#eab308', light: '#fef08a' },
    info: { bg: '#3b82f6', light: '#bfdbfe' },
  };
  return colors[severity] || colors.info;
};

const formatTimestamp = (timestamp) => {
  const now = new Date();
  const diffMs = now - timestamp;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return timestamp.toLocaleDateString();
};

export default function NotificationsPage() {
  const [notifications, setNotifications] = useState([]);

  useEffect(() => {
    getFromEngine('onboarding', '/api/v1/notifications')
      .then(res => { if (res && Array.isArray(res)) setNotifications(res); })
      .catch(() => {});
  }, []);
  const [filterTab, setFilterTab] = useState('all');
  const [expandedId, setExpandedId] = useState(null);

  const tabs = [
    { id: 'all', label: 'All', count: notifications.length },
    { id: 'critical', label: 'Critical', count: notifications.filter(n => n.severity === 'critical').length },
    { id: 'findings', label: 'Findings', count: notifications.filter(n => n.source === 'Findings').length },
    { id: 'compliance', label: 'Compliance', count: notifications.filter(n => n.source === 'Compliance').length },
    { id: 'threats', label: 'Threats', count: notifications.filter(n => n.source === 'Threats').length },
    { id: 'system', label: 'System', count: notifications.filter(n => n.source === 'System').length },
  ];

  const filtered = notifications.filter((n) => {
    if (filterTab === 'all') return true;
    if (filterTab === 'critical') return n.severity === 'critical';
    return n.source === tabs.find(t => t.id === filterTab)?.label;
  });

  const unreadCount = notifications.filter(n => !n.read).length;

  const handleMarkAsRead = (id) => {
    setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n));
  };

  const handleMarkAllAsRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  const handleDelete = (id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold" style={{ color: 'var(--text-primary)' }}>Notifications</h1>
          <p style={{ color: 'var(--text-tertiary)' }} className="mt-1">Stay informed of security alerts, findings, compliance issues, and threats</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 rounded-lg text-white font-medium transition-colors" style={{ backgroundColor: 'var(--accent-primary)' }}>
          <Settings className="w-4 h-4" /> Preferences
        </button>
      </div>

      {/* Filter Tabs */}
      <div className="flex gap-2 border-b overflow-x-auto" style={{ borderColor: 'var(--border-primary)' }}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setFilterTab(tab.id)}
            className="px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap"
            style={{
              borderColor: filterTab === tab.id ? 'var(--accent-primary)' : 'transparent',
              color: filterTab === tab.id ? 'var(--accent-primary)' : 'var(--text-secondary)',
            }}
          >
            {tab.label} ({tab.count})
          </button>
        ))}
      </div>

      {/* Bulk Actions */}
      {unreadCount > 0 && (
        <button onClick={handleMarkAllAsRead} className="text-sm font-medium transition-colors hover:opacity-75" style={{ color: 'var(--accent-primary)' }}>
          Mark all as read
        </button>
      )}

      {/* Notifications List */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 rounded-lg border" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)' }}>
          <Bell className="w-12 h-12 mb-4" style={{ color: 'var(--text-muted)' }} />
          <p style={{ color: 'var(--text-tertiary)' }} className="text-center">No notifications</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((notif) => {
            const isExpanded = expandedId === notif.id;
            const severity = getSeverityColor(notif.severity);

            return (
              <div
                key={notif.id}
                className="rounded-lg border overflow-hidden transition-all duration-200 cursor-pointer hover:border-blue-500"
                style={{
                  backgroundColor: notif.read ? 'var(--bg-card)' : 'var(--bg-secondary)',
                  borderColor: isExpanded ? 'var(--accent-primary)' : 'var(--border-primary)',
                }}
                onClick={() => setExpandedId(isExpanded ? null : notif.id)}
              >
                <div className="p-4">
                  <div className="flex items-start gap-4">
                    {/* Unread Dot */}
                    {!notif.read && <div className="w-2.5 h-2.5 rounded-full flex-shrink-0 mt-2" style={{ backgroundColor: 'var(--accent-primary)' }} />}

                    {/* Icon */}
                    <div className="flex-shrink-0 mt-1">{getSeverityIcon(notif.severity)}</div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between gap-2 mb-1">
                        <h3 className="font-semibold text-sm" style={{ color: notif.read ? 'var(--text-secondary)' : 'var(--text-primary)' }}>
                          {notif.title}
                        </h3>
                        <span className="px-2 py-1 rounded text-xs font-semibold flex-shrink-0" style={{ backgroundColor: severity.light, color: severity.bg }}>
                          {notif.severity.charAt(0).toUpperCase() + notif.severity.slice(1)}
                        </span>
                      </div>

                      <p className="text-sm line-clamp-2 mb-2" style={{ color: 'var(--text-tertiary)' }}>
                        {notif.message}
                      </p>

                      <div className="flex items-center gap-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                        <span>{formatTimestamp(notif.timestamp)}</span>
                        <span className="w-1 h-1 rounded-full" style={{ backgroundColor: 'var(--text-muted)' }} />
                        <span>{notif.source}</span>
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {!notif.read && (
                        <button
                          onClick={(e) => { e.stopPropagation(); handleMarkAsRead(notif.id); }}
                          className="p-2 rounded-lg transition-colors hover:opacity-75"
                          style={{ color: 'var(--text-tertiary)' }}
                          title="Mark as read"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      )}
                      <button
                        onClick={(e) => { e.stopPropagation(); handleDelete(notif.id); }}
                        className="p-2 rounded-lg transition-colors hover:opacity-75"
                        style={{ color: 'var(--text-tertiary)' }}
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Expanded Details */}
                  {isExpanded && (
                    <div className="mt-4 pt-4 border-t" style={{ borderColor: 'var(--border-primary)' }}>
                      <p className="text-sm leading-relaxed mb-4" style={{ color: 'var(--text-secondary)' }}>
                        {notif.message}
                      </p>
                      <div className="flex gap-2">
                        {!notif.read && (
                          <button
                            onClick={(e) => { e.stopPropagation(); handleMarkAsRead(notif.id); }}
                            className="px-3 py-1.5 rounded-lg text-sm font-medium text-white transition-colors"
                            style={{ backgroundColor: 'var(--accent-primary)' }}
                          >
                            Mark as read
                          </button>
                        )}
                        <button
                          onClick={(e) => { e.stopPropagation(); handleDelete(notif.id); }}
                          className="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors border"
                          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-secondary)', borderColor: 'var(--border-primary)' }}
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
