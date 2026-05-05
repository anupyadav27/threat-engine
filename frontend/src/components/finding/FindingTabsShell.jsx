'use client';

import { useEffect, useMemo, useState, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import dynamic from 'next/dynamic';
import { emit } from '@/lib/telemetry';
import { ENGINE_FINDING_TABS } from '@/lib/engine-finding-tabs';
import OverviewTab from './OverviewTab';
import ResourceContextTab from './ResourceContextTab';
import RelatedFindingsTab from './RelatedFindingsTab';
import ComplianceTab from './ComplianceTab';
import RemediationTab from './RemediationTab';

const UNIVERSAL_TABS = [
  { tabId: 'overview',    label: 'Overview',         Component: OverviewTab },
  { tabId: 'resource',    label: 'Resource Context', Component: ResourceContextTab },
  { tabId: 'related',     label: 'Related Findings', Component: RelatedFindingsTab },
  { tabId: 'compliance',  label: 'Compliance',       Component: ComplianceTab },
  { tabId: 'remediation', label: 'Remediation',      Component: RemediationTab },
];

export default function FindingTabsShell({ finding, engine, id, data }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialTab = searchParams.get('tab') || 'overview';
  const [activeTab, setActiveTab] = useState(initialTab);

  const tabPermissions = data?.tabPermissions || finding?.tabPermissions || {};

  // Build engine-specific tabs from registry (lazy via next/dynamic)
  const engineTabs = useMemo(() => {
    const entries = ENGINE_FINDING_TABS[engine] || [];
    return entries
      .filter((entry) => (typeof entry.visible === 'function' ? entry.visible(finding) : true))
      .map((entry) => ({
        tabId: entry.tabId,
        label: entry.label,
        Component: dynamic(entry.component, { ssr: false }),
        registryEntry: entry,
      }));
  }, [engine, finding]);

  const allTabs = useMemo(() => {
    return [...UNIVERSAL_TABS, ...engineTabs].filter((t) => {
      // Hide compliance tab when BFF says user lacks framework access.
      if (t.tabId === 'compliance' && tabPermissions.compliance === false) return false;
      return true;
    });
  }, [engineTabs, tabPermissions]);

  // Keep ?tab= in sync (no full refetch — AC-6)
  useEffect(() => {
    const desired = searchParams.get('tab') || 'overview';
    if (desired !== activeTab) setActiveTab(desired);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  function selectTab(tabId) {
    if (tabId === activeTab) return;
    emit('finding.tab_switch', { engine, finding_id: id, from: activeTab, to: tabId });
    setActiveTab(tabId);
    const params = new URLSearchParams(searchParams.toString());
    params.set('tab', tabId);
    router.replace(`?${params.toString()}`, { scroll: false });
  }

  // Fall back to overview if active tab was hidden (e.g. compliance 403)
  const safeActiveTab = allTabs.find((t) => t.tabId === activeTab) ? activeTab : 'overview';
  const ActiveComponent = (allTabs.find((t) => t.tabId === safeActiveTab) || UNIVERSAL_TABS[0]).Component;

  return (
    <div className="flex flex-col">
      <div
        className="flex flex-wrap gap-1 border-b mb-4"
        style={{ borderColor: 'var(--border-primary)' }}
        role="tablist"
      >
        {allTabs.map((t) => {
          const isActive = t.tabId === safeActiveTab;
          return (
            <button
              key={t.tabId}
              role="tab"
              aria-selected={isActive}
              onClick={() => selectTab(t.tabId)}
              className="px-3 py-2 text-sm font-medium border-b-2 transition-colors"
              style={{
                color: isActive ? 'var(--accent-primary)' : 'var(--text-muted)',
                borderColor: isActive ? 'var(--accent-primary)' : 'transparent',
              }}
            >
              {t.label}
            </button>
          );
        })}
      </div>

      <div role="tabpanel">
        <Suspense fallback={<div className="p-6 text-sm" style={{ color: 'var(--text-muted)' }}>Loading…</div>}>
          <ActiveComponent finding={finding} engine={engine} id={id} data={data} />
        </Suspense>
      </div>
    </div>
  );
}
