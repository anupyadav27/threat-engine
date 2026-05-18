# Story AP-REDESIGN-04: AssetDetailMini — Shared Component

**Epic:** Attack Path UI Redesign  
**Phase:** REDESIGN  
**Priority:** P0  
**Story Points:** 5  
**Status:** ready  
**Depends on:** none (no new BFF endpoints — uses existing asset_findings.py + asset_posture.py)  

---

## Context

When an analyst clicks a node in the attack path canvas, or clicks an asset row in inventory, they need a compact but data-rich asset detail view — without navigating away from the current page. This story creates `AssetDetailMini`, a shared component that both pages use.

**Two BFF endpoints already exist and power all four tabs:**
- `GET /api/v1/views/inventory/asset/{uid}/findings` → `asset_findings.py` (reads `security_findings` table)
- `GET /api/v1/views/inventory/asset/{uid}/posture` → `asset_posture.py` (reads `resource_security_posture`)

No engine changes. No new BFF endpoints.

---

## File to Create

```
frontend/src/components/shared/AssetDetailMini.jsx
```

---

## Component Contract

```jsx
<AssetDetailMini
  uid={node_uid}          // resource_uid to fetch findings for
  displayName={node_name} // shown in header
  resourceType={node_type} // shown as type badge
  onViewFull={() => router.push(`/inventory/${encodeURIComponent(uid)}`)}
  // optional — if steps[] data already has findings, pass them to avoid re-fetch:
  prefetchedMisconfigs={step.misconfigs}   // array from attack_path_nodes.misconfigs
  prefetchedCves={step.cves}               // array from attack_path_nodes.cves
  prefetchedThreats={step.threat_detections} // array from attack_path_nodes.threat_detections
/>
```

When `prefetched*` props are provided, the tab renders immediately without a BFF call. When absent, tabs lazy-fetch from BFF on first activation.

---

## Layout

```
┌───────────────────────────────────────────────────────────┐
│ [Type Badge]  Resource Name (truncated 40 chars)          │
│               resource_uid (small, mono, copy-on-click)   │
│                                         [View Full Asset →]│
├───────────────────────────────────────────────────────────┤
│ [Misconfigs N] [CVEs N] [CDR N] [Posture]                 │
├───────────────────────────────────────────────────────────┤
│ TAB CONTENT (scrollable, max-height 320px)                │
└───────────────────────────────────────────────────────────┘
```

---

## Acceptance Criteria

### Misconfigs Tab
- AC-1: Shows findings where `source_engine = 'check'` from `/views/inventory/asset/{uid}/findings`
- AC-2: If `prefetchedMisconfigs` prop provided, renders from prop (no BFF call)
- AC-3: Each row: severity badge (colored), title, rule_id (small mono), status chip (open/closed)
- AC-4: Sorted by severity (critical first)
- AC-5: Empty state: "No misconfigurations found for this asset"
- AC-6: Max 10 rows shown; "Show all N" link if more

### CVEs Tab
- AC-7: Shows findings where `finding_type = 'cve'` (any source_engine, typically vuln/secops)
- AC-8: If `prefetchedCves` prop provided, renders from prop (no BFF call)
- AC-9: Each row: CVE ID (`rule_id`), EPSS score (colored: ≥0.5 = red), CVSS score, KEV badge (red "KEV" if `in_kev=true`), severity badge
- AC-10: Viewer role: `epss_score` is null from BFF → show "—" not 0
- AC-11: Sorted by EPSS score desc (highest risk first)
- AC-12: Empty state: "No CVEs found for this asset"

### CDR Tab
- AC-13: Shows findings where `source_engine = 'cdr'` from findings endpoint
- AC-14: If `prefetchedThreats` prop provided, renders from prop (no BFF call)
- AC-15: Each row: MITRE technique badge (`mitre_technique_id`), tactic name (`mitre_tactic`), title, severity badge
- AC-16: Viewer role and analyst role: `detail` field is null → don't render detail section
- AC-17: Empty state: "No CDR detections for this asset"
- AC-18: Tab hidden entirely if user is viewer (CDR data restricted to analyst+)

### Posture Tab
- AC-19: Fetches `GET /api/v1/views/inventory/asset/{uid}/posture` on first tab activation (lazy)
- AC-20: Shows 8 key signals only (not all 30+ posture columns):
  - `network.is_internet_exposed` → "Internet Exposed" (red) / "Private" (green)
  - `network.is_in_private_subnet` → "Private Subnet" (green) / "Public Subnet" (amber)
  - `encryption.volume_encrypted` → "Encrypted at Rest" / "Unencrypted" (red)
  - `attack_path.is_on_attack_path` → "On Attack Path" (red) / "Not on path" (gray)
  - `attack_path.is_choke_point` → "Choke Point — breaks N paths" (red) / hidden if false
  - `iam.is_admin_role` → "Admin Role" (red) / hidden if false
  - `container.has_privileged_container` → "Privileged Container" (red) / hidden if false
  - `encryption.cert_days_remaining` → "Cert expires in N days" (amber if <30)
- AC-21: Empty posture: "Posture data not yet scanned" (not an error)

### General
- AC-22: Loading state: skeleton rows (3 lines) shown while BFF fetches
- AC-23: Error state: "Unable to load findings — 503" (no fallback data, no mock)
- AC-24: "View Full Asset →" button always visible in header; links to `/inventory/{encodeURIComponent(uid)}`
- AC-25: `credential_ref` never rendered in any tab
- AC-26: `policy_statement` never rendered in this component (it's in PathDetailPanel only)
- AC-27: Component is self-contained — no global state, no router dependency (pure props)
- AC-28: Responsive: min-width 320px, works inside accordion expansion and inventory inline

---

## Technical Notes

**Data flow for attack path node click:**
```
user clicks NodeBox in AttackPathExpanded
  → AttackPathExpanded passes step object to AssetDetailMini
  → Misconfigs, CVEs, CDR tabs use prefetched* props (no BFF call)
  → Posture tab lazy-fetches from /views/inventory/asset/{uid}/posture
```

**Data flow for inventory row click:**
```
user clicks row in inventory/page.jsx
  → AssetDetailMini rendered with uid=asset.resource_uid, no prefetched props
  → All tabs lazy-fetch from BFF on activation
```

**Tab count badges:**
- Derive from `prefetched*` length OR from BFF `by_engine` aggregates
- Show `(N)` in tab label, e.g., "Misconfigs (3)"

**Handling `null` EPSS (viewer role):**
```jsx
{epss_score !== null ? `${(epss_score * 100).toFixed(1)}%` : '—'}
```

---

## Definition of Done
- [ ] Component renders all 4 tabs with correct data sources
- [ ] `prefetched*` props used when available (avoids re-fetch in attack path context)
- [ ] Viewer role: CDR tab hidden, EPSS shows "—"
- [ ] Analyst role: CDR tab visible but `detail` not rendered
- [ ] Skeleton loading state on all lazy-fetched tabs
- [ ] "View Full Asset" link navigates to `/inventory/{uid}`
- [ ] `credential_ref` and `policy_statement` never appear in output
- [ ] Local dev test: mount component with a real `uid` from a running scan
- [ ] Passes in both contexts: inside AttackPathExpanded AND inside inventory row expand
- [ ] No global state mutation (pure component)