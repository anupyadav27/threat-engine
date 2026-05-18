# Story SF-P4-01: Findings Tab in PostureTabs (Asset Detail)

## Status: done

## Metadata
- **Phase**: P4 — UI Layer
- **Epic**: Security Findings Unified Layer (sub-project of Attack Path Engine Epic)
- **Points**: 3
- **Priority**: P1
- **Depends on**: SF-P2-01 (BFF /views/inventory/asset/{uid}/findings endpoint exists), SF-P0-01 (table exists)
- **Blocks**: nothing — adds new UI surface for existing data
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — new client-side data fetch, RBAC field-stripping awareness.

## User Story

As an analyst reviewing an asset, I want a "Findings" tab in the PostureTabs component on the asset detail page so that I can see all unified security findings (from check, IAM, network, datasec, vuln, CDR, and container engines) for this specific resource without leaving the asset detail page.

## Context

PostureTabs currently renders 5 dimension tabs (Network, IAM, Encryption, Data, Database) that all share a single fetch from `/views/inventory/asset/{uid}/posture`. The Findings tab is a 6th tab that fetches from a separate endpoint `/views/inventory/asset/{uid}/findings` (SF-P2-01). Since the data sources are different, FindingsPanel manages its own fetch lifecycle independently from the posture tabs.

**Multi-CSP scope**: The endpoint returns findings from all source engines regardless of CSP. K8s findings appear as `finding_type=k8s_violation` or `container_risk` with `provider=k8s`. The tab renders identically for AWS, Azure, GCP, OCI, and K8s resources.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC

## Acceptance Criteria

### Functional
- [ ] AC-1: 'findings' tab appears as the last tab in PostureTabs for all resource types (resolveTabs returns all resource type arrays with 'findings' appended)
- [ ] AC-2: TAB_META entry: `findings: { label: 'Findings', Icon: Search, color: '#f97316' }`
- [ ] AC-3: `FindingsPanel` is self-contained — it has its own state (`data`, `loading`, `error`, `loaded`) and fetches from `/gateway/api/v1/views/inventory/asset/${encodeURIComponent(resourceUid)}/findings` with `credentials: 'include'`
- [ ] AC-4: FindingsPanel renders: severity chips summary row (`N critical`, `N high`, etc.) + per-finding rows showing severity badge, source_engine badge, and title
- [ ] AC-5: Finding rows show source_engine with a distinct color per engine (check=#0ea5e9, iam=#a855f7, network=#22c55e, datasec=#f97316, vuln=#ef4444, cdr=#eab308, container=#6d28d9)
- [ ] AC-6: FindingsPanel caps display at 20 rows — shows "Showing 20 of N findings" when more exist
- [ ] AC-7: Empty state: "No findings posture signals collected yet" — uses existing EmptyDimension component
- [ ] AC-8: Error state: "Could not load findings: {error}" — consistent with other tab error styling
- [ ] AC-9: Loading state: 4 pulse skeleton rows — same as other tabs
- [ ] AC-10: FindingsPanel does NOT share the posture loading/error state — these are independent fetch lifecycles
- [ ] AC-11: When viewer role fetches this endpoint, the BFF already strips `detail` and `epss_score` server-side — the UI does not need to add client-side stripping (trust server)

### Security
- [ ] AC-12: No DEV_BYPASS_AUTH in modified files
- [ ] AC-13: Fetch uses `credentials: 'include'` — session cookie sent; no hardcoded auth headers

## Key Files
- `/Users/apple/Desktop/threat-engine/frontend/src/app/inventory/[assetId]/PostureTabs.jsx` (modified — Findings tab added)

## Definition of Done
- [ ] PostureTabs.jsx modified and committed with FindingsPanel component
- [ ] Findings tab visible in browser for any asset that has security findings
- [ ] Severity chip summary renders correctly (counts from `data.by_severity`)
- [ ] Source engine badges render with correct colors
- [ ] Empty state shown when no findings exist for this resource
- [ ] Viewer role: tab renders; detail field not shown (server-side stripping verified via Network tab in DevTools)
- [ ] bmad-security-reviewer: no BLOCKERS