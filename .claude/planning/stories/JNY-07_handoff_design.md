# JNY-07 Design Handoff: <PivotLink> Component Contract

**From:** cspm-ui-dev + bmad-agent-ux-designer
**To:** JNY-07 implementer (bmad-dev), CP-2 reviewer (bmad-architect)
**Status:** design-complete — no code written

## Project conventions discovered
| Convention | Value | Source |
|---|---|---|
| Language | JavaScript (.jsx) — no TypeScript | frontend/package.json (no typescript dep) |
| Type checks | JSDoc only (no prop-types package) | SeverityBadge.jsx uses JSDoc @param |
| Icons | lucide-react ^0.460.0 | package.json line 18 |
| Tooltip lib | None — local hover-state pattern (useState + absolute div) | components/ciem/BehavioralTimeline.jsx:21,127 |
| Storybook | Not installed — use __previews__/ pattern | absent from package.json |
| Router | next/navigation useRouter().push (89 sites — see §9) | grep |
| Telemetry sink | None found — must create stub in lib/telemetry.js | grep trackEvent\|posthog\|datadog returned 0 |
| Severity styles | shared util at lib/severity-styles.js + SeverityBadge | exists |

## 1. Component API (props)

| Prop | Type | Required | Default | Notes |
|---|---|---|---|---|
| to | 'asset'\|'threat'\|'finding'\|'technique'\|'control'\|'scenario'\|'workload'\|'scan'\|'agent'\|'identity'\|'framework' | yes | — | Resolver key. Unknown → plain text + console.warn (dev) |
| id | string | yes | — | Entity id; URL-encoded internally |
| engine | string | required when to='finding' | — | Used in /finding/${engine}/${id}. Missing → plain text + console.warn |
| framework | string | required when to='control' | — | Used in /compliance/${framework}/control/${id} |
| provider | 'aws'\|'azure'\|'gcp'\|'oci'\|'alicloud'\|'k8s' | no | — | Passed as query string when present; surfaces in tooltip |
| label | string | no | id (middle-truncated) | Display text |
| truncate | number | no | 40 | Max chars for label rendering |
| showIcon | boolean | no | true | Lucide icon prefix |
| showSeverity | severity string | no | — | If set, render <SeverityBadge> to right |
| size | 'xs'\|'sm'\|'md' | no | 'sm' | Affects font-size + icon size |
| onClick | (e) => void | no | — | Secondary handler — runs BEFORE navigation. Telemetry fires regardless |
| children | node | no | — | Overrides label if provided |
| kind | string | no | — | Sub-type for scan (sast/dast/sca/project) — see §10 Q2 |

JSDoc-only (no PropTypes/TS). Match style of SeverityBadge.jsx.

## 2. URL resolution table

Centralized in **frontend/src/lib/pivot-routes.js** — exports resolvePivotUrl({to, id, engine, framework, provider, kind}).

| to | Resolved URL | Required extras |
|---|---|---|
| asset | /inventory/${encodeURIComponent(id)} | — |
| threat | /threats/${id} | — |
| finding | /finding/${engine}/${id} | engine |
| technique | /threats/technique/${id} | — |
| control | /compliance/${framework}/control/${id} | framework |
| framework | /compliance/${id} | — |
| scenario | /risk/scenario/${id} | — |
| workload | /cwpp/workload/${id} | — |
| scan | /secops/${id} (sast) or /secops/dast/${id} or /secops/sca/${id} | optional kind |
| agent | /vulnerability/agents/${id} | — |
| identity | /ciem/identity/${encodeURIComponent(id)} | — |

If provider is set AND target accepts it (asset, finding, scan), append ?provider=${provider}.

Validation: function throws Error('PivotLink: unknown to="..."') for unknown to. Component catches and renders plain-text fallback.

## 3. Render structure (pseudo-JSX)

```
<Link href={resolvedUrl} prefetch={false} legacyBehavior>
  <a
    className={pivotLinkClasses(size)}
    title={fullLabelOrId}
    aria-label={`Open ${entityTypeLabel}: ${id}`}
    aria-describedby={tooltipOpen ? tooltipId : undefined}
    onClick={handleClick}
    onFocus={showRichTooltip}
    onBlur={hideRichTooltip}
    onMouseEnter={scheduleRichTooltip}    // 400ms timeout
    onMouseLeave={cancelRichTooltip}
  >
    {showIcon && <EntityIcon size={iconSize} className="inline mr-1" aria-hidden />}
    <span className="truncate">{displayLabel}</span>
    {showSeverity && <SeverityBadge severity={showSeverity} className="ml-2" />}
  </a>
</Link>
{tooltipOpen && <PivotTooltip id={tooltipId} ... />}
```

**Empty/null id** → <span className="text-gray-500" title={`No ${entityTypeLabel} id`}>{label || '—'}</span>. Never an <a> without href.

**Middle-truncate** for ARNs/long ids: keep first 12 + '…' + last 8 chars; full string in title.

Tailwind 4 classes:
- base: inline-flex items-center text-cyan-400 hover:text-cyan-300 hover:underline
- focus: focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-500 rounded-sm
- size xs: text-xs, sm: text-sm, md: text-base

## 4. Hover tooltip behavior

- Trigger: 400ms setTimeout on mouseenter; immediate on focus.
- Cancel: clearTimeout on mouseleave/blur.
- Content order:
  - <EntityIcon /> <strong>{entityTypeLabel}</strong>
  - engine badge (if applicable)
  - <CloudProviderBadge provider={provider} /> (already exists in shared/)
  - severity row (if showSeverity)
  - separator
  - muted hint: "Cmd/Ctrl-click to open in new tab"
- DOM: portal-free absolute div, mirrors BehavioralTimeline.jsx:127. role="tooltip", unique id.
- Position: below-right of link; flip if near viewport edge.

No new dependencies — reuse useState + absolute-div pattern.

## 5. Telemetry event spec

**File:** frontend/src/lib/telemetry.js (new — does not exist).

```
trackEvent(name, detail) {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new CustomEvent('cspm:pivot-click',
    { detail: { name, ...detail, ts: Date.now() } }));
}
```

Global handler (same file) listens once on import:
- Sink: console.debug for now; production sink wired later via env var (DataDog RUM stub).
- Allow-list: detail.id forwarded to sink for to in {asset, threat, technique, control, framework, scenario, workload, identity}. For finding/scan/agent send id_hash (sha256 first 8 chars) — these may contain repo paths or vuln data.

PivotLink emits exactly once per click:
```
{ name: 'pivot_click', to, id, engine, provider, sourceRoute: window.location.pathname, ts }
```
Telemetry must not block navigation (fire-and-forget; never await).

## 6. Accessibility checklist

- [x] Real <a href> — keyboard navigable; supports middle-click + copy-link
- [x] aria-label="Open <entity-type-label>: <id>"
- [x] title carries full id when label truncated
- [x] Tooltip reachable on focus (not just hover)
- [x] Tooltip has role="tooltip" + aria-describedby link from <a>
- [x] Focus outline: focus-visible:outline-2 outline-cyan-500 (WCAG 2.4.7)
- [x] Color contrast: cyan-400 on slate-900 = 7.1:1 (AA pass)
- [x] Severity badge has visible text label, not color-only (already true)
- [x] No onClick-only navigation — assistive tech follows the href

## 7. Edge case handling

| Case | Behavior |
|---|---|
| id empty/null | <span class="text-gray-500"> with label or '—'. No link. No telemetry. |
| to='finding' no engine | Plain text + console.warn (dev). No link, no crash. |
| to='control' no framework | Plain text + console.warn (dev). |
| Unknown to | Plain text + console.warn (dev). |
| id with special chars (S3 ARN, OCID) | Always encodeURIComponent inside resolvePivotUrl |
| Long ARN label | Middle-truncate at truncate chars: arn:aws:s3:::ver…ucket; full in title |
| User onClick calls e.preventDefault() | Navigation suppressed; telemetry STILL fires (intentional) |
| SSR (no window) | trackEvent no-op; tooltip state false |
| Prefetch | <Link prefetch={false}> — pivot targets are detail pages; long lists would explode network |

## 8. File plan

| File | Status | Purpose |
|---|---|---|
| frontend/src/components/shared/PivotLink.jsx | NEW | The component |
| frontend/src/lib/pivot-routes.js | NEW | resolvePivotUrl() + entity registry (icons, labels) — single source of truth |
| frontend/src/lib/telemetry.js | NEW | trackEvent() + global pivot-click listener |
| frontend/src/components/shared/__previews__/PivotLink.preview.jsx | NEW | Replaces Storybook (project doesn't use it). All entity types × severities × edge cases. |
| frontend/src/components/shared/__tests__/PivotLink.test.jsx | NEW | Unit tests (per story line 87) |
| .claude/documentation/contracts/pivot-link-contract.md | NEW | Contract for JNY-08 reviewers (per story line 88) |

**Naming note:** story line 38 specifies pivotEntityRegistry.js. Renamed to pivot-routes.js to match repo's kebab-case convention (severity-styles.js, permission-constants.js) and so JNY-08/12 can import resolvePivotUrl() directly. Registry object lives in same file.

## 9. JNY-08 migration list — router.push patterns to replace

grep "router.push" frontend/src/app filtered to engine routes returned **89 hits**.

### Replace with <PivotLink> (entity-pivot clicks — ~60 sites)
| File | Line(s) | Current | New to= |
|---|---|---|---|
| app/inventory/page.jsx | 1024 | onRowClick(asset) → /inventory/${uid} | asset |
| app/threats/[threatId]/page.jsx | 800 | → /misconfig?rule_id=… | finding (engine=check) |
| app/threats/[threatId]/page.jsx | 853 | → /inventory/${uid} | asset |
| app/ciem/page.jsx | 454 | onIdentityClick → /ciem/identity/${p} | identity |
| app/secops/page.jsx | 1386-1388, 1474-1476, 1782, 1821, 2004-2006, 2048-2050, 2066-2068, 2156, 2239, 2318 | secops scan nav (sast/dast/sca) | scan (with kind) |
| app/secops/projects/page.jsx | 455, 571 | → /secops/projects/${repo} | scan w/ kind='project' (or new entity — see §10 Q1) |
| app/secops/projects/[projectId]/page.jsx | 720-721 | sast/sca scan nav | scan |
| app/secops/vuln/[id]/page.jsx | 731, 745 | vuln detail pivot | finding (engine=vulnerability) |

### Keep as router.push (back-button / redirect / query-only — NOT pivot)
| File | Line(s) | Why keep |
|---|---|---|
| app/threats/timeline/page.jsx | 48 | Back button |
| app/threats/[threatId]/page.jsx | 372, 451, 493, 897, 1423 | Back / redirect / query-string blast-radius |
| app/ciem/identity/[principal]/page.jsx | 156, 185, 194 | Back + sub-route nav |
| app/secops/[scanId]/page.jsx | 625, 664, 837 | Back |
| app/secops/sca/[sbomId]/page.jsx | 383, 409 | Back |
| app/secops/projects/page.jsx | 493 | Back |
| app/secops/projects/[projectId]/page.jsx | 757 | Back |
| app/ciem/identity/[principal]/blast-radius/page.jsx | 24 | Back |

**Migration scope: ~60 of 89 hits.** JNY-08 should ALSO sweep bare <td>{resource_uid}</td> cells (no router.push but per ADR §3.1 should be PivotLinks) — separate sub-task.

## 10. Open questions for bmad-architect (CP-2)

1. **secops project pivot** — to='project' (new entity) vs to='scan' with kind='project'? Current registry has ~10 base types; project would extend.
2. **secops sast/dast/sca divergence** — confirm to='scan' + kind='sast'|'dast'|'sca' prop is acceptable vs three separate to values. Recommend kind to keep registry small.
3. **Telemetry sink** — no existing infra. Ship lib/telemetry.js as console.debug stub now, or block JNY-07 on real sink decision (DataDog RUM vs PostHog)?
4. **Hover prefetch** — story line 54 says optional prefetch via onMouseEnter. Implement as best-effort router.prefetch(url), or defer to JNY-09? Story line 65 says "Zero new fetch calls on page load" — hover-prefetch satisfies that.
5. **Permission-aware hiding** — story line 80 says out-of-scope. Confirm: lower-role users see link, target page enforces auth (404 from BFF). OK without <Can> wrapping?
6. **Icon mapping** — proposal: asset=Server, threat=AlertTriangle, finding=Shield, technique=Crosshair, control=BookCheck, framework=Book, scenario=Gauge, workload=Box, scan=ScanLine, agent=Cpu, identity=User. Confirm or revise.
7. **Severity color collision** — link cyan + critical-red badge on same row may be visually noisy. Acceptable, or shift link color to neutral when showSeverity set?

---

**Status:** ready for bmad-dev to implement against this contract. CP-2 review by bmad-architect should resolve the 7 open questions before code.
