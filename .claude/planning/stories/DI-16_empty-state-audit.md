# DI-16: UI — Empty State Audit: Classify All "No Data" Occurrences

## Track
Track 4 — Empty State Audit

## Priority
P1 — produces the work list for DI-17

## Story
As a product manager, I need a complete audit of every UI tab, chart, and table that shows "no data" (empty state, zero counts, or blank renders), classified by root cause, so that the engineering team knows which are legitimate empties vs. which are bugs.

## Background

"No data" in the UI has four possible root causes:

| Class | Definition | Fix |
|-------|------------|-----|
| **A: Legitimate empty** | No scan has run for this tenant/account | Show correct empty state copy: "Run your first scan to see data here." |
| **B: Data gap** | Scan ran, but pipeline step didn't write data to DB | File an engine story (Track 3) |
| **C: Wrong query** | BFF sends wrong parameters (wrong tenant_id, wrong scan_run_id, etc.) | Fix BFF query (Track 2) |
| **D: Missing route** | Frontend page calls a BFF view that doesn't exist or is misspelled | Fix the view name |

## Method

Walk each page/tab by actually navigating to it in the browser with the DevTools network panel open. For each empty state:

1. Note the page URL and component/tab name
2. Check the network tab — was a BFF view call made?
3. Was the response 200 or 4xx?
4. If 200: did the response contain data? (Check response body)
5. If data present in response but UI is empty: Class C or D (wrong query or component bug)
6. If response is empty (zeros/empty arrays): is there a scan run? Check scan_run_id in the response's scanMeta field
7. If no scan run: Class A
8. If scan run exists but no data: Class B

## Pages to Audit

Organize by navigation section:

### Security Posture
- [ ] Dashboard — KPI strip (8 metrics)
- [ ] Dashboard — Posture Score hero
- [ ] Dashboard — Cloud Health grid
- [ ] Dashboard — Compliance Framework gauges
- [ ] Dashboard — MITRE Top 5 Techniques
- [ ] Dashboard — Threat Activity Trend (30d)
- [ ] Dashboard — Top 10 Riskiest Resources

### Threats (9 tabs)
- [ ] Threats — Overview tab (threat cards)
- [ ] Threats — MITRE ATT&CK tab (heatmap grid)
- [ ] Threats — Attack Paths tab
- [ ] Threats — Findings tab
- [ ] Threats — Timeline tab
- [ ] Threats — Command Room
- [ ] Threats — Toxic Combos
- [ ] Threats — Blast Radius
- [ ] Threats — Posture Delta

### Compliance
- [ ] Compliance — Frameworks list (score gauges)
- [ ] Compliance — Controls table
- [ ] Compliance — Trend chart

### Cloud Security (Misconfig)
- [ ] Misconfig — Findings table
- [ ] Misconfig — Summary by service

### Inventory
- [ ] Inventory — Resource list
- [ ] Inventory — By provider chart
- [ ] Inventory — Drift count

### IAM
- [ ] IAM — Findings table
- [ ] IAM — Privilege escalation risks

### Network Security
- [ ] Network — Topology view
- [ ] Network — Layer findings

### Data Security
- [ ] DataSec — Data resources
- [ ] DataSec — Classification summary

### Other Pillars
- [ ] CIEM — Identity risks
- [ ] CNAPP — Aggregated score
- [ ] CWPP — Workload findings
- [ ] Container Security — Image findings
- [ ] Database Security — DB findings
- [ ] Encryption — Key management
- [ ] AI Security — AI service risks
- [ ] Vulnerability — CVE findings
- [ ] SecOps — IaC scan results
- [ ] Risk — Risk scenarios

## Deliverable

A spreadsheet-style classification table. Format:

```
| Page | Component | Class | Root Cause | Fix |
|------|-----------|-------|------------|-----|
| /threats | MITRE tab | B | mitre_tactics always NULL | DI-15 |
| /threats | Attack Paths | A | No attack path data in scan | Correct empty state copy |
| /compliance | Frameworks | C | BFF queries wrong framework table | DI-10 |
| /dashboard | MITRE Top 5 | B | same as DI-15 | DI-15 |
```

## Acceptance Criteria

- [ ] Every page/tab in the list above has been visited and classified
- [ ] Classification table is complete (all 30+ components)
- [ ] Each Class B, C, D item has a referenced fix story (or new story filed)
- [ ] Each Class A item has correct empty state copy defined (see DI-17)
- [ ] No "unknown" classification allowed — must follow the audit method until classified

## Time Estimate

1 day to audit, 0.5 days to write the table.

## Definition of Done
- Audit complete
- Table committed to `.claude/planning/` as `DI-16-empty-state-audit-results.md`
- All Class C/D items either fixed in this story or filed as new stories
