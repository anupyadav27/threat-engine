# SecOps Engine — Review & Improvement Roadmap

**Goal:** Build a tool competitive with (and better than) Snyk and SonarQube.

---

## Current Strengths

| Area | What you have |
|------|----------------|
| **Coverage** | 14 languages: Python, Java, C#, JS, Go, C, C++, Ruby, Terraform, Docker, K8s, Ansible, Azure ARM, CloudFormation |
| **Rules** | ~2,900 rules; SonarSource-style metadata (CWE, OWASP, type: VULNERABILITY / CODE_SMELL / SECURITY_HOTSPOT) |
| **Analysis** | AST/semantic analysis (e.g. Go: type assertions, goroutines, nil safety, data flow); language detector with structural fingerprints |
| **API** | Git clone → scan → persist; status polling; list scans; get findings with severity/language filters |
| **DB** | `secops_report`, `secops_findings`, `secops_rule_metadata` with CWE/OWASP; rule sync from scanner docs |
| **Legacy** | `fail_on_findings` on legacy `/scan`; SARIF only in docker_scanner |

---

## Gaps vs Snyk

| Gap | Impact | Recommendation |
|-----|--------|-----------------|
| **No dependency (SCA) scanning** | Snyk’s main value: known vulns in deps | Add lockfile/manifest parsing (pip, npm, go.mod, Cargo, etc.) and match against OSV / NVD or internal vuln DB. Report vulnerable package + version + fix version. |
| **No container/image scanning** | Images are a major attack surface | Add container image layer + package scan (or integrate Trivy/ Grype); report OS + app deps inside image. |
| **No license compliance** | Enterprises need license risk | Optional: report license per dependency; flag copyleft / policy violations. |
| **Remediation not in API** | Users want “how to fix” in one call | Enrich findings with `recommendation` / `remediation` from rule metadata (you already have it in DB); return in GET findings and in SARIF. |
| **SARIF not unified** | CI (GitHub, Azure DevOps) expects one SARIF run | Emit SARIF 2.1 for the **entire** scan (all scanners); add `?format=sarif` to GET findings. |

---

## Gaps vs SonarQube

| Gap | Impact | Recommendation |
|-----|--------|-----------------|
| **No quality metrics** | No “health” score or trends | Add per-scan/per-repo: duplication %, complexity distribution, security hotspot count, maintainability rating (from rules). Store in `secops_report.summary` or new table; expose in API. |
| **No quality gates** | Can’t “fail build if critical > 0” in new API | Add optional quality gate to scan request (e.g. `quality_gate: { critical: 0, high: 5 }`); return `gate_passed: bool` and `gate_details` in response. |
| **No “new” vs “overall”** | PRs need “only new issues” | Support diff context: pass base ref/commit; only report findings on changed lines/blocks; tag `is_new`. |
| **Rule parameters hardcoded** | e.g. cognitive complexity threshold | Load thresholds from rule metadata or config (e.g. `logic.threshold` in JSON); allow override per tenant/project. |
| **Security hotspot workflow** | Sonar has “review” (confirm / FP) | Persist `finding_status: open | confirmed | fixed | won't_fix`; API to update status; filter by status in GET findings. |

---

## High-Impact Improvements (Prioritized)

### 1. Unified SARIF 2.1 output (fast win)

- **Where:** API layer + small SARIF builder.
- **What:** After scan, build one SARIF `run` per language; merge into single SARIF log. Add `GET /api/v1/secops/scan/{id}/findings?format=sarif`.
- **Why:** GitHub Advanced Security, Azure DevOps, and others consume SARIF; single file per scan is expected.

### 2. Remediation in findings API

- **Where:** `secops_db_writer.persist_findings` and/or GET findings.
- **What:** JOIN `secops_rule_metadata` on `rule_id` when returning findings; add `recommendation`, `remediation`, `cwe`, `owasp` to each finding. Optionally store in `secops_findings.metadata` at persist time.
- **Why:** Matches Snyk/Sonar “fix” experience without extra round-trips.

### 3. Quality gate in scan API

- **Where:** `ScanRequest` + `_run_scan_and_persist` + response.
- **What:** Add `quality_gate: Optional[dict]` (e.g. `{"critical": 0, "high": 10}`). After persist, count by severity; set `gate_passed` and `gate_details` in response and in `secops_report.summary`.
- **Why:** Enables “fail pipeline if too many critical/high” like Sonar.

### 4. SCA / dependency scanning (biggest differentiator)

- **Where:** New module e.g. `scanner_engine/dependency_scanner/` (or per-language lockfile parsers).
- **What:** Parse lockfiles/manifests (e.g. `requirements.txt`, `package-lock.json`, `go.sum`, `Cargo.lock`); resolve to (package, version); match against vuln DB (OSV API or internal table); emit findings with rule_id, severity, fix version.
- **Why:** This is the #1 feature users compare to Snyk; even a minimal version (e.g. pip + npm + OSV) is valuable.

### 5. Quality metrics (duplication, complexity)

- **Where:** Per-scanner or post-scan aggregator.
- **What:** Reuse existing complexity/duplication rules: aggregate counts and percentages; store in scan summary (e.g. `duplication_blocks`, `avg_complexity`, `files_over_complexity_threshold`). Expose in GET scan status/summary.
- **Why:** Sonar’s “quality gate + metrics” is a key expectation; you already have the building blocks in rules.

### 6. Security hotspot status workflow

- **Where:** DB + API.
- **What:** Add `finding_status` to `secops_findings` (or use `status` values: open, confirmed, won't_fix, fixed). Add `PATCH /api/v1/secops/findings/{id}` to set status; filter by status in GET findings.
- **Why:** Reduces noise and aligns with Sonar “review hotspots” workflow.

### 7. Configurable rule parameters

- **Where:** Rule metadata (e.g. `logic.threshold`) + generic rule engines.
- **What:** When loading rule, read threshold/limits from metadata; pass into logic. Allow tenant/project override (e.g. in config or DB) later.
- **Why:** Same rule can be tuned (e.g. cognitive complexity 15 vs 20) without code change.

### 8. “New” findings only (PR/branch context)

- **Where:** Scan request + diff logic.
- **What:** Accept `base_ref` or `base_commit`; compute changed files/lines (e.g. via git diff); after scan, tag findings that fall on changed lines as `is_new`; optional mode to return only new findings.
- **Why:** PR checks should focus on “new” issues; Sonar/Snyk both do this.

---

## Optional / Later

- **Container image scanning:** Integrate Trivy or Grype for image layers + OS/app deps; or run your dependency scanner on extracted manifest.
- **License compliance:** Attach license to each dependency; policy engine for “block”/“warn” by license.
- **Performance:** Parallelize file scanning; incremental scan (only changed files); AST cache per file hash.
- **CVSS:** Add CVSS score to vulnerability findings (from rule metadata or NVD) for prioritization.

---

## Summary

- **Already strong:** Multi-language SAST, rich rules, CWE/OWASP, semantic analysis, DB and API.
- **Fast wins:** Unified SARIF, remediation in API, quality gate.
- **Differentiators:** SCA (dependency + vuln DB), quality metrics, hotspot workflow, “new” findings, configurable parameters.

Implementing **1–3** and **5** gives a Sonar-like experience; adding **4** and **6–8** gets you to “better than Snyk/Sonar” in the dimensions that matter most (deps, quality gates, remediation, and workflow).
