# Rule Check Python Code Generation — Master Plan

**Goal**: Generate verified Python check functions (and YAML rules) for 9,614 security rules across 7 CSPs, without LLM hallucination.

**Strategy**: Write Python that *runs* → record the op/field/operator → emit YAML. Validation is built in because each check must produce a real value from a real (or fixture) API response.

---

## Rule Universe (as of 2026-04-17)

| CSP      | Rules | File                                    |
|----------|------:|-----------------------------------------|
| AWS      | 1,928 | `1_aws_full_scope_assertions.yaml`      |
| Azure    | 1,660 | `2_azure_full_scope_assertions.yaml`    |
| GCP      | 1,319 | `3_gcp_full_scope_assertions.yaml`      |
| OCI      | 1,914 | `4_oci_full_scope_assertions.yaml`      |
| K8s      |   718 | `5_k8s_full_scope_assertions.yaml`      |
| AliCloud | 1,374 | `6_alicloud_full_scope_assertions.yaml` |
| IBM      |    56 | `7_ibm_full_scope_assertions.yaml`      |
| **Total** | **8,969** |                                    |

---

## Phase 0 — Triage / Implementability Classification

**Goal**: For every rule_id, label it with one of:

| Class         | Meaning                                              | Next step          |
|---------------|------------------------------------------------------|--------------------|
| SCAN_ABLE     | Provable via a single CSP API response field        | → code-gen Phase 3 |
| MULTI_OP      | Requires 2+ API calls (list then describe)          | → code-gen Phase 3 |
| POLICY_ATTEST | Governance/policy attestation, no API field exists  | → skip / manual    |
| AMBIGUOUS     | Rule name too vague to decide                       | → human review     |

### Approach

1. **Heuristics first (free, deterministic)**: rule-name patterns can classify 60-70% without any LLM
   - "antivirus_enabled", "change_control_enabled", "policy_enforcement" → POLICY_ATTEST
   - "encryption_enabled", "logging_enabled", "public", "status" → SCAN_ABLE candidate
   - Known non-API verbs: `enforced`, `reviewed`, `maintained`, `documented`, `validated`, `trained` → POLICY_ATTEST

2. **LLM classifier for the residual** (cheap: Mistral Small / DeepSeek): only the ~30% that heuristics can't decide

### Deliverables

- [ ] `classify_rules.py` — heuristic + (optional) LLM classifier
- [ ] In-place YAML update: add `implementable: SCAN_ABLE | MULTI_OP | POLICY_ATTEST | AMBIGUOUS` to every rule entry
- [ ] `triage_report.csv` — summary counts per CSP × class
- [ ] `triage_report.md` — human-readable breakdown

### Expected outcome

Probably ~5,000-6,000 SCAN_ABLE rules → that's the real code-gen target.

### Actual outcome (2026-04-17, final after Phase 0b refinement)

| CSP | SCAN_ABLE | MULTI_OP | POLICY_ATTEST | EVENT | AMBIGUOUS | Total | Scannable % |
|---|---:|---:|---:|---:|---:|---:|---:|
| AWS | 1,908 | 12 | 5 | 3 | 0 | 1,928 | 99.0% |
| Azure | 1,631 | 8 | 11 | 2 | 8 | 1,660 | 98.1% |
| GCP | 1,299 | 9 | 5 | 6 | 0 | 1,319 | 98.3% |
| OCI | 1,887 | 9 | 10 | 8 | 0 | 1,914 | 98.7% |
| K8s | 696 | 0 | 19 | 3 | 0 | 718 | 96.9% |
| AliCloud | 1,351 | 5 | 8 | 7 | 3 | 1,374 | 98.7% |
| IBM | 38 | 0 | 0 | 18 | 0 | 56 | 67.9% |
| **Total** | **8,810** | **43** | **58** | **47** | **11** | **8,969** | **98.9%** |

**Real code-gen target: 8,853 rules** (SCAN_ABLE + MULTI_OP).

Notes:
- **MULTI_OP strict definition applied**: MULTI_OP only when CHECK CONDITION
  fields come from *different* API operations. Single-op reads (`bucket_policy`,
  `resource_policy`, `role_assignment`, `policy_bindings`, plain `_attached`)
  moved to SCAN_ABLE (110 → 43 MULTI_OP).
- **Posture-override suffix fix**: EVENT tokens like `_policy_change`,
  `_terminated`, `_removed` no longer misclassify config checks whose rule_id
  ends in `_enabled`, `_configured`, `_threshold_check`, etc.
- **11 AMBIGUOUS** remain (Azure: 8 `*.basic.compliance.check` + `*.configured`;
  AliCloud: 3 `*.configured`). These need LLM re-classifier (~$0.50).
- **47 EVENT** rules are threat-detection events — route to threat engine, skip
  check-engine code-gen.
- **58 POLICY_ATTEST** rules cover governance (training, runbooks, process
  documentation). Mark as "attestation-only" in rule DB.

---

## Phase 0b — Python Client Categorization + Duplicate Suppression

**Goal**: Tag every rule with its SDK client, identify cross-service duplicates, and mark canonicals so Phase 3 generates one shared function instead of N copies.

### Two fields added to each rule entry

| Field | Meaning |
|-------|---------|
| `python_client` | Primary SDK client that owns the resource (e.g. `boto3.ec2`, `azure.mgmt.storage`) |
| `check_client` | SDK client that executes the *check logic* — differs from `python_client` for cross-service checks (IAM role audits, KMS key checks, audit-log checks) |

When `check_client == python_client` → single-client check, generate normally.
When `check_client != python_client` → cross-service check; the generated function calls `check_client`'s API.

### Duplicate suppression

Rules with the same `(check_client, check_leaf)` across 2+ different primary services share identical check logic.
One is marked **canonical**; the rest get `is_duplicate: true` + `canonical_rule_id`.
Phase 3 code-gen produces ONE function for the canonical; duplicate rules reference it.

### Actual outcome (2026-04-17)

| CSP | Total rules | Unique clients | Duplicates suppressed |
|-----|----------:|---------------:|---------------------:|
| AWS | 1,928 | 93 | 26 (IAM: 21, KMS: 5) |
| Azure | 1,660 | 53 | 0 |
| GCP | 1,319 | 80 | 4 (audit log) |
| OCI | 1,914 | 40 | 10 (audit log) |
| K8s | 718 | 10 | 0 |
| AliCloud | 1,374 | 39 | 2 (CloudMonitor) |
| IBM | 56 | 11 | 0 |
| **Total** | **8,969** | — | **42** |

Net code-gen target after dedup: **8,811 unique check functions** (8,853 scannable − 42 duplicates).

### Deliverables

- [x] `categorize_by_client.py` — client mapper + dedup engine
- [x] `client_dedup_report.md` — duplicate list with canonical references
- [x] `client_groups.csv` — full rule × client detail table
- [x] All 7 YAML files updated in-place with `python_client`, `check_client`, `is_duplicate`, `canonical_rule_id`

---

## Phase 1 — Golden Set (manual)

**Goal**: Hand-craft 30 reference checks (5 per CSP except IBM) that cover every extractor/operator pattern the LLM will need to mimic.

### Diversity checklist

- [ ] Simple scalar field (`status == "ACTIVE"`)
- [ ] Nested dot-path (`config.encryption.enabled`)
- [ ] CLI flag in array (K8s `--audit-policy-file`)
- [ ] Array `any` (`any tag.Key == "Environment"`)
- [ ] Array `all` (`all rules have action=DENY`)
- [ ] Array `count` (`>= 2 MFA devices`)
- [ ] Multi-op (list buckets → get encryption)
- [ ] Missing-resource = FAIL (account-wide check)
- [ ] Boolean flip (`disabled == false` = enabled)
- [ ] Numeric threshold (`MaxAge >= 30`)

### Deliverables

- [x] `golden/` folder — 30 `.py` golden checks (5 × 6 CSPs), each with inline PASS/FAIL fixtures
- [x] `python_to_yaml_generator.py` — condition evaluator + YAML emitter (`extract_value`, `evaluate_condition`, `evaluate_conditions`, `CheckSpec`, `run_spec`, `emit_yaml`, `GoldenCheck`)
- [x] `golden/check_runner.py` — validation harness: **30/30 pass**

### Patterns covered

| # | Pattern | Example rule |
|---|---------|-------------|
| 1 | scalar-exists | aws.s3.bucket.server_side_encryption_enabled |
| 2 | nested-multi-all | aws.iam.account.password_policy_compliant |
| 3 | array-not-contains | aws.ec2.securitygroup.unrestricted_ssh_access |
| 4 | boolean-equals-false / not_exists | aws.ec2.instance.public_ip_auto_assign_disabled |
| 5 | numeric-threshold (lt/gte) | aws.iam.user.access_key_age_90_days |
| 6 | scalar-equals-true | azure.storage.account.https_traffic_only_enabled |
| 7 | nested-boolean | azure.keyvault.vault.soft_delete_enabled |
| 8 | value-in-list (in operator) | azure.sql.server.tls_minimum_version_compliant |
| 9 | not-empty (account-wide list) | azure.monitor.activitylog.alert_for_policy_write_configured |
| 10 | array-not-equals | azure.network.securitygroup.rdp_access_restricted |
| 11 | boolean-is-false | gcp.compute.instance.serial_port_access_disabled |
| 12 | scalar-equals | gcp.storage.bucket.public_access_prevention_enforced |
| 13 | deep-nested-exists (3 levels) | gcp.sql.instance.ssl_enforcement_enabled |
| 14 | array-all-condition | gcp.compute.instance.shielded_vm_all_options_enabled |
| 15 | array-filter-not-contains (any) | gcp.compute.firewall.no_open_rdp_from_internet |
| 16 | scalar-exists (OCI) | oci.objectstorage.bucket.encryption_at_rest_enabled |
| 17 | scalar-equals (OCI) | oci.iam.user.mfa_activated |
| 18 | nested-path (2-level nested all) | oci.database.autonomous_database.auto_backup_enabled |
| 19 | length-gte (array count) | oci.monitoring.alarm.critical_alarm_count_sufficient |
| 20 | not-empty (OCI) | oci.networking.vcn.security_list_configured |
| 21 | boolean-is-false (K8s array) | k8s.pod.container.privileged_mode_disabled |
| 22 | array-not-empty | k8s.pod.container.resource_limits_configured |
| 23 | not-equals-wildcard | k8s.rbac.clusterrole.wildcard_verbs_restricted |
| 24 | annotation-key-exists | k8s.namespace.security.pod_security_standard_applied |
| 25 | nested-spec-is-true | k8s.pod.container.readonly_rootfs_enabled |
| 26 | scalar-exists (AliCloud) | alicloud.oss.bucket.server_side_encryption_enabled |
| 27 | scalar-equals-true (AliCloud) | alicloud.ecs.instance.disk_encrypted |
| 28 | nested-exists | alicloud.ram.account.mfa_required_for_login |
| 29 | array-not-contains (AliCloud) | alicloud.vpc.security_group.no_open_ssh_from_internet |
| 30 | scalar-equals-enum | alicloud.slb.listener.https_listener_only |

---

## Phase 2 — Fixture Library

**Goal**: Capture ~500-800 real CSP API responses, one per unique `(csp, service, operation)` tuple. Enables free offline validation forever.

### Approach

1. Extract unique `(csp, service)` pairs from classified YAML
2. For each service, identify the `describe_*`/`list_*`/`get_*` ops the checks will use
3. Capture via:
   - AWS: `aws {service} {op} --output json > fixtures/aws/{service}/{op}.json`
   - Azure: `az {service} {op} -o json`
   - GCP: `gcloud {service} {op} --format=json`
   - K8s: `kubectl get {resource} -o json`
4. Sanitize: strip account IDs, emails, ARNs → `{ACCOUNT_ID}`, `{EMAIL}`

### Actual outcome (2026-04-17)

| CSP | Unique ops | Fixtures generated | Notes |
|-----|----------:|------------------:|-------|
| AWS | 596 | 567 | Covers all major services |
| Azure | 205 | 179 | 26 ops have no discovery schema |
| GCP | 134 | 102 | 32 ops have no discovery schema |
| OCI | 66 | 61 | — |
| K8s | 57 | 33 | 24 ops use condition-var fallback |
| AliCloud | 0 | 0 | No rule_check dir yet (Phase 3) |
| IBM | 0 | 0 | No rule_check dir yet (Phase 3) |
| **Total** | **1,058** | **942** | **89.0% coverage** |

Synthetic fixture heuristics cover realistic PASS/FAIL values for:
- Boolean prefixes (`Require*`, `Allow*`, `Expire*`, `Hard*`)
- Numeric thresholds (`Age`, `Length`, `Count`, `Days`, `Interval`)
- Security enums (`TlsVersion`, `Protocol`, `Prevention`, `Action`)
- Array patterns (`verbs`, `resources`, `rules`, `ports`)
- Encryption/access fields (`SSE`, `public_access`, `logging`, `replication`)

### Deliverables

- [x] `fixtures/{csp}/{service}/{op}.json` tree (942 files)
- [x] `fixtures/index.json` — lookup map (op → fixture path + fields + rule_count)
- [x] `capture_fixtures.sh` — re-runnable script (real CLI commands for all 1,058 ops)
- [x] `build_fixture_index.py` — generator script with heuristic fixture synthesis

---

## Phase 3 — Bulk Generation

**Goal**: For every SCAN_ABLE + MULTI_OP rule, generate the Python check function using LLM + immediate fixture-validation.

### Generation loop

```
for rule in classified_rules where implementable in (SCAN_ABLE, MULTI_OP):
    prompt = build_prompt(
        rule=rule,
        golden_examples=pick_similar(rule, golden_set, k=3),
        fixture=find_fixture(rule.csp, rule.service),
    )
    code = llm.generate(prompt)
    yaml_out = run_against_fixture(code, fixture)
    if validated(yaml_out):
        save(rule.rule_id, yaml_out)
    else:
        queue_retry(rule, with_better_model=True)
```

### Model tiering

| Tier | Model | Use | Expected pass rate |
|------|-------|-----|--------------------|
| 1 | Mistral Small / Codestral | First pass | ~70% |
| 2 | DeepSeek V3 / Claude Haiku | Retry failures | ~85% cumulative |
| 3 | Claude Sonnet / Opus | Hard cases | ~95% cumulative |
| 4 | Human | Residual edge cases | 100% |

### Cost target

Under $20 total for all 6k scan-able rules.

### Deliverables

- [ ] `generate_checks.py` — batch driver with retry + tier escalation
- [ ] `generated/{csp}/{service}/{rule_id}.yaml` — output tree
- [ ] `generated/{csp}/{service}/{rule_id}.py` — the check function
- [ ] `generation_report.csv` — per-rule pass/fail, model used

---

## Phase 4 — Validation & Integration

**Goal**: Prove generated rules work against live CSP accounts, merge into production rule DB.

### Steps

1. **Live run**: pick 100 random generated rules, run against the sandbox account, confirm findings shape
2. **Compare**: diff generated rules vs existing hand-written rules in `catalog/rule/{csp}_rule_check/`
3. **Merge**: import into `rule_discoveries` / check DB
4. **Canary**: enable 10% of new rules in staging scan pipeline; watch for error rate
5. **Full rollout**: enable all

### Deliverables

- [ ] `validate_live.py` — runs generated checks against real accounts
- [ ] `validation_report.csv` — pass/fail per rule on live data
- [ ] DB migration SQL to insert validated rules
- [ ] Runbook: how to re-generate after rule-catalog updates

---

## Milestones / Gating

| Gate | Criterion                                                   |
|------|-------------------------------------------------------------|
| G0   | Phase 0 complete → scan-able rule count finalized           |
| G1   | Phase 1 complete → 30 golden checks running offline         |
| G2   | Phase 2 complete → fixtures cover 95% of unique (csp, svc)  |
| G3   | Phase 3 complete → generated YAML for ≥ 90% of scan-able    |
| G4   | Phase 4 complete → ≥ 80% of generated rules pass live run   |

---

## Current Status

- [x] Plan written (this file)
- [x] **Phase 0 — Triage** (complete 2026-04-17 — 98.9% scan-able; 11 genuinely AMBIGUOUS; MULTI_OP strict definition applied 110→43; posture-override suffix fix)
- [x] **Phase 0b — Client categorization + dedup** (complete 2026-04-17 — 42 duplicates suppressed; 8,811 unique functions to generate)
- [x] **Phase 1 — Golden set** (complete 2026-04-17 — 30/30 checks pass; 15 unique patterns; `python_to_yaml_generator.py` validated)
- [x] **Phase 2 — Fixture library** (complete 2026-04-17 — 942 fixtures; realistic PASS/FAIL heuristics; index.json + capture_fixtures.sh)
- [ ] Phase 3 — Generation
- [ ] Phase 4 — Validation

---

## Key Files

| File | Purpose |
|------|---------|
| `PLAN.md` | This plan |
| `classify_rules.py` | Phase 0 classifier (next) |
| `1_aws_full_scope_assertions.yaml` through `7_ibm_...` | Input rule catalog, updated in-place with `implementable:` |
| `triage_report.csv` | Per-CSP × class summary |
| `golden/` | Phase 1 reference checks |
| `fixtures/` | Phase 2 captured responses |
| `generated/` | Phase 3 output |

---

*Last updated: 2026-04-17*
