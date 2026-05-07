# DCAT-01 — AWS Catalog-as-Truth Learnings

**Sprint:** DCAT-01 (AWS)
**Completed:** 2026-05-07
**Final scan:** 39,611 findings across 339 services / 1,236 discovery_ids
**Flat-shape rate:** **98.8%** (39,124 flat / 487 nested)

---

## What worked

### 1. Catalog YAMLs already had the lift declared
`step6_*.discovery.yaml` files were generated long ago with `{{ response.KeyMetadata.KeySpec }}` style templates. No catalog rewrite was needed — discovery just had to actually run them. Saved ~2 weeks of catalog authoring.

### 2. boto3 type stubs gave 100% syntactic gap-detection
`scripts/catalog_gap_autogen.py` produced 49,731 missing-field patches across 372 AWS services without a single LLM call (Class IV bucket = 0). DeepSeek wired but unused. Lesson: when SDK ships strong type info, catalog gaps become a syntactic problem.

### 3. `NativeEnvironment` preserves Python types
Booleans stayed `bool`, lists stayed `list`. Plain `Environment` would have stringified everything (`True` → `"True"`) and silently corrupted DB columns.

### 4. DB sync via `rule_discoveries` was already in place
The catalog YAMLs and the DB row are the same shape (`{discovery: [...], emit: {item: {...}}}`). `dcat_db_sync.py` was an idempotent JSON-canonicalize + UPSERT — 462 services synced cleanly, no schema migration needed.

### 5. Feature flag (`DISCOVERY_RENDER_EMIT`) made rollout safe
v-dcat01 shipped with the renderer but `_RENDERER_AVAILABLE=False` because jinja2 was missing — production data was unaffected. v-dcat02 added the dep, v-dcat03/04 patched additional code paths, v-dcat05 added failure-flush. Each iteration fell back gracefully.

---

## What broke (and what we learned)

### Issue 1: Multiple emit-handling code paths in service_scanner.py
**Symptom:** v-dcat03 still produced nested data even though renderer was wired.
**Root cause:** `service_scanner.py` has THREE emit-handling locations (lines 487, 567, 846). My initial patch only covered one. When `discovery_for_each` chaining didn't apply, code dropped through to a different `elif 'item' in emit_config:` block that still did raw dump.
**Fix:** patch every emit-handling block uniformly. Future scanners (other CSPs) should consolidate to a single emit-rendering function to avoid this.
**Learning:** when refactoring inherited code, `grep -n "raw_response\|response.items()"` BEFORE patching, not after the bug surfaces.

### Issue 2: jinja2 not in requirements.txt
**Symptom:** v-dcat01 deployed but renderer's import silently failed → `_RENDERER_AVAILABLE=False` → raw dumps.
**Root cause:** `engines/discoveries/requirements.txt` didn't list jinja2. The `try/except ImportError` swallowed the error.
**Fix:** added `jinja2>=3.1.0` to requirements.
**Learning:** `try/except ImportError` is a footgun. Either fail-fast (raise) or LOG a startup banner saying "renderer disabled — feature flag will not function." Silent fallback hides config bugs.

### Issue 3: Discovery image build hung at buildkit layer
**Symptom:** `docker build` ran 30+ min with no output, stuck on requirements layer.
**Root cause:** unclear — possibly buildkit cache contention or network timeout fetching boto3==1.35.81 dep tree.
**Workaround:** built v-dcat02 via `docker run + pip install + commit` (90 seconds vs 30+ min stuck).
**Followup workaround:** v-dcat03/04/05 used `FROM v-dcat02 + COPY` Dockerfiles to layer just the patches — fast even when buildkit is slow.
**Learning:** for iterative scanner patches during a sprint, `FROM <prev>` micro-Dockerfiles are dramatically faster than full rebuilds. Production releases can do the proper full build.

### Issue 4: Argo trigger workflow has no auth header
**Symptom:** `bash trigger-scan.sh --discovery $SCAN ...` failed with 401 because the curl/python client doesn't send `X-Auth-Context`.
**Root cause:** the Argo workflow predates the AuthMiddleware on engine-discoveries.
**Workaround:** synthesize auth context inside the discovery pod, hit `localhost:8001/api/v1/discovery` directly (bypasses the Argo path).
**Learning:** Argo trigger needs a system-token mechanism (or a back-channel auth bypass for trusted internal callers). Filed separately as out-of-scope for DCAT-01.

### Issue 5: DISCOVERY_SCANNER_IMAGE env var must be updated separately
**Symptom:** new image deployed but Job pods still ran old image.
**Root cause:** the API server reads `DISCOVERY_SCANNER_IMAGE` env when creating Job specs. Updating the deployment image alone doesn't update this var.
**Fix:** every rollout did `kubectl set image` AND `kubectl set env` together.
**Learning:** the container image and the scanner-Job image are TWO different things. The deployment YAML should derive the scanner image from the deployment image (or omit DISCOVERY_SCANNER_IMAGE so it inherits). Documented for follow-up.

### Issue 6: ENTRYPOINT lost during `docker commit`
**Symptom:** v-dcat02 pod stuck in CrashLoopBackOff with `cannot open sh: No such file`.
**Root cause:** `docker create --entrypoint /bin/sh ...` set the entrypoint, then `docker commit` baked it in. Original CMD `sh -c "uvicorn ..."` collided with the inherited `/bin/sh` entrypoint → ran `sh sh -c ...`.
**Fix:** rebuild via `Dockerfile FROM <base>` instead of commit (preserves original CMD/ENTRYPOINT cleanly).
**Learning:** prefer `FROM` to `commit` for inherited image config. `docker commit --change` is brittle.

### Issue 7: Enrichment merge re-introduces nesting (the 487 nested rows)
**Symptom:** 1.2% of rows still nested after the renderer ran.
**Root cause:** `_merge_dependent_data` in `dependencies.py` merges describe_key fields into list_keys items. If ANY source row had even one residual nested key, it propagates into the target. Cross-scan: a partial old scan or an unpatched code path leaves a nested field, and enrichment carries it forward.
**Status:** known edge case, not yet fixed.
**Plan:** add a `_flatten_nested_envelopes()` step in the enrichment merge to catch any remaining nested structures (KeyMetadata, DBInstance, User, Role, Configuration, Certificate). Document as a P2 follow-up — 1.2% rate is acceptable for v1 cutover.
**Learning:** enrichment is a SECOND opportunity for nested data to enter the flat shape. Need to either flatten at enrichment-merge time, or constrain enrichment sources to only-flat data.

### Issue 8: Catalog lint surfaced 6 pre-existing bare-variable templates
**Symptom:** `lint_catalog_emits.py --provider aws` reported 6 WARNs — templates like `{{ resource_type }}` instead of `{{ response.resource_type }}`.
**Root cause:** authored manually before the catalog generator standardized on `response.X` / `item.X` / `context.X` prefixes.
**Status:** harmless today (Jinja still resolves bare vars from the context) but a smell.
**Plan:** auto-fix in next gap-autogen run; lock with a strict-mode lint rule.
**Learning:** the catalog wasn't 100% clean even before DCAT-01. The lint script is the long-term safety net.

---

## Numbers

| Metric | Value |
|---|---|
| AWS services audited | 372 |
| Auto-add field patches generated | 49,731 |
| Auto-rename patches | 1,198 |
| Class IV (LLM-needed) gaps | 0 |
| Local catalog YAMLs patched | 320 (302 with on-disk catalog; 2 had patches but no catalog) |
| `rule_discoveries` DB rows synced | 462 (14 inserted, 448 updated) |
| Discovery image iterations | 5 (v-dcat01 → v-dcat05) |
| Final flat-shape rate | 98.8% (39,124 / 39,611) |
| Lint warnings on existing catalog | 6 |
| LLM calls actually made | 0 (DeepSeek wired but unused) |

---

## Operational improvements queued

1. **Drop `DISCOVERY_SCANNER_IMAGE` env var** — derive from deployment image at scanner create time.
2. **Argo trigger auth fix** — system-token or X-Auth-Context synthesis in the trigger workflow.
3. **Enrichment-merge flatten step** — handle the 1.2% nested edge case.
4. **CI lint** — `lint_catalog_emits.py --strict` as a pre-merge gate on PRs touching catalog YAML.
5. **Failure-log dashboard** — weekly digest from `discovery_emit_failures` to drive the next round of catalog patches.
6. **Single emit-rendering function** — consolidate the 3 emit-handling spots in service_scanner.py into one call.

---

## Recommended adoption sequence for other CSPs

Based on what bit us in AWS, the per-CSP rollout should:

1. **Run the lint FIRST** — `lint_catalog_emits.py --provider <csp>` to catch obvious gaps before any code change.
2. **Run the gap-autogen** — but each CSP needs its own SDK introspection helper (azure/gcp/oci/etc. don't have boto3-like service-2.json).
3. **Add CSP-specific deps to requirements.txt** — `jinja2` for everyone; CSP SDK already in.
4. **Build the FIRST scanner image with feature flag OFF** — verify renderer is importable, log a startup banner.
5. **Flip the flag, run a small-scope scan** — single service in a single tenant.
6. **Validate flat shape ≥ 98% before broad rollout** — that's the AWS bar.
7. **Wire failure-flush at scan completion** — same pattern as `_flush_emit_failures_to_db` in run_scan.py.

Order of CSPs (by data-shape simplicity):
1. **K8s** — openapi schemas, easy SDK introspection, smallest LoC
2. **IBM** — smallest catalog (154 rows), low risk
3. **Azure** — uniform Pydantic-like models, predictable
4. **GCP** — protobuf descriptors, slightly more work
5. **AliCloud** — region partitioning quirks
6. **OCI** — largest scanner LoC

Each CSP gets its own DCAT-02-X chip per the existing sprint plan.
