# Story PC-GAP-05: Encryption Engine — Pattern B → Pattern A (AWS First)

## Status: done

## Metadata
- **Phase**: CSP Coverage Track — Provider Pattern Upgrade
- **Sprint**: Posture Coverage Enhancement
- **Points**: 5 (AWS first; subsequent CSPs are 3 pts each — separate stories)
- **Priority**: P2 — Medium ROI
- **Depends on**: PC-P1-01 (Encryption posture writer must exist first)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-architect (pattern change) + bmad-security-reviewer

## Gap Being Closed

The Encryption engine is currently **Pattern B** — providers only define which discovery services to load. `run_scan.py` drives generic analysis using `check_findings` only. This means:

- **KMS key rotation state**: NOT checked via actual KMS API data (only via check rules that may not exist for all CSPs)
- **Imported key material detection**: NOT checked (requires KMS `Origin=EXTERNAL` field from discovery)
- **Certificate expiry days**: NOT computed from actual ACM certificate expiry date
- **TLS version from load balancer config**: NOT read from actual ALB listener policy
- **Multi-region key replication**: NOT detected

The encryption posture columns `cert_days_remaining` and `tls_version` exist in `resource_security_posture` but are **never written** (currently zero/null for all resources) because Pattern B can't read these from discovery data.

## Pattern Change for AWS

### Current Pattern B flow (all CSPs today)

```
run_scan.py
  → AWSEncryptionProvider.key_services  # just a list
  → disc_reader.load_all_encryption_resources(services=provider.key_services)
  → for resource in resources:
      findings = check_findings WHERE resource_uid = resource.uid
      # Pattern B: no custom analysis — just aggregate check findings
```

### New Pattern A flow (AWS after this story)

```
run_scan.py
  → AWSEncryptionProvider.analyze(scan_run_id, tenant_id, account_id)
      → load discovery_findings for KMS, ACM, ACM-PCA, SecretsManager, SSM
      → _analyze_kms()     ← rotation state, origin, multi-region
      → _analyze_acm()     ← cert expiry days, key algorithm, renewal status
      → _analyze_secrets() ← SecretManager rotation state
      → return List[EncryptionFinding]
```

### Base Class Change

Current `BaseEncryptionProvider` has NO `analyze()` abstract method. After this story:

```python
# engines/encryption/encryption_security_engine/providers/base.py
class BaseEncryptionProvider(ABC):

    # Pattern B properties (keep for backward compat with non-AWS CSPs)
    @property
    def key_services(self) -> List[str]: return []
    @property
    def cert_services(self) -> List[str]: return []

    # Pattern A — optional override (AWS implements, others still use Pattern B)
    def analyze(self, scan_run_id: str, tenant_id: int,
                account_id: str) -> Optional[List[EncryptionFinding]]:
        return None  # None means "use Pattern B fallback"
```

`run_scan.py` checks: `if (findings := provider.analyze(...)) is not None: use findings; else: use Pattern B`

This allows **incremental migration** — AWS moves to Pattern A in this story, other CSPs follow in separate stories.

---

## AWS Encryption Analysis Modules

### Module 1 — KMS Key Analysis

**Discovery IDs:**
- `aws.kms.list_keys` — all KMS keys
- `aws.kms.describe_key` — KeyMetadata: Origin, KeyRotationEnabled, MultiRegion, KeyState
- `aws.kms.get_key_rotation_status` — RotationEnabled: bool

**Findings to generate:**

| Rule ID | Severity | Check |
|---------|---------|-------|
| `aws.kms.key.rotation_enabled` | HIGH | `KeyRotationEnabled=false` for SYMMETRIC_DEFAULT keys |
| `aws.kms.key.no_imported_material` | MEDIUM | `Origin=EXTERNAL` (imported key material — cannot be rotated automatically) |
| `aws.kms.key.not_multi_region_replica` | LOW | Key is a multi-region replica (`MultiRegionKeyType=REPLICA`) — deletion risk |
| `aws.kms.key.not_pending_deletion` | CRITICAL | `KeyState=PendingDeletion` — key used for encryption is about to be deleted |
| `aws.kms.key.cmk_not_exposed_via_policy` | HIGH | Key policy allows `kms:*` to `*` principal |

**Posture signals written:**
- `has_kms_managed_key=True/False` per resource (from KMS policy cross-reference)
- `is_encrypted_at_rest=True` if CMK active

### Module 2 — ACM Certificate Analysis

**Discovery IDs:**
- `aws.acm.list_certificates` — all certs per region
- `aws.acm.describe_certificate` — NotAfter (expiry), KeyAlgorithm, RenewalStatus, InUseBy

**Findings to generate:**

| Rule ID | Severity | Check |
|---------|---------|-------|
| `aws.acm.certificate.not_expiring_soon` | CRITICAL | `NotAfter` within 30 days |
| `aws.acm.certificate.not_expiring_60_days` | HIGH | `NotAfter` within 60 days |
| `aws.acm.certificate.auto_renewal_enabled` | HIGH | `RenewalStatus != SUCCESS` for managed certs (auto-renewal failed) |
| `aws.acm.certificate.rsa_2048_or_better` | MEDIUM | `KeyAlgorithm` is `RSA_1024` (deprecated) |
| `aws.acm.certificate.in_use` | LOW | Certificate not attached to any resource (`InUseBy` empty) — orphaned |

**Posture signals written:**
- `has_valid_certificate=True/False`
- `cert_days_remaining=N` (integer: days until `NotAfter`)
- `tls_version="TLSv1.2"` (from ALB listener — see Module 3)

### Module 3 — ALB/ELB TLS Version

**Discovery IDs:**
- `aws.elbv2.describe_listeners` — Protocol, SslPolicy
- `aws.elbv2.describe_load_balancers` — Scheme (internet-facing vs internal)

**SSL Policy → TLS version mapping:**

| SSL Policy | Min TLS |
|-----------|---------|
| ELBSecurityPolicy-TLS13-1-2-2021-06 | TLSv1.3 |
| ELBSecurityPolicy-2016-08 | TLSv1.0 (insecure) |
| ELBSecurityPolicy-TLS-1-2-Ext-2018-06 | TLSv1.2 |

**Findings:**

| Rule ID | Severity | Check |
|---------|---------|-------|
| `aws.elbv2.listener.tls_12_or_better` | HIGH | Listener SslPolicy allows TLSv1.0 or TLSv1.1 |
| `aws.elbv2.listener.https_only` | CRITICAL | Internet-facing LB has HTTP listener on port 80 with no redirect |

**Posture signal:** `tls_version="TLSv1.2"` or `"TLSv1.0"` written per resource

### Module 4 — Secrets Manager Rotation

**Discovery IDs:**
- `aws.secretsmanager.list_secrets` — all secrets
- `aws.secretsmanager.describe_secret` — RotationEnabled, LastRotatedDate, RotationRules

**Findings:**

| Rule ID | Severity | Check |
|---------|---------|-------|
| `aws.secretsmanager.secret.rotation_enabled` | HIGH | `RotationEnabled=false` |
| `aws.secretsmanager.secret.rotation_within_90_days` | HIGH | `LastRotatedDate` older than 90 days |
| `aws.secretsmanager.secret.not_unused` | MEDIUM | Secret has `LastAccessedDate` null (never accessed — orphaned) |

---

## run_scan.py Changes

```python
# Current (Pattern B)
provider = get_provider(provider_name)
resources = disc_reader.load_all_encryption_resources(services=provider.all_services)

# New (Pattern A with B fallback)
provider = get_provider(provider_name)
findings = provider.analyze(scan_run_id, tenant_id, account_id)
if findings is None:
    # Pattern B fallback — non-upgraded CSPs
    resources = disc_reader.load_all_encryption_resources(services=provider.all_services)
    findings = _pattern_b_analyze(resources, scan_run_id, tenant_id, account_id)

save_encryption_findings(findings)
write_encryption_posture_signals(scan_run_id, tenant_id, account_id, provider_name)
```

## Acceptance Criteria

- [ ] AC-1: `BaseEncryptionProvider.analyze()` returns `None` by default (Pattern B fallback preserved for non-AWS CSPs)
- [ ] AC-2: `AWSEncryptionProvider.analyze()` returns non-None list (Pattern A active for AWS)
- [ ] AC-3: `aws.kms.key.rotation_enabled` fires for KMS keys with `KeyRotationEnabled=false`
- [ ] AC-4: `aws.acm.certificate.not_expiring_soon` fires for certs with < 30 days remaining
- [ ] AC-5: `cert_days_remaining` column in `resource_security_posture` is populated with actual integer values (not null) for AWS resources with ACM certs attached
- [ ] AC-6: `tls_version` column populated for ALB resources based on SSL policy
- [ ] AC-7: Non-AWS CSPs still work (Azure, GCP etc. use Pattern B fallback — verify no regression)
- [ ] AC-8: After AWS scan: `SELECT cert_days_remaining, tls_version FROM resource_security_posture WHERE provider='aws' AND cert_days_remaining IS NOT NULL LIMIT 5` shows real values

## MITRE ATT&CK
| Technique | Addressed by |
|-----------|-------------|
| T1552.004 | Unsecured Credentials: Private Keys — KMS imported material detection |
| T1485 | Data Destruction — key pending deletion detection |
| T1600 | Weaken Encryption — TLS 1.0/1.1 policy detection |

## Definition of Done
- [ ] `AWSEncryptionProvider.analyze()` fully implemented (KMS + ACM + ALB TLS + SecretsManager)
- [ ] `BaseEncryptionProvider.analyze()` returns `None` as default
- [ ] `run_scan.py` checks for `None` and falls back to Pattern B for non-upgraded CSPs
- [ ] Unit tests in `tests/unit/encryption/test_aws_encryption_provider.py`
- [ ] Encryption engine rebuilt and deployed
- [ ] `cert_days_remaining` and `tls_version` populated in `resource_security_posture` after AWS scan