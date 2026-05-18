# Story PC-DEPTH-03: Encryption Engine — Azure / GCP / OCI Pattern A Upgrade

## Status: done

## Metadata
- **Phase**: Analysis Depth Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 4 (≈1.5 pts per CSP — smaller scope than AWS because cert fields are simpler)
- **Priority**: P2 — follows PC-GAP-05 (AWS Pattern A first)
- **Depends on**: PC-GAP-05 (Pattern A base class change done; `BaseEncryptionProvider.analyze()` returns `None` by default)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer

## Gap Being Closed

PC-GAP-05 upgrades AWS Encryption to Pattern A (KMS rotation + ACM cert expiry + ALB TLS version). After that story, Azure, GCP, and OCI still use Pattern B — their providers only return service lists.

**Posture columns that remain null for non-AWS after PC-GAP-05:**
- `cert_days_remaining` — certificate expiry countdown
- `has_valid_certificate` — cert not expired or near-expiry
- `tls_version` — minimum TLS enforced at LB/gateway level
- `has_kms_managed_key` — resource encrypted with managed vs default key

All three CSPs have the discovery data available (confirmed by catalog structure).

---

## Data Required Per CSP

### Azure

**Source: Discovery Engine (`discovery_findings`)**

| Discovery ID | Sub-feature | Field used |
|-------------|------------|-----------|
| `azure.keyvault.list_vaults` | Key Vault config | `properties.enableSoftDelete`, `properties.enablePurgeProtection` |
| `azure.key.list_keys` | Key rotation | `attributes.enabled`, `attributes.expires`, `keyOps` |
| `azure.certificateregistration.list_certificates` | App Service certs | `properties.expirationDate`, `properties.autoRenew` |
| `azure.keyvault.list_certificates` | Key Vault certs | `attributes.expires`, `attributes.enabled`, `x509Thumbprint` |
| `azure.network.list_application_gateways` | TLS version | `sslPolicy.minProtocolVersion` (TLSv1_0/TLSv1_1/TLSv1_2/TLSv1_3) |
| `azure.network.list_load_balancers` | TLS probe | `probes[].protocol` (HTTPS vs HTTP) |
| `azure.network.list_public_ip_addresses` | — | Cross-ref for internet-facing context |

**Analysis per feature:**

**Cert expiry** (`cert_days_remaining`):
```python
expires = vault_cert.get("attributes", {}).get("expires")  # Unix timestamp
days = (datetime.fromtimestamp(expires, tz=timezone.utc) - now).days
```

**Key Vault protection gaps:**
- `enableSoftDelete=false` → CRITICAL (key can be permanently deleted instantly)
- `enablePurgeProtection=false` → HIGH (soft-deleted key can be purged within retention window)
- Key with `attributes.expires` not set → MEDIUM (key never expires — rotation drift)

**TLS version** (from AppGW SSL policy):
```python
# azure.network.list_application_gateways → sslPolicy.minProtocolVersion
tls_map = {
    "TLSv1_0": "TLSv1.0",  # CRITICAL
    "TLSv1_1": "TLSv1.1",  # HIGH
    "TLSv1_2": "TLSv1.2",  # PASS
    "TLSv1_3": "TLSv1.3",  # PASS
}
```

**Findings generated:**

| Rule ID | Severity |
|---------|---------|
| `azure.keyvault.vault.soft_delete_enabled` | CRITICAL |
| `azure.keyvault.vault.purge_protection_enabled` | HIGH |
| `azure.keyvault.certificate.not_expiring_soon` | CRITICAL (< 30 days) / HIGH (< 60 days) |
| `azure.keyvault.certificate.auto_renew_enabled` | HIGH |
| `azure.network.application_gateway.tls_12_minimum` | HIGH (if TLSv1_0 or TLSv1_1) |

---

### GCP

**Source: Discovery Engine (`discovery_findings`)**

| Discovery ID | Sub-feature | Field used |
|-------------|------------|-----------|
| `gcp.cloudkms.list_key_rings` | KMS structure | `name`, `location` |
| `gcp.cloudkms.list_crypto_keys` | Key rotation | `rotationPeriod`, `nextRotationTime`, `versionTemplate.algorithm` |
| `gcp.certificatemanager.list_certificates` | Managed cert expiry | `expireTime`, `managed.state` (ACTIVE/FAILED) |
| `gcp.certificatemanager.list_certificate_maps` | Cert binding | Which LB/domain uses which cert |
| `gcp.compute.list_ssl_policies` | TLS version | `minTlsVersion` (TLS_1_0/TLS_1_1/TLS_1_2) |
| `gcp.compute.list_target_https_proxies` | TLS binding | `sslPolicy` field (absent = default permissive policy) |
| `gcp.compute.list_target_ssl_proxies` | TLS binding | `sslPolicy` |

**Analysis per feature:**

**KMS rotation** (`rotationPeriod`):
```python
rotation_period = key.get("rotationPeriod", "")  # e.g. "7776000s" = 90 days
# If rotationPeriod absent → rotation disabled → HIGH finding
# If rotation period > 365 days → MEDIUM finding
```

**Certificate expiry:**
```python
expire_time = cert.get("expireTime")  # RFC3339 timestamp
days = (parse_rfc3339(expire_time) - now).days
# < 30 days → CRITICAL, < 60 days → HIGH
```

**TLS version** (SSL policy):
```python
# gcp.compute.list_ssl_policies → minTlsVersion
# Target proxy with NO sslPolicy → uses GCP default = TLS_1_0 → CRITICAL
# minTlsVersion = TLS_1_0 → CRITICAL
# minTlsVersion = TLS_1_1 → HIGH
# minTlsVersion = TLS_1_2 → PASS
```

**Findings generated:**

| Rule ID | Severity |
|---------|---------|
| `gcp.cloudkms.crypto_key.rotation_period_configured` | HIGH |
| `gcp.cloudkms.crypto_key.rotation_period_90_days` | MEDIUM (rotation > 90 days) |
| `gcp.certificatemanager.certificate.not_expiring_soon` | CRITICAL/HIGH |
| `gcp.compute.ssl_policy.min_tls_12` | CRITICAL/HIGH |
| `gcp.compute.target_https_proxy.ssl_policy_attached` | HIGH (no policy = default permissive) |

---

### OCI

**Source: Discovery Engine (`discovery_findings`)**

| Discovery ID | Sub-feature | Field used |
|-------------|------------|-----------|
| `oci.kms.list_vaults` | Vault type | `vaultType` (DEFAULT vs VIRTUAL_PRIVATE) |
| `oci.key_management.list_keys` | Key rotation | `currentKeyVersion`, `timeCreated`, `keyShape.algorithm` |
| `oci.certificates_management.list_certificates` | Cert expiry | `currentVersionSummary.timeOfDeletion`, `currentVersionSummary.validity.timeOfValidityNotAfter` |
| `oci.certificates_management.list_ca_bundles` | CA config | `lifecycleState` |
| `oci.network.list_load_balancers` | TLS version | `listeners[].sslConfiguration.protocols` (TLSv1/TLSv1.1/TLSv1.2/TLSv1.3) |
| `oci.apigateway.list_gateways` | TLS | `endpointType` (PUBLIC vs PRIVATE), TLS version on deployment |

**Analysis per feature:**

**Vault type:**
```python
vault_type = vault.get("vaultType")
# DEFAULT = shared HSM partition → MEDIUM (production should use VIRTUAL_PRIVATE)
# VIRTUAL_PRIVATE = dedicated HSM → PASS
```

**Key rotation** (OCI doesn't have automatic rotation — manual rotation via key versions):
```python
# timeCreated of current key version
created = parse_rfc3339(key_version.get("timeCreated"))
days_since_rotation = (now - created).days
# > 365 days → HIGH (key not rotated in over a year)
# > 180 days → MEDIUM
```

**Certificate expiry:**
```python
expiry = cert.get("currentVersionSummary", {}).get("validity", {}).get("timeOfValidityNotAfter")
days = (parse_rfc3339(expiry) - now).days
```

**TLS from OCI LB:**
```python
protocols = lb_listener.get("sslConfiguration", {}).get("protocols", [])
# ["TLSv1"] or ["TLSv1.1"] → HIGH
# ["TLSv1.2", "TLSv1.3"] → PASS
```

**Findings generated:**

| Rule ID | Severity |
|---------|---------|
| `oci.kms.vault.virtual_private_hsm` | MEDIUM (DEFAULT vault used in prod) |
| `oci.key_management.key.rotation_within_365_days` | HIGH |
| `oci.certificates_management.certificate.not_expiring_soon` | CRITICAL/HIGH |
| `oci.network.load_balancer.tls_12_minimum` | HIGH |

---

## Implementation Pattern (same for all 3 CSPs)

Each provider's `analyze()` follows this structure (mirrors PC-GAP-05 AWS pattern):

```python
class AzureEncryptionProvider(BaseEncryptionProvider):

    def analyze(self, scan_run_id, tenant_id, account_id,
                discoveries_conn, check_conn) -> List[Dict]:
        findings = []
        now = datetime.now(timezone.utc)

        # Load discovery data scoped to tenant
        resources = self._load_discovery(
            discoveries_conn, scan_run_id, tenant_id, account_id,
            discovery_ids=[
                "azure.keyvault.list_vaults",
                "azure.keyvault.list_certificates",
                "azure.network.list_application_gateways",
                ...
            ]
        )

        findings.extend(self._analyze_key_vault(resources, scan_run_id, tenant_id, account_id, now))
        findings.extend(self._analyze_certificates(resources, scan_run_id, tenant_id, account_id, now))
        findings.extend(self._analyze_tls(resources, scan_run_id, tenant_id, account_id, now))
        return findings
```

---

## Posture Signals Written

After this story, `write_encryption_posture_signals()` will populate for Azure/GCP/OCI:
- `has_valid_certificate` — True if cert_days_remaining > 30
- `cert_days_remaining` — integer days until expiry
- `tls_version` — `"TLSv1.2"` / `"TLSv1.0"` / etc.
- `has_kms_managed_key` — True if BYOK/CMK configured (KV key, Cloud KMS key, OCI Vault key)

---

## CDR / Vulnerability Data — NOT needed

Key rotation and cert expiry are pure config-based analysis from discovery data. No behavioral data required.

---

## Acceptance Criteria

- [ ] AC-1: Azure `AzureEncryptionProvider.analyze()` returns non-None, populates `cert_days_remaining` for Key Vault certs
- [ ] AC-2: `azure.keyvault.vault.soft_delete_enabled` fires for Key Vaults with `enableSoftDelete=false`
- [ ] AC-3: `azure.network.application_gateway.tls_12_minimum` fires for AppGW with `minProtocolVersion=TLSv1_0`
- [ ] AC-4: GCP `gcp.compute.ssl_policy.min_tls_12` fires for Target HTTPS Proxies without an explicit SSL policy
- [ ] AC-5: GCP `gcp.cloudkms.crypto_key.rotation_period_configured` fires for keys with no `rotationPeriod` set
- [ ] AC-6: OCI `oci.certificates_management.certificate.not_expiring_soon` fires for certs with < 30 days remaining
- [ ] AC-7: `cert_days_remaining` column in `resource_security_posture` populated for Azure/GCP/OCI resources after scan (currently always null)
- [ ] AC-8: All discovery queries include `AND tenant_id = %s`

## Definition of Done
- [ ] `providers/azure.py`, `providers/gcp.py`, `providers/oci.py` all have `analyze()` implemented
- [ ] Unit tests per CSP in `tests/unit/encryption/`
- [ ] Encryption engine rebuilt and deployed
- [ ] After scan: `SELECT provider, COUNT(*) FROM encryption_findings WHERE provider IN ('azure','gcp','oci') GROUP BY provider` shows non-zero rows from analyze() path (not just Pattern B check_findings)
