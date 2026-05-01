# Decommission: Test Cloud Resources (Azure / OCI / AliCloud)

> Created: 2026-05-01  
> Purpose: Document test resources created for CSPM engine validation that may still be incurring cost.

---

## 1. Azure

**Account ID / Subscription:** `f6d24b5d-51ed-47b7-9f6a-0ad194156b5e`  
**Credential ref:** `threat-engine/account/f6d24b5d-51ed-47b7-9f6a-0ad194156b5e`  
**Credential type:** `azure_service_principal`  
**Region:** `eastus`

### Discovered Resources

| Resource Type | Count | Billing Impact |
|---|---|---|
| VirtualMachine | 1 | **HIGH — stop/delete immediately** |
| ManagedDisk | 1 | **MEDIUM — delete or snapshot** |
| PublicIPAddress | 1 | Low (idle IPs still billed) |
| StorageAccount | 5 | Low (depends on stored data) |
| KeyVault | 7 | Low (soft-delete holds 90 days) |
| ResourceGroup | 7 | Free |
| NetworkSecurityGroup | 5 | Free |
| VirtualNetwork | 5 | Free |
| RoleAssignment | 4 | Free |
| AADTenant | 2 | Free |

### Decommission Checklist

- [ ] Stop (or delete) the VirtualMachine in `eastus`
- [ ] Delete or snapshot the ManagedDisk
- [ ] Release the PublicIPAddress
- [ ] Delete test StorageAccounts (or at least drain blobs)
- [ ] Purge KeyVaults (soft-delete; purge-protection may require 90-day wait)
- [ ] Delete ResourceGroups (cascades to all child resources)
- [ ] Remove the Service Principal from Azure AD if no longer needed
- [ ] Remove the secret from AWS Secrets Manager at `threat-engine/account/f6d24b5d-51ed-47b7-9f6a-0ad194156b5e`
- [ ] Set account to `account_status=inactive` in `cloud_accounts` table (onboarding DB)

---

## 2. OCI

**Account ID / Tenancy OCID:** `ocid1.tenancy.oc1..aaaaaaaaicrnz3tu46szyr7ynaaelvezq3mvlujvabvnwybsj3tuvrppk2oa`  
**Credential ref:** `threat-engine/account/ocid1.tenancy.oc1..aaaaaaaaicrnz3tu46szyr7ynaaelvezq3mvlujvabvnwybsj3tuvrppk2oa`  
**Credential type:** `api_key`  
**Region:** `ap-mumbai-1`

### Discovered Resources

| Resource Type | Count | Billing Impact |
|---|---|---|
| oci.core/Instance | 1 | **HIGH — stop/terminate immediately** |
| oci.key_management/Vault | 2 | Medium (virtual vault = low; HSM vault = ~$1/hr) |
| oci.objectstorage/Bucket | 3 | Low (depends on stored data) |
| oci.core/Vcn | 4 | Free |
| oci.core/Subnet | 1 | Free |
| oci.core/RouteTable | 4 | Free |
| oci.core/SecurityList | 8 | Free |
| oci.audit/Event | 275 | Free (audit events, not resources) |
| oci.audit/Configuration | 2 | Free |
| oci.dns/ZoneTransferServer | 6 | Free |
| oci.functions/PbfListing | 10 | Free (platform listings) |
| oci.data_safe/Configuration | 1 | Free if not actively scanning |

### Decommission Checklist

- [ ] Terminate (or stop) the OCI Compute Instance in `ap-mumbai-1`
- [ ] Check KMS Vault type — if HSM, schedule deletion immediately (30-day hold)
- [ ] Delete Object Storage buckets (empty first)
- [ ] Delete VCNs and subnets after instances are gone
- [ ] Revoke the API key / delete the OCI IAM user used for scanning
- [ ] Remove the secret from AWS Secrets Manager at the credential ref above
- [ ] Set account to `account_status=inactive` in onboarding DB

---

## 3. AliCloud

**Account ID:** `5181776522508288`  
**Credential ref:** `threat-engine/account/5181776522508288`  
**Credential type:** `access_key`  
**Primary region:** `cn-hangzhou` (with ap-southeast-1 also used)

### Discovered Resources

| Resource Type | Count | Billing Impact |
|---|---|---|
| alicloud.vpc/Vpc | 4 (cn-hangzhou) + 1 (ap-southeast-1) | Free |
| alicloud.vpc/RouteTable | 2 | Free |
| alicloud.ecs/SecurityGroup | 2 (cn-hangzhou) + 1 (ap-southeast-1) | Free |
| alicloud.kms/Key | 3 (cn-hangzhou) | Low (~$0.002/key/month) |
| alicloud.ram/Role | 7 × 33 regions (repeated) | Free (global, not per-region) |
| alicloud.ram/User | 4 × 33 regions (repeated) | Free (global, not per-region) |
| alicloud.actiontrail/Trail | 1 | Low (trail free; log storage is billed) |

> Note: RAM Roles/Users appear across all regions in scan output — this is the CSPM engine enumerating globally-scoped resources in each region loop. The actual count is 7 roles + 4 users.

### Decommission Checklist

- [ ] No compute instances found — **lowest risk of the three**
- [ ] Disable or schedule deletion of KMS Keys (7-day deletion window)
- [ ] Delete Object Storage buckets backing ActionTrail if no longer needed
- [ ] Disable ActionTrail to stop log write charges
- [ ] Delete test RAM users/roles created for CSPM scanner
- [ ] Disable/delete the Access Key used for scanning
- [ ] Remove the secret from AWS Secrets Manager at `threat-engine/account/5181776522508288`
- [ ] Set account to `account_status=inactive` in onboarding DB

---

## 4. Mark Accounts Inactive in CSPM (SQL)

After decommissioning the cloud-side resources, mark the accounts offline so scans don't re-run:

```sql
-- Connect to: threat_engine_onboarding (onboarding DB)
UPDATE cloud_accounts
SET account_status = 'inactive', account_onboarding_status = 'decommissioned', updated_at = now()
WHERE account_id IN (
    'f6d24b5d-51ed-47b7-9f6a-0ad194156b5e',   -- Azure
    'ocid1.tenancy.oc1..aaaaaaaaicrnz3tu46szyr7ynaaelvezq3mvlujvabvnwybsj3tuvrppk2oa',  -- OCI
    '5181776522508288'                           -- AliCloud
);
```

---

## 5. Summary: Priority Order

| Priority | Action |
|---|---|
| **Immediate** | Stop/terminate Azure VM + OCI Compute Instance |
| **This week** | Delete Azure ManagedDisk, OCI Vault (if HSM), release Public IP |
| **Low urgency** | Clean up IAM keys, storage, KMS keys across all three |
| **After cleanup** | Mark accounts inactive in CSPM onboarding DB |
