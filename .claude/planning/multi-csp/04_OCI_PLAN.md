# OCI (Oracle Cloud Infrastructure) — Detailed Project Plan

## Context

- **Credentials:** ❌ Not available on this laptop — need to provision
- **Discovery configs in DB:** 156 (`rule_discoveries WHERE provider='oci'`)
- **Check rules in DB:** 1,914 (highest of all non-AWS CSPs)
- **Scanner current state:** Stub (400 lines, no DB catalog integration)
- **Catalog YAMLs:** 317 services

## Pre-Requisite: Credential Setup

Before any development work starts:
1. Create OCI free tier account (oracle.com/cloud/free — $300 credit)
2. Generate API key pair (`~/.oci/config`)
3. Note: Tenancy OCID, User OCID, Fingerprint, Region
4. Store in K8s secret: `oci-creds` with keys: `tenancy_ocid`, `user_ocid`,
   `fingerprint`, `private_key`, `region`

## Milestone 1: OCI Scanner Foundation

**Estimated effort:** 4-5 days (1 Python + OCI SDK engineer)

### User Stories

**US-OCI-01: OCI Client Factory**
- **OCI SDK uses a different pattern** — one `oci.config` dict used across all service clients
- **Tasks:**
  - T1: Map `rule_discoveries.service` to OCI client classes:
    - `identity` → `oci.identity.IdentityClient`
    - `compute` → `oci.core.ComputeClient`
    - `network` → `oci.core.VirtualNetworkClient`
    - `objectstorage` → `oci.object_storage.ObjectStorageClient`
    - `database` → `oci.database.DatabaseClient`
    - `audit` → `oci.audit.AuditClient`
    - (all mapped from 156 discovery configs)
  - T2: Implement `OCIClientFactory.get_client(service, config_dict)`
  - T3: Handle OCI compartment hierarchy (OCI uses compartments, not accounts)
  - T4: Handle OCI credential types: config file, instance principals, resource principals

**US-OCI-02: OCI Compartment Traversal**
- OCI organises resources in a **compartment tree** (≈ AWS account hierarchy)
- The scanner must recursively enumerate sub-compartments
- **Tasks:**
  - T1: `IdentityClient.list_compartments(compartment_id, compartment_id_in_subtree=True)`
  - T2: Treat each compartment as equivalent to an AWS account (separate resource namespace)
  - T3: Treat OCI regions as equivalent to AWS regions

**US-OCI-03: OCI Pagination**
- OCI uses `page` + `opc-next-page` header tokens
- **Tasks:**
  - T1: Implement `oci_paginate(client_method, **kwargs)` wrapper
  - T2: Respect `limit` param (OCI max is typically 1000)
  - T3: 10s timeout wrapper using `ThreadPoolExecutor`

## Milestone 2: Noise Removal

**Remove from 156 OCI discovery configs:**
- Audit log events
- Monitoring metrics
- Usage reports
- Announcements
- Work request logs

**Keep (security-relevant):**
- IAM users, groups, policies
- Compute instances (public IP, boot volume encryption)
- VCN, subnets, Security Lists, Network Security Groups
- Block volumes (encryption)
- Object Storage buckets (public access, versioning)
- Database systems (encryption, network access)
- KMS vaults and keys
- Certificates
- WAF policies
- Bastion sessions

## OCI Technical Notes

- **Compartments are the resource boundary** — treat as accounts
- **OCIDs** are the resource identifier format (not ARNs)
- **OCI SDK Python:** `oci` package — different from AWS/Azure/GCP
- **Auth:** RSA key pair + tenancy OCID (stored in `~/.oci/config`)
- **Rate limits:** OCI has service-level throttling (varies by service)
