# Compliance Data Quality Report — Thorough Review

**Date:** 2026-04-09

---

## 1. SOURCE DOCUMENTS STATUS

### Documents Available but NOT Parsed:
| Source | File | Size | Status |
|--------|------|------|--------|
| NIST 800-53 Rev 5 | `compliance_doc/nist/NIST.SP.800-53r5.html` | 11 MB | Raw pdftohtml, NOT parsed |
| PCI DSS v4.0.1 | `compliance_doc/pci/PCI-DSS-v4_0_1.html` | 3.3 MB | Raw pdftohtml, NOT parsed |
| CIS AWS (5 PDFs) | `compliance_doc/cis/Cloud_Providers/AWS/` | PDFs only | NO HTML, NO JSON |
| CIS Azure (12 files) | `compliance_doc/cis/Cloud_Providers/Azure/` | PDFs + HTMLs | JSON files ALL EMPTY |
| CIS GCP | `compliance_doc/cis/Cloud_Providers/GCP/` | PDFs + HTMLs | JSON files ALL EMPTY |
| CIS OCI | `compliance_doc/cis/Cloud_Providers/Oracle_Cloud/` | PDFs + HTMLs | JSON files ALL EMPTY |
| CIS IBM | `compliance_doc/cis/Cloud_Providers/IBM_Cloud/` | PDFs + HTMLs | JSON files ALL EMPTY |

### Only Successfully Parsed:
| Source | Controls | Quality |
|--------|----------|---------|
| CIS Alibaba v1 | 92 | Partial — title has TOC mixed in, most fields empty |
| CIS Alibaba v2 | 87 | Partial — same quality issues |

**Bottom line: 60 JSON output files exist but ALL are empty except 2 Alibaba files with poor quality.**

---

## 2. RULE_METADATA IN CHECK DB (What We Actually Have)

| CSP | Total Rules | Description | Remediation | Rationale | Severity |
|-----|-------------|-------------|-------------|-----------|----------|
| **AWS** | 1,918 | **1,918 (100%)** | **1,918 (100%)** | **1,918 (100%)** | **1,918 (100%)** |
| **Azure** | 1,691 | 1,581 (93%) | **0 (0%)** | 1,566 (93%) | 1,691 (100%) |
| **GCP** | 1,675 | 1,584 (95%) | **0 (0%)** | 1,576 (94%) | 1,675 (100%) |
| **OCI** | 1,977 | 1,914 (97%) | **0 (0%)** | 1,914 (97%) | 1,977 (100%) |
| **IBM** | 1,547 | 1,504 (97%) | **0 (0%)** | 1,504 (97%) | 1,547 (100%) |
| **AliCloud** | 1,306 | 1,306 (100%) | **0 (0%)** | 1,306 (100%) | 1,306 (100%) |

**Critical finding: ONLY AWS has remediation steps. All other CSPs have 0 remediation.**
- Azure, GCP, OCI, IBM, AliCloud have description + rationale but NO remediation
- All CSPs have severity (100%)

---

## 3. COMPLIANCE_CONTROLS IN DB (What UI Shows)

| Framework | Total | Name | Desc | Family | Severity | Audit | Remediation |
|-----------|-------|------|------|--------|----------|-------|-------------|
| cis_oci | 1,977 | 1,977 | 1,914 | 1,977 | 1,977 | **0** | 1,914 |
| cis_azure | 1,691 | 1,691 | 1,581 | 1,691 | 1,691 | **0** | 1,566 |
| cis_gcp | 1,675 | 1,675 | 1,584 | 1,675 | 1,675 | **0** | 1,576 |
| cis_ibm | 1,547 | 1,547 | 1,504 | 1,547 | 1,547 | **0** | 1,504 |
| cis_alicloud | 1,306 | 1,306 | 1,306 | 1,306 | 1,306 | **0** | 1,306 |
| nist_800_53 | 321 | 321 | 295 | 309 | 321 | **321** | 321 |
| cis_aws | 161 | 161 | 161 | 161 | 155 | **161** | 161 |
| fedramp | 140 | 140 | 117 | 139 | **0** | 117 | 117 |
| pci_dss_v4 | 94 | 94 | 94 | 83 | 94 | 92 | 94 |
| nist_800_171 | 50 | 50 | 47 | 50 | **0** | 47 | 47 |
| iso27001 | 44 | 44 | 43 | 42 | **0** | 43 | 43 |
| canada_pbmm | 39 | 39 | 33 | 39 | **0** | 33 | 33 |
| hipaa | 32 | 32 | 32 | 32 | **0** | 32 | 32 |
| soc2 | 25 | 25 | 25 | 10 | **0** | 25 | 25 |
| rbi_bank | 20 | 20 | 20 | 20 | **0** | 20 | 20 |
| rbi_nbfc | 16 | 16 | 16 | 14 | **0** | 16 | 16 |
| cisa_ce | 15 | 15 | 15 | 15 | **0** | 15 | 15 |
| gdpr | 3 | 3 | 3 | 3 | **0** | 3 | 3 |

**Note:** "Remediation" column = implementation_guidance (populated from rule_metadata.rationale).
This is NOT actual remediation steps — it's the rationale/description. Real remediation (how to fix) only exists for AWS rules.

---

## 4. CRITICAL DATA GAPS

### Gap 1: No Remediation for Non-AWS CSPs
- Azure, GCP, OCI, IBM, AliCloud rules have `remediation = NULL` in rule_metadata
- This means the Remediation tab shows rationale/description, NOT actual fix steps
- **Impact:** Users can't see how to fix issues for non-AWS cloud providers
- **Fix needed:** Either parse from CIS PDFs or generate remediation templates per rule pattern

### Gap 2: Section Names Are Generic
- CIS AWS: "1 Section", "2 Section" instead of "1. Identity and Access Management", "2. Storage"
- CSP frameworks: Have proper `control_family` from rule service mapping ("Compute", "Identity & Access Management")
- Multi-cloud frameworks (NIST, FedRAMP, HIPAA): Have family from original data but not proper section names
- **Fix needed:** Map control_family to proper CIS section names. For CIS AWS, the mapping is:
  - 1 → Identity and Access Management
  - 2 → Storage
  - 3 → Logging
  - 4 → Monitoring
  - 5 → Networking

### Gap 3: No Section Ordering
- Controls sort alphabetically ("1 Section", "10 Section", "11 Section", "2 Section")
- **Fix needed:** Add `sort_order` or parse numeric prefix for proper ordering

### Gap 4: No CLI/Console Split
- CIS AWS testing_procedures has both "From Console" and "From Command Line" sections mixed
- Only 27/161 have "From Console" marker, 23 have "From Command Line" marker
- **Fix needed:** Split into separate fields or parse at display time

### Gap 5: Missing Severity for 10 Frameworks
- FedRAMP (140), NIST 800-171 (50), ISO27001 (44), HIPAA (32), SOC2 (25), etc. all have severity=NULL
- **Fix needed:** Derive from mapped rule severity (take highest severity of linked rules)

### Gap 6: CIS Source Documents Not Parsed
- 91 HTML files and 95 PDFs exist but none are parsed into structured JSON
- Only 2 Alibaba JSONs have data, and that data is poor quality
- **Fix needed:** Build proper HTML parser for CIS benchmark format
- **Contains:** Section hierarchy, control IDs, titles, descriptions, rationale, audit (Console + CLI), remediation (Console + CLI), default values, references

---

## 5. ACTION PLAN (Priority Order)

### Phase 1: Fix What We Have (no parsing needed)
1. **Fix severity** — derive from rule_metadata severity for all frameworks
2. **Fix section ordering** — add numeric sort_order column
3. **Fix CIS AWS section names** — hardcode the 12 section names from CIS benchmark
4. **Split CLI/Console** in CIS AWS testing_procedures — regex-based at DB level
5. **Clarify remediation vs rationale** — rename `implementation_guidance` values that are actually rationale

### Phase 2: Parse Source Documents  
6. **Parse CIS HTML files** (91 files) — extract section hierarchy, control details, audit/remediation (Console + CLI)
7. **Parse NIST HTML** — extract 321+ controls with descriptions, guidance, assessment procedures
8. **Parse PCI HTML** — extract requirements, testing procedures, guidance

### Phase 3: Generate Missing Data
9. **Generate remediation for non-AWS CSPs** — template-based from AWS remediation patterns
10. **Expand rule-to-framework mapping** — currently 3.96% coverage, target 60%+

---

## 6. DATABASE SCHEMA CHANGES NEEDED

```sql
-- Add to compliance_controls
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS sort_order INT;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS section_id VARCHAR(50);
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS section_name VARCHAR(200);
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS subsection_id VARCHAR(50);
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS subsection_name VARCHAR(200);
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS audit_console TEXT;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS audit_cli TEXT;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS remediation_console TEXT;
ALTER TABLE compliance_controls ADD COLUMN IF NOT EXISTS remediation_cli TEXT;
```
