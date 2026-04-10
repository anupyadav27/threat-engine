# Compliance Module — Complete Improvement List

## Status: PLANNING (do not start coding until approved)

---

## A. DATA QUALITY FIXES

### A1. Section Hierarchy & Naming
- **Current**: `control_family` = "1 Section", "2 Section" etc. — no real names
- **Needed**: Proper section names from source docs (e.g., "1. Identity and Access Management", "2. Storage", "3. Logging")
- **Subsections**: Some frameworks have 3-level hierarchy (Section → Requirement → Sub-requirement)
  - PCI DSS: Section 3 → 3.1 → 3.1.1
  - CIS: Section 1 → 1.1 → 1.1.1
  - NIST: Family AC → AC-2 → AC-2(1)
- **Schema change**: Add `section_id`, `section_name`, `subsection_id`, `subsection_name` columns to `compliance_controls` OR create `compliance_sections` table
- **Source**: Parse from CIS PDFs, NIST HTML (`/Users/apple/Desktop/compliance_doc/nist/NIST.SP.800-53r5.html`), PCI HTML (`/Users/apple/Desktop/compliance_doc/pci/PCI-DSS-v4_0_1.html`)

### A2. Section Ordering
- **Current**: Alphabetical sort ("1 Section", "10 Section", "11 Section", "2 Section")
- **Needed**: Numeric ascending (1, 2, 3... 10, 11, 12)
- **Fix**: Add `sort_order` INT column to controls, or use `control_number` field properly

### A3. CLI vs Console Remediation Split
- **Current**: Mixed in one `testing_procedures` text blob
- **Needed**: Separate fields or structured data:
  - `audit_console` — console/UI-based audit steps
  - `audit_cli` — CLI command-based audit steps  
  - `remediation_console` — console/UI-based remediation steps
  - `remediation_cli` — CLI command-based remediation steps
- **Source**: CIS benchmarks have explicit "From Console:" and "From Command Line:" markers
- **Stats**: 27 CIS AWS controls have "From Console", 23 have "From Command Line", 62 have `aws` CLI commands

### A4. Populate Missing Audit Procedures
- **Current**: 0 audit procedures for CSP-specific CIS frameworks (7,196 controls total)
- **Needed**: Populate from `rule_metadata.description` or generate from rule check logic
- **Frameworks affected**: cis_oci (1977), cis_azure (1691), cis_gcp (1675), cis_ibm (1547), cis_alicloud (1306)

### A5. Populate Missing Severity
- **Current**: 0 severity for FedRAMP (140), NIST 800-171 (50), ISO27001 (44), HIPAA (32), SOC2 (25), etc.
- **Needed**: Derive from mapped rule severity or set framework-default severity

### A6. Populate Missing Descriptions
- **Current**: ~200 controls missing descriptions across frameworks
- **Needed**: Fill from rule_metadata.description via rule_control_mapping

### A7. Framework Version & Authority
- **Current**: Most frameworks missing version/authority/category metadata
- **Needed**: Add proper versions (CIS AWS v3.0, NIST 800-53 Rev 5, PCI DSS v4.0.1, etc.)

---

## B. TABLE / GRID FEATURES

### B1. Framework List Table Columns
Current: Framework | Provider | Score | Controls | Findings
**Add**:
- **Account** — filter by cloud account (shows which accounts are scanned for this framework)
- **CSP** — already have Provider, keep it
- **Tenant** — filter by tenant
- **Tags** — resource tags filter
- **Findings** — count of failing findings (link to findings page)
- **Last Assessed** — when the last assessment ran

### B2. Controls Table Columns (inside framework detail)
Current: Status | ID | Control | Severity | Findings
**Add**:
- **Account** — which account(s) this control applies to
- **Findings** — clickable count → navigates to filtered findings view
- **Resources** — pass/fail resource count → navigates to inventory filtered by this control
- **Section** — proper section name (not just family)

### B3. Filtering & Grouping
- **Filter by**: Framework, Provider/CSP, Account, Severity, Status (Pass/Fail/Partial/N-A), Tags
- **Group by**: Framework, Section, Severity, Provider, Account
- **Search**: Full-text search across control name, description, control_id
- **Sort**: All columns sortable, numeric sort for section/control numbers

### B4. Export
- **CSV**: Download checklist as CSV
- **PDF**: Formal compliance report (audit-ready)
- **JSON**: API export for integration

---

## C. NAVIGATION & CROSS-LINKING

### C1. Findings → Findings Page
- Clicking finding count in controls table → navigate to `/threats` or `/misconfig` filtered by framework + control_id
- Or open findings in a filtered view within compliance

### C2. Resources → Inventory
- Clicking resource ARN in findings panel → navigate to `/inventory/{assetId}`
- Clicking resource count in controls table → navigate to `/inventory?filter=control:{control_id}`

### C3. Control Detail → Related Pages
- Link to rule management (`/rules?rule_id=xxx`)
- Link to affected resources in inventory
- Link to threat findings for same resources

### C4. Framework Breadcrumb
- Compliance → Framework → Section → Control (clickable breadcrumb)

---

## D. SLIDE-OUT PANEL IMPROVEMENTS

### D1. Tab Structure (Orca-style)
- **Info**: Description, rationale, control metadata, compliance frameworks cross-mapping
- **Findings**: Resource-level findings with evidence (current)
- **Audit**: Testing procedures split into Console / CLI with proper formatting
- **Remediation**: Fix steps split into Console / CLI / Terraform / Pulumi / CloudFormation / ARM
  - Console steps with numbered instructions
  - CLI steps in code block with copy button
  - Other IaC modes as placeholder → future AI generation

### D2. Audit Tab Sections
```
AUDIT TAB
├── From Console (numbered steps with screenshots/links)
├── From Command Line (code blocks with aws/az/gcloud commands)
└── Expected Result (what passing looks like)
```

### D3. Remediation Tab Sections
```
REMEDIATION TAB
├── Mode selector: [CLI] [Console] [Terraform] [Pulumi] [CloudFormation] [ARM]
├── Selected mode content:
│   ├── CLI → code block with actual commands (copy button)
│   ├── Console → numbered steps (1. Open console... 2. Navigate to...)
│   └── Others → placeholder for future
└── References (links to AWS docs, CIS docs, etc.)
```

---

## E. ASSESSMENT & SCORING

### E1. Score Computation
- **Current**: Only counts PASS/FAIL from compliance_findings (FAIL-only storage)
- **Needed**: Score = (passed_controls / total_applicable_controls) * 100
- **By Control**: What % of controls pass
- **By Asset**: What % of assets are fully compliant

### E2. Trend Tracking
- Store assessment scores per scan_run_id
- Show score trend over time (7D/14D/1M like Orca)

### E3. Account-Level Scores
- Per-account compliance score per framework
- Account compliance matrix (rows=accounts, cols=frameworks)

---

## F. REPORT GENERATION

### F1. CIS Checklist Report (PDF)
- Cover page with framework name, version, date, scope
- Per-section summary with pass/fail counts
- Per-control row: ID | Title | Status | Evidence | Remediation
- Appendix: Full resource evidence

### F2. Audit Report (SOC2/PCI/HIPAA)
- Executive summary
- Scope & methodology
- Per-control assessment with evidence
- Exception register
- Remediation tracking

### F3. Regulatory Posture Report (NIST/FedRAMP)
- System Security Plan (SSP) format
- Per-control-family implementation status
- Control inheritance mapping (CSP vs customer responsibility)

---

## PRIORITY ORDER

1. **A1 + A2**: Fix section names + ordering (foundation for everything else)
2. **A3**: Split CLI/Console remediation data
3. **B3**: Add filtering and grouping to tables
4. **B1 + B2**: Add missing columns (Account, Findings links, Resources)
5. **C1 + C2**: Cross-linking to findings and inventory pages
6. **D1-D3**: Panel improvements (Audit/Remediation tab split with CLI/Console)
7. **A4-A7**: Fill remaining data gaps
8. **E1-E3**: Assessment and scoring improvements
9. **F1-F3**: Report generation

---

## REFERENCE: Source Documents Available
- CIS AWS PDFs: `/Users/apple/Desktop/compliance_doc/cis/Cloud_Providers/AWS/` (5 PDFs)
- CIS Azure: `/Users/apple/Desktop/compliance_doc/cis/Cloud_Providers/Azure/` (12 PDFs + JSONs)
- CIS GCP: `/Users/apple/Desktop/compliance_doc/cis/Cloud_Providers/GCP/`
- CIS OCI: `/Users/apple/Desktop/compliance_doc/cis/Cloud_Providers/Oracle_Cloud/`
- CIS IBM: `/Users/apple/Desktop/compliance_doc/cis/Cloud_Providers/IBM_Cloud/` (2 PDFs + JSONs)
- CIS Alibaba: `/Users/apple/Desktop/compliance_doc/cis/Cloud_Providers/Alibaba_Cloud/` (JSONs parsed)
- NIST 800-53: `/Users/apple/Desktop/compliance_doc/nist/NIST.SP.800-53r5.html`
- PCI DSS v4: `/Users/apple/Desktop/compliance_doc/pci/PCI-DSS-v4_0_1.html`

## REFERENCE: Current DB Stats
- 18 frameworks (23 in compliance_frameworks, 18 with controls)
- 9,156 controls total
- 11,608 rule-control mappings
- 27,722 compliance findings
- 562 controls with testing_procedures
- 569 controls with implementation_guidance
- 8,196 CSP controls with descriptions but no audit/remediation detail
