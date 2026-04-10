const pptxgen = require("pptxgenjs");
const pres = new pptxgen();

pres.layout = "LAYOUT_16x9";
pres.author = "Threat Engine Team";
pres.title = "Compliance Module - Data Quality & Feature Completion";

// ── Theme ──
const T = {
  navy: "1E2761", navyDark: "141B3D", ice: "CADCFC", white: "FFFFFF",
  accent: "3B82F6", green: "22C55E", red: "EF4444", amber: "F59E0B",
  gray: "94A3B8", grayDark: "64748B", grayLight: "F1F5F9",
  bg: "0F172A", bgCard: "1E293B", text: "E2E8F0", muted: "94A3B8",
};

function darkSlide() {
  const s = pres.addSlide();
  s.background = { color: T.bg };
  return s;
}
function lightSlide() {
  const s = pres.addSlide();
  s.background = { color: T.white };
  return s;
}
function sectionBar(s, title) {
  s.addShape(pres.shapes.RECTANGLE, { x: 0, y: 0, w: 10, h: 0.7, fill: { color: T.navy } });
  s.addText(title, { x: 0.5, y: 0.1, w: 9, h: 0.5, fontSize: 14, color: T.ice, bold: true, fontFace: "Calibri" });
}

// ═══════════════════════════════════════════════════════
// SLIDE 1: Title
// ═══════════════════════════════════════════════════════
let s1 = darkSlide();
s1.addShape(pres.shapes.RECTANGLE, { x: 0, y: 0, w: 10, h: 5.625, fill: { color: T.navyDark } });
s1.addShape(pres.shapes.RECTANGLE, { x: 0, y: 3.8, w: 10, h: 1.825, fill: { color: T.navy } });
s1.addText("COMPLIANCE MODULE", { x: 0.8, y: 1.0, w: 8.4, h: 0.8, fontSize: 42, color: T.white, bold: true, fontFace: "Calibri" });
s1.addText("Data Quality & Feature Completion", { x: 0.8, y: 1.8, w: 8.4, h: 0.6, fontSize: 24, color: T.ice, fontFace: "Calibri" });
s1.addText("Project Plan — 5 Milestones / 10 Weeks", { x: 0.8, y: 2.5, w: 8.4, h: 0.5, fontSize: 16, color: T.muted, fontFace: "Calibri" });
s1.addText("Threat Engine CSPM Platform", { x: 0.8, y: 4.2, w: 4, h: 0.4, fontSize: 14, color: T.ice, fontFace: "Calibri" });
s1.addText("April 2026", { x: 6, y: 4.2, w: 3.2, h: 0.4, fontSize: 14, color: T.muted, align: "right", fontFace: "Calibri" });

// ═══════════════════════════════════════════════════════
// SLIDE 2: Executive Summary
// ═══════════════════════════════════════════════════════
let s2 = darkSlide();
sectionBar(s2, "EXECUTIVE SUMMARY");
s2.addText("What We're Building", { x: 0.5, y: 1.0, w: 9, h: 0.5, fontSize: 22, color: T.white, bold: true, fontFace: "Calibri", margin: 0 });
s2.addText("Multi-cloud compliance module supporting 18+ frameworks across 6 CSPs (AWS, Azure, GCP, OCI, IBM, AliCloud) with full audit, remediation, and reporting capabilities.", { x: 0.5, y: 1.5, w: 9, h: 0.7, fontSize: 13, color: T.muted, fontFace: "Calibri" });

// KPI boxes
const kpis = [
  { label: "Frameworks", value: "23", sub: "18 active" },
  { label: "Controls", value: "9,156", sub: "in database" },
  { label: "CSPs", value: "6", sub: "multi-cloud" },
  { label: "Rules", value: "11,211", sub: "check rules" },
];
kpis.forEach((k, i) => {
  const x = 0.5 + i * 2.3;
  s2.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 2.4, w: 2.1, h: 1.2, fill: { color: T.bgCard }, rectRadius: 0.1 });
  s2.addText(k.value, { x, y: 2.5, w: 2.1, h: 0.6, fontSize: 28, color: T.accent, bold: true, align: "center", fontFace: "Calibri" });
  s2.addText(k.label, { x, y: 3.0, w: 2.1, h: 0.3, fontSize: 11, color: T.white, align: "center", fontFace: "Calibri" });
  s2.addText(k.sub, { x, y: 3.25, w: 2.1, h: 0.25, fontSize: 9, color: T.muted, align: "center", fontFace: "Calibri" });
});

s2.addText("Key Challenge", { x: 0.5, y: 3.9, w: 9, h: 0.4, fontSize: 16, color: T.amber, bold: true, fontFace: "Calibri", margin: 0 });
s2.addText([
  { text: "Only AWS has full compliance data (100% remediation). ", options: { bold: true, color: T.white } },
  { text: "Azure, GCP, OCI, IBM, AliCloud have 0% remediation. 91 CIS HTML documents exist but are not parsed. Section hierarchy, CLI/Console split, and severity data are missing for most frameworks.", options: { color: T.muted } },
], { x: 0.5, y: 4.3, w: 9, h: 0.8, fontSize: 12, fontFace: "Calibri" });

// ═══════════════════════════════════════════════════════
// SLIDE 3: Gap Analysis
// ═══════════════════════════════════════════════════════
let s3 = lightSlide();
sectionBar(s3, "CURRENT STATE — GAP ANALYSIS");
s3.addText("Rule Metadata Coverage by CSP", { x: 0.5, y: 0.9, w: 9, h: 0.4, fontSize: 18, color: T.navyDark, bold: true, fontFace: "Calibri", margin: 0 });

const gapData = [
  ["CSP", "Rules", "Description", "Remediation", "Rationale", "Severity"],
  ["AWS", "1,918", "100%", "100%", "100%", "100%"],
  ["Azure", "1,691", "93%", "0%", "93%", "100%"],
  ["GCP", "1,675", "95%", "0%", "94%", "100%"],
  ["OCI", "1,977", "97%", "0%", "97%", "100%"],
  ["IBM", "1,547", "97%", "0%", "97%", "100%"],
  ["AliCloud", "1,306", "100%", "0%", "100%", "100%"],
];
const gapRows = gapData.map((row, ri) => row.map((cell, ci) => ({
  text: cell,
  options: {
    fontSize: ri === 0 ? 10 : 11,
    bold: ri === 0,
    color: ri === 0 ? T.white : (ci === 3 && ri > 1 ? T.red : T.navyDark),
    fill: { color: ri === 0 ? T.navy : (ri % 2 === 0 ? T.grayLight : T.white) },
    align: ci === 0 ? "left" : "center",
    fontFace: "Calibri",
  }
})));
s3.addTable(gapRows, { x: 0.5, y: 1.4, w: 9, colW: [1.2, 1, 1.5, 1.5, 1.3, 1.2], border: { pt: 0.5, color: "CBD5E1" } });

s3.addText("Critical Finding: Only AWS has remediation steps. 5 CSPs have ZERO remediation.", { x: 0.5, y: 3.6, w: 9, h: 0.4, fontSize: 12, color: T.red, bold: true, fontFace: "Calibri", margin: 0 });

// Additional gaps
s3.addText("Additional Data Gaps", { x: 0.5, y: 4.1, w: 9, h: 0.3, fontSize: 14, color: T.navyDark, bold: true, fontFace: "Calibri", margin: 0 });
s3.addText([
  { text: "Section naming: ", options: { bold: true, breakLine: false } },
  { text: "'1 Section' instead of '1. Identity and Access Management'", options: { breakLine: true } },
  { text: "No hierarchy: ", options: { bold: true, breakLine: false } },
  { text: "Flat structure, no Section → Subsection → Control tree", options: { breakLine: true } },
  { text: "No CLI/Console split: ", options: { bold: true, breakLine: false } },
  { text: "Audit and remediation steps mixed in one text blob", options: { breakLine: true } },
  { text: "Missing severity: ", options: { bold: true, breakLine: false } },
  { text: "10 frameworks have NULL severity for all controls", options: { breakLine: true } },
  { text: "60 empty JSONs: ", options: { bold: true, breakLine: false } },
  { text: "CIS benchmark parsing failed — all output files are empty []", options: {} },
], { x: 0.5, y: 4.4, w: 9, h: 1.1, fontSize: 10, color: T.grayDark, fontFace: "Calibri" });

// ═══════════════════════════════════════════════════════
// SLIDE 4: Milestone 1
// ═══════════════════════════════════════════════════════
let s4 = darkSlide();
sectionBar(s4, "MILESTONE 1: DATA FOUNDATION — Week 1-2");
s4.addText("Fix what we have — no external parsing needed", { x: 0.5, y: 0.9, w: 9, h: 0.4, fontSize: 16, color: T.ice, italic: true, fontFace: "Calibri", margin: 0 });

const ms1 = [
  { us: "US-1.1", title: "Section Names & Hierarchy", tasks: "Map CIS 12 sections to real names\nAdd sort_order column\nPopulate section_id/name for all frameworks", agent: "Security BA", color: T.accent },
  { us: "US-1.2", title: "Severity for All Controls", tasks: "Derive from rule severity\nSet defaults for unmapped controls", agent: "Security SME", color: T.green },
  { us: "US-1.3", title: "CLI / Console Split", tasks: "Add audit_cli, audit_console columns\nParse CIS AWS 'From Console/CLI' markers\nPopulate from rule_metadata", agent: "CSP SME (AWS)", color: T.amber },
  { us: "US-1.4", title: "DB Schema Enhancement", tasks: "Add section hierarchy columns\nAdd remediation_cli/console columns\nAdd references_urls JSONB", agent: "Dev Lead", color: T.muted },
];
ms1.forEach((m, i) => {
  const y = 1.4 + i * 1.0;
  s4.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.5, y, w: 9, h: 0.85, fill: { color: T.bgCard }, rectRadius: 0.08 });
  s4.addShape(pres.shapes.RECTANGLE, { x: 0.5, y, w: 0.06, h: 0.85, fill: { color: m.color } });
  s4.addText(m.us, { x: 0.7, y: y + 0.05, w: 0.8, h: 0.3, fontSize: 10, color: m.color, bold: true, fontFace: "Calibri" });
  s4.addText(m.title, { x: 1.5, y: y + 0.05, w: 3, h: 0.3, fontSize: 13, color: T.white, bold: true, fontFace: "Calibri" });
  s4.addText(m.tasks, { x: 1.5, y: y + 0.35, w: 5, h: 0.45, fontSize: 9, color: T.muted, fontFace: "Calibri" });
  s4.addText(m.agent, { x: 7.5, y: y + 0.15, w: 1.8, h: 0.3, fontSize: 10, color: T.ice, align: "right", fontFace: "Calibri" });
});

// ═══════════════════════════════════════════════════════
// SLIDE 5: Milestone 2
// ═══════════════════════════════════════════════════════
let s5 = darkSlide();
sectionBar(s5, "MILESTONE 2: DOCUMENT PARSING — Week 3-5");
s5.addText("Extract structured data from CIS, NIST, PCI source documents", { x: 0.5, y: 0.9, w: 9, h: 0.4, fontSize: 16, color: T.ice, italic: true, fontFace: "Calibri", margin: 0 });

const ms2 = [
  { us: "US-2.1", title: "CIS Benchmark Parser (91 HTML files)", tasks: "Build Python parser for CIS HTML format\nExtract: hierarchy, audit (Console+CLI), remediation (Console+CLI)\nValidate against 3 sample PDFs", agent: "CSP SME + Security BA", docs: "91 HTMLs, 95 PDFs", color: T.accent },
  { us: "US-2.2", title: "NIST 800-53 Rev 5 Parser", tasks: "Parse 11MB HTML document\nExtract 321+ controls: family, description, assessment procedures\nMap to existing control_ids", agent: "Security SME (NIST)", docs: "1 HTML (11MB)", color: T.green },
  { us: "US-2.3", title: "PCI DSS v4.0.1 Parser", tasks: "Parse 3.3MB HTML document\nExtract 94+ requirements with testing procedures\nMap section hierarchy (12 requirements)", agent: "Security SME (PCI)", docs: "1 HTML (3.3MB)", color: T.amber },
];
ms2.forEach((m, i) => {
  const y = 1.4 + i * 1.3;
  s5.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.5, y, w: 9, h: 1.15, fill: { color: T.bgCard }, rectRadius: 0.08 });
  s5.addShape(pres.shapes.RECTANGLE, { x: 0.5, y, w: 0.06, h: 1.15, fill: { color: m.color } });
  s5.addText(m.us, { x: 0.7, y: y + 0.05, w: 0.8, h: 0.3, fontSize: 10, color: m.color, bold: true, fontFace: "Calibri" });
  s5.addText(m.title, { x: 1.5, y: y + 0.05, w: 5, h: 0.3, fontSize: 13, color: T.white, bold: true, fontFace: "Calibri" });
  s5.addText(m.tasks, { x: 1.5, y: y + 0.38, w: 5, h: 0.65, fontSize: 9, color: T.muted, fontFace: "Calibri" });
  s5.addText(m.agent, { x: 7, y: y + 0.05, w: 2.3, h: 0.25, fontSize: 10, color: T.ice, align: "right", fontFace: "Calibri" });
  s5.addText("Source: " + m.docs, { x: 7, y: y + 0.3, w: 2.3, h: 0.25, fontSize: 9, color: T.muted, align: "right", fontFace: "Calibri" });
});

// ═══════════════════════════════════════════════════════
// SLIDE 6: Milestone 3
// ═══════════════════════════════════════════════════════
let s6 = darkSlide();
sectionBar(s6, "MILESTONE 3: DATA ENRICHMENT — Week 5-6");
s6.addText("Fill gaps, generate missing data, expand mappings", { x: 0.5, y: 0.9, w: 9, h: 0.4, fontSize: 16, color: T.ice, italic: true, fontFace: "Calibri", margin: 0 });

const ms3 = [
  { us: "US-3.1", title: "Non-AWS CSP Remediation", tasks: "Generate Azure remediation (az CLI patterns)\nGenerate GCP remediation (gcloud patterns)\nGenerate OCI/IBM/AliCloud templates\nValidate per CSP SME", agent: "CSP SME per cloud", color: T.accent },
  { us: "US-3.2", title: "Expand Rule Mappings", tasks: "Analyze 1,474 unmapped AWS rules\nKeyword + ML matching\nTarget: 444 → 800+ mapped (60%+)", agent: "Security BA", color: T.green },
];
ms3.forEach((m, i) => {
  const y = 1.5 + i * 1.5;
  s6.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.5, y, w: 9, h: 1.3, fill: { color: T.bgCard }, rectRadius: 0.08 });
  s6.addShape(pres.shapes.RECTANGLE, { x: 0.5, y, w: 0.06, h: 1.3, fill: { color: m.color } });
  s6.addText(m.us, { x: 0.7, y: y + 0.1, w: 0.8, h: 0.3, fontSize: 10, color: m.color, bold: true, fontFace: "Calibri" });
  s6.addText(m.title, { x: 1.5, y: y + 0.1, w: 5, h: 0.3, fontSize: 14, color: T.white, bold: true, fontFace: "Calibri" });
  s6.addText(m.tasks, { x: 1.5, y: y + 0.45, w: 5.5, h: 0.7, fontSize: 10, color: T.muted, fontFace: "Calibri" });
  s6.addText(m.agent, { x: 7.5, y: y + 0.15, w: 1.8, h: 0.25, fontSize: 10, color: T.ice, align: "right", fontFace: "Calibri" });
});

// ═══════════════════════════════════════════════════════
// SLIDE 7: Milestone 4
// ═══════════════════════════════════════════════════════
let s7 = darkSlide();
sectionBar(s7, "MILESTONE 4: UI & API — Week 6-8");
s7.addText("Build the complete compliance UI with all features", { x: 0.5, y: 0.9, w: 9, h: 0.4, fontSize: 16, color: T.ice, italic: true, fontFace: "Calibri", margin: 0 });

const ms4 = [
  { us: "US-4.1", title: "Framework List: Filtering & Grouping", tasks: "Add columns: Account, CSP, Tenant, Tags, Findings, Last Assessed\nFilter/Group by all columns | Export CSV/PDF/JSON" },
  { us: "US-4.2", title: "Controls Table: Cross-Linking", tasks: "Findings count → findings page | Resource ARN → inventory\nAccount column | Breadcrumb navigation" },
  { us: "US-4.3", title: "Audit & Remediation Tabs", tasks: "Audit: Console + CLI sections | Remediation: Mode selector\nCLI code block with copy | Console numbered steps" },
  { us: "US-4.4", title: "Assessment Scoring & Trends", tasks: "Score by Control + by Asset | Trend chart (7D/14D/1M)\nAccount-level compliance matrix" },
];
ms4.forEach((m, i) => {
  const y = 1.4 + i * 0.95;
  s7.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.5, y, w: 9, h: 0.8, fill: { color: T.bgCard }, rectRadius: 0.08 });
  s7.addShape(pres.shapes.RECTANGLE, { x: 0.5, y, w: 0.06, h: 0.8, fill: { color: T.accent } });
  s7.addText(m.us, { x: 0.7, y: y + 0.05, w: 0.8, h: 0.25, fontSize: 10, color: T.accent, bold: true, fontFace: "Calibri" });
  s7.addText(m.title, { x: 1.5, y: y + 0.05, w: 7, h: 0.25, fontSize: 12, color: T.white, bold: true, fontFace: "Calibri" });
  s7.addText(m.tasks, { x: 1.5, y: y + 0.35, w: 7.5, h: 0.4, fontSize: 9, color: T.muted, fontFace: "Calibri" });
});

// ═══════════════════════════════════════════════════════
// SLIDE 8: Milestone 5
// ═══════════════════════════════════════════════════════
let s8 = darkSlide();
sectionBar(s8, "MILESTONE 5: REPORTS — Week 8-10");
s8.addText("Generate audit-ready compliance reports", { x: 0.5, y: 0.9, w: 9, h: 0.4, fontSize: 16, color: T.ice, italic: true, fontFace: "Calibri", margin: 0 });

const ms5 = [
  { title: "CIS Checklist PDF", desc: "Cover page + per-section summary + per-control Pass/Fail with evidence + appendix", icon: "PDF" },
  { title: "SOC2 / PCI Audit Report", desc: "Executive summary + scope + per-control assessment + exception register + remediation tracking", icon: "AUDIT" },
  { title: "NIST SSP / FedRAMP Report", desc: "System Security Plan format + per-family implementation status + control inheritance mapping", icon: "GOV" },
];
ms5.forEach((m, i) => {
  const y = 1.5 + i * 1.2;
  s8.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.5, y, w: 9, h: 1.0, fill: { color: T.bgCard }, rectRadius: 0.08 });
  s8.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.7, y: y + 0.15, w: 0.7, h: 0.7, fill: { color: T.navy }, rectRadius: 0.05 });
  s8.addText(m.icon, { x: 0.7, y: y + 0.3, w: 0.7, h: 0.4, fontSize: 10, color: T.ice, bold: true, align: "center", fontFace: "Calibri" });
  s8.addText(m.title, { x: 1.6, y: y + 0.1, w: 7, h: 0.35, fontSize: 14, color: T.white, bold: true, fontFace: "Calibri" });
  s8.addText(m.desc, { x: 1.6, y: y + 0.5, w: 7.5, h: 0.4, fontSize: 10, color: T.muted, fontFace: "Calibri" });
});

// ═══════════════════════════════════════════════════════
// SLIDE 9: Agent Review Structure
// ═══════════════════════════════════════════════════════
let s9 = darkSlide();
sectionBar(s9, "REVIEW GATES — SPECIALIZED AGENT VALIDATION");
s9.addText("Every milestone reviewed by 4 specialized agents before completion", { x: 0.5, y: 0.9, w: 9, h: 0.4, fontSize: 14, color: T.ice, italic: true, fontFace: "Calibri", margin: 0 });

const agents = [
  { name: "Security SME Agent", role: "Reviews control definitions, severity levels, MITRE mapping, compliance standard accuracy", color: T.red },
  { name: "CSP SME Agent", role: "Reviews CSP-specific remediation, CLI commands (aws/az/gcloud), console steps, provider accuracy", color: T.accent },
  { name: "Security BA Agent", role: "Reviews completeness, section hierarchy, framework compliance, cross-framework consistency", color: T.green },
  { name: "QA Agent", role: "Validates data quality, cross-references with source PDFs/HTMLs, tests API responses", color: T.amber },
];
agents.forEach((a, i) => {
  const y = 1.5 + i * 0.95;
  s9.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.5, y, w: 9, h: 0.8, fill: { color: T.bgCard }, rectRadius: 0.08 });
  s9.addShape(pres.shapes.RECTANGLE, { x: 0.5, y, w: 0.06, h: 0.8, fill: { color: a.color } });
  s9.addText(a.name, { x: 0.7, y: y + 0.05, w: 3, h: 0.3, fontSize: 13, color: T.white, bold: true, fontFace: "Calibri" });
  s9.addText(a.role, { x: 0.7, y: y + 0.38, w: 8.5, h: 0.35, fontSize: 10, color: T.muted, fontFace: "Calibri" });
});

// ═══════════════════════════════════════════════════════
// SLIDE 10: Schema Changes
// ═══════════════════════════════════════════════════════
let s10 = lightSlide();
sectionBar(s10, "DATABASE SCHEMA CHANGES");
s10.addText("compliance_controls table — new columns", { x: 0.5, y: 0.9, w: 9, h: 0.4, fontSize: 16, color: T.navyDark, bold: true, fontFace: "Calibri", margin: 0 });

const schema = [
  ["Column", "Type", "Purpose"],
  ["sort_order", "INT", "Numeric ordering within framework"],
  ["section_id", "VARCHAR(50)", "Section identifier (e.g. '3', 'AC')"],
  ["section_name", "VARCHAR(200)", "Section display name (e.g. 'Protect Stored Account Data')"],
  ["subsection_id", "VARCHAR(50)", "Subsection identifier (e.g. '3.1', 'AC-2')"],
  ["subsection_name", "VARCHAR(200)", "Subsection display name"],
  ["audit_console", "TEXT", "Console-based audit/testing steps"],
  ["audit_cli", "TEXT", "CLI-based audit commands"],
  ["remediation_console", "TEXT", "Console-based remediation steps"],
  ["remediation_cli", "TEXT", "CLI remediation commands"],
  ["references_urls", "JSONB", "Reference links [{url, title}]"],
];
const schemaRows = schema.map((row, ri) => row.map((cell, ci) => ({
  text: cell,
  options: {
    fontSize: ri === 0 ? 10 : 10,
    bold: ri === 0,
    color: ri === 0 ? T.white : T.navyDark,
    fill: { color: ri === 0 ? T.navy : (ri % 2 === 0 ? T.grayLight : T.white) },
    fontFace: ci === 0 || ci === 1 ? "Consolas" : "Calibri",
    align: "left",
  }
})));
s10.addTable(schemaRows, { x: 0.5, y: 1.4, w: 9, colW: [2.5, 2, 4.5], border: { pt: 0.5, color: "CBD5E1" } });

// ═══════════════════════════════════════════════════════
// SLIDE 11: Timeline
// ═══════════════════════════════════════════════════════
let s11 = darkSlide();
sectionBar(s11, "TIMELINE — 10 WEEKS");

const timeline = [
  { name: "M1: Data Foundation", weeks: "W1-2", w: 2, x: 0, color: T.accent },
  { name: "M2: Document Parsing", weeks: "W3-5", w: 3, x: 2, color: T.green },
  { name: "M3: Data Enrichment", weeks: "W5-6", w: 2, x: 4.5, color: T.amber },
  { name: "M4: UI & API", weeks: "W6-8", w: 3, x: 5.5, color: T.accent },
  { name: "M5: Reports", weeks: "W8-10", w: 3, x: 7.5, color: T.red },
];

// Week labels
for (let i = 1; i <= 10; i++) {
  const x = 0.5 + (i - 1) * 0.9;
  s11.addText("W" + i, { x, y: 1.2, w: 0.9, h: 0.3, fontSize: 10, color: T.muted, align: "center", fontFace: "Calibri" });
  s11.addShape(pres.shapes.LINE, { x, y: 1.5, w: 0, h: 3.5, line: { color: T.bgCard, width: 0.5 } });
}

timeline.forEach((t, i) => {
  const y = 1.7 + i * 0.7;
  const barX = 0.5 + t.x * 0.9;
  const barW = t.w * 0.9;
  s11.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: barX, y, w: barW, h: 0.45, fill: { color: t.color }, rectRadius: 0.05 });
  s11.addText(t.name, { x: barX + 0.1, y: y + 0.02, w: barW - 0.2, h: 0.25, fontSize: 10, color: T.white, bold: true, fontFace: "Calibri" });
  s11.addText(t.weeks, { x: barX + 0.1, y: y + 0.22, w: barW - 0.2, h: 0.2, fontSize: 8, color: "FFFFFFCC", fontFace: "Calibri" });
});

// ═══════════════════════════════════════════════════════
// SLIDE 12: Summary
// ═══════════════════════════════════════════════════════
let s12 = darkSlide();
s12.addShape(pres.shapes.RECTANGLE, { x: 0, y: 0, w: 10, h: 5.625, fill: { color: T.navyDark } });
s12.addShape(pres.shapes.RECTANGLE, { x: 0, y: 4.2, w: 10, h: 1.425, fill: { color: T.navy } });
s12.addText("Next Steps", { x: 0.8, y: 1.0, w: 8.4, h: 0.6, fontSize: 32, color: T.white, bold: true, fontFace: "Calibri" });

s12.addText([
  { text: "1. ", options: { bold: true, color: T.accent } },
  { text: "Approve this plan and priority order", options: { color: T.text, breakLine: true } },
  { text: "2. ", options: { bold: true, color: T.accent } },
  { text: "Start Milestone 1: Fix section names, severity, CLI/Console split", options: { color: T.text, breakLine: true } },
  { text: "3. ", options: { bold: true, color: T.accent } },
  { text: "Build CIS HTML parser prototype for Milestone 2", options: { color: T.text, breakLine: true } },
  { text: "4. ", options: { bold: true, color: T.accent } },
  { text: "Assign specialized SME agents per milestone", options: { color: T.text, breakLine: true } },
  { text: "5. ", options: { bold: true, color: T.accent } },
  { text: "Review and validate data quality at each gate", options: { color: T.text } },
], { x: 0.8, y: 1.7, w: 8.4, h: 2.2, fontSize: 14, fontFace: "Calibri", lineSpacingMultiple: 1.5 });

s12.addText("Data Quality First — Everything Else Follows", { x: 0.8, y: 4.5, w: 8.4, h: 0.5, fontSize: 18, color: T.ice, bold: true, fontFace: "Calibri" });

// ── Save ──
pres.writeFile({ fileName: "/Users/apple/Desktop/threat-engine/data/compliance_project_plan.pptx" })
  .then(() => console.log("Saved: compliance_project_plan.pptx"))
  .catch(e => console.error("Error:", e));
