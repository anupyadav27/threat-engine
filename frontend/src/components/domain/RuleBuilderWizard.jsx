'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  X, ChevronLeft, ChevronRight, Check, AlertTriangle, AlertCircle,
  Search, Plus, Trash2, ChevronDown, Copy, Download, Cloud,
  Server, Globe, Database, Layers, Box,
} from 'lucide-react';

// ─── Constants ────────────────────────────────────────────────────────────────

const CSPS = [
  { id: 'aws',      label: 'AWS',      color: '#FF9900', icon: Cloud },
  { id: 'azure',    label: 'Azure',    color: '#0089D6', icon: Cloud },
  { id: 'gcp',      label: 'GCP',      color: '#4285F4', icon: Globe },
  { id: 'oci',      label: 'OCI',      color: '#F80000', icon: Server },
  { id: 'alicloud', label: 'AliCloud', color: '#FF6A00', icon: Cloud },
  { id: 'ibm',      label: 'IBM',      color: '#0530AD', icon: Database },
  { id: 'k8s',      label: 'K8s',      color: '#326CE5', icon: Layers },
];

const SEVERITIES = [
  { value: 'CRITICAL', color: '#ef4444' },
  { value: 'HIGH',     color: '#f97316' },
  { value: 'MEDIUM',   color: '#f59e0b' },
  { value: 'LOW',      color: '#22c55e' },
];

const CATEGORIES = [
  'configuration', 'identity', 'network', 'data', 'encryption',
  'logging', 'compute', 'storage', 'monitoring', 'access',
];

const FRAMEWORKS = [
  'CIS', 'NIST 800-53', 'ISO 27001', 'PCI-DSS', 'HIPAA',
  'GDPR', 'SOC 2', 'FedRAMP', 'MITRE ATT&CK',
];

const OPERATORS = [
  { value: 'equals',       label: 'equals',             noValue: false },
  { value: 'not_equals',   label: 'not equals',         noValue: false },
  { value: 'contains',     label: 'contains',           noValue: false },
  { value: 'not_contains', label: 'not contains',       noValue: false },
  { value: 'in',           label: 'in (comma list)',    noValue: false },
  { value: 'not_in',       label: 'not in',             noValue: false },
  { value: 'exists',       label: 'exists',             noValue: true  },
  { value: 'not_empty',    label: 'not empty',          noValue: true  },
  { value: 'is_true',      label: 'is true',            noValue: true  },
  { value: 'is_false',     label: 'is false',           noValue: true  },
  { value: 'lt',           label: '< less than',        noValue: false },
  { value: 'lte',          label: '≤ less or equal',   noValue: false },
  { value: 'gt',           label: '> greater than',     noValue: false },
  { value: 'gte',          label: '≥ greater or equal', noValue: false },
  { value: 'starts_with',  label: 'starts with',        noValue: false },
  { value: 'ends_with',    label: 'ends with',          noValue: false },
  { value: 'regex',        label: 'matches regex',      noValue: false },
];

const STEPS = [
  { n: 1, label: 'Metadata'   },
  { n: 2, label: 'CSP & Service' },
  { n: 3, label: 'Operation'  },
  { n: 4, label: 'Conditions' },
  { n: 5, label: 'Review & Save' },
];

// ─── Structured-data helpers (for DB payload) ────────────────────────────────

function buildConditionsObject(logic, conditions) {
  const filled = conditions.filter((c) => c.var.trim());
  if (filled.length === 0) return {};
  const mapOne = (c) => {
    const opDef = OPERATORS.find((o) => o.value === c.op);
    return { var: c.var, op: c.op, value: opDef?.noValue ? null : (c.value || null) };
  };
  if (filled.length === 1) return mapOne(filled[0]);
  return { [logic]: filled.map(mapOne) };
}

// ── Per-CSP field/action extraction ──────────────────────────────────────────

/** Display name for an operation — handles AWS/Azure (yaml_action) and GCP (op key). */
function opDisplayName(op) {
  return op.yaml_action || op.python_method || op.op || op.operation || op.key || '';
}

/** Strip list-field prefix from GCP produces_fields paths.
 * e.g. list_field="items", path="items[].name" → "name"
 *      list_field=null, path="bindings" → "bindings"
 */
function gcpFieldPath(op, rawPath) {
  const lf = op.outputs?.list_field;
  if (lf && rawPath.startsWith(`${lf}[].`)) return rawPath.slice(lf.length + 3);
  return rawPath;
}

function extractConditionFields(csp, op) {
  if (csp === 'gcp') {
    return (op.outputs?.produces_fields || []).map((f) => gcpFieldPath(op, f.path));
  }
  if (csp === 'k8s') {
    // item_fields keys are cleaner (top-level only); fall back to output_fields array
    const ifs = op.item_fields || {};
    const keys = Object.keys(ifs);
    if (keys.length > 0) return keys;
    const ofs = op.output_fields;
    if (Array.isArray(ofs)) return ofs;
    return [];
  }
  if (csp === 'azure') {
    return Object.keys(op.item_fields || {});
  }
  // AWS, OCI, AliCloud, IBM — output_fields is an object
  const ofs = op.output_fields || op.item_fields || {};
  if (typeof ofs === 'object' && !Array.isArray(ofs)) return Object.keys(ofs);
  if (Array.isArray(ofs)) return ofs;
  return [];
}

/** items_for template — the response path that contains the list of items. */
function getDiscoveryItemsFor(csp, op) {
  if (csp === 'gcp') {
    const lf = op.outputs?.list_field;
    return lf ? `{{ response.${lf} }}` : `{{ response.items }}`;
  }
  if (csp === 'k8s') return `{{ response.items }}`;
  if (csp === 'azure') {
    return `{{ response.${op.main_output_field || 'value'} }}`;
  }
  // AWS / OCI / AliCloud / IBM — find the first list-typed output field
  const outputFields = op.output_fields || {};
  for (const [key, field] of Object.entries(outputFields)) {
    if (typeof field === 'object' && field.type === 'list') return `{{ response.${key} }}`;
  }
  const keys = Object.keys(outputFields);
  return keys.length > 0 ? `{{ response.${keys[0]} }}` : null;
}

/** item → field mapping for discovery emit.item. */
function getDiscoveryItemFields(csp, op) {
  if (csp === 'gcp') {
    return Object.fromEntries(
      (op.outputs?.produces_fields || [])
        .slice(0, 40)
        .map((f) => {
          const clean = gcpFieldPath(op, f.path);
          return [clean, `{{ item.${clean} }}`];
        })
    );
  }
  if (csp === 'k8s') {
    const ifs = op.item_fields || {};
    const keys = Object.keys(ifs);
    if (keys.length > 0) {
      return Object.fromEntries(keys.slice(0, 40).map((k) => [k, `{{ item.${k} }}`]));
    }
    // Fallback: output_fields string array
    const ofs = Array.isArray(op.output_fields) ? op.output_fields : [];
    return Object.fromEntries(ofs.slice(0, 40).map((k) => [k, `{{ item.${k} }}`]));
  }
  if (csp === 'azure') {
    return Object.fromEntries(
      Object.keys(op.item_fields || {}).slice(0, 40).map((k) => [k, `{{ item.${k} }}`])
    );
  }
  // AWS / OCI / AliCloud / IBM
  const ofs = op.output_fields || {};
  if (typeof ofs !== 'object' || Array.isArray(ofs)) return {};
  return Object.fromEntries(Object.keys(ofs).slice(0, 40).map((k) => [k, `{{ item.${k} }}`]));
}

// ─── YAML Helpers (pure JS, for download preview only) ───────────────────────

function slugify(str) {
  return str
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s_-]/g, '')
    .replace(/\s+/g, '_')
    .replace(/-+/g, '_')
    .slice(0, 60);
}

function yamlValue(v) {
  if (v === null || v === undefined || v === '' || v === 'null') return 'null';
  const s = String(v);
  if (s === 'true' || s === 'false') return s;
  if (!isNaN(s) && s.trim() !== '') return s;
  if (/[\[\]{}&*!|>'"#%@,]/.test(s) || s.startsWith(' ') || s.includes('\n')) {
    return `'${s.replace(/'/g, "''")}'`;
  }
  return s;
}

function buildConditionsYaml(logic, conditions, indent = 4) {
  const sp = ' '.repeat(indent);
  const filled = conditions.filter((c) => c.var.trim());
  if (filled.length === 0) return `${sp}var: item.__FIELD__\n${sp}op: equals\n${sp}value: null\n`;
  if (filled.length === 1) {
    const c = filled[0];
    const opDef = OPERATORS.find((o) => o.value === c.op);
    let yaml = `${sp}var: ${c.var}\n${sp}op: ${c.op}\n`;
    yaml += opDef?.noValue ? `${sp}value: null\n` : `${sp}value: ${yamlValue(c.value)}\n`;
    return yaml;
  }
  let yaml = `${sp}${logic}:\n`;
  for (const c of filled) {
    const opDef = OPERATORS.find((o) => o.value === c.op);
    yaml += `${sp}- var: ${c.var}\n`;
    yaml += `${sp}  op: ${c.op}\n`;
    yaml += opDef?.noValue
      ? `${sp}  value: null\n`
      : `${sp}  value: ${yamlValue(c.value)}\n`;
  }
  return yaml;
}

function buildRuleYaml(form, selectedOperation, conditionLogic, conditions) {
  const ruleId = `${form.csp}.${form.service}.${form.category}.${slugify(form.ruleName)}`;
  // GCP: op field IS the full discovery_id (e.g. gcp.compute.addresses.list)
  const discoveryId =
    form.csp === 'gcp'
      ? (selectedOperation.op || selectedOperation.key || '')
      : `${form.csp}.${form.service}.${opDisplayName(selectedOperation)}`;

  let yaml = `- rule_id: ${ruleId}\n`;
  yaml += `  for_each: ${discoveryId}\n`;
  yaml += `  severity: ${form.severity}\n`;
  yaml += `  conditions:\n`;
  yaml += buildConditionsYaml(conditionLogic, conditions, 4);

  return { yaml, ruleId, discoveryId };
}

function buildDiscoveryYaml(csp, service, op) {
  // GCP: discovery_id = op field; action = last two dotted segments (e.g. addresses.list)
  let discoveryId, action;
  if (csp === 'gcp') {
    discoveryId = op.op || op.key || '';
    const parts = discoveryId.split('.');
    action = parts.length >= 4 ? parts.slice(2).join('.') : discoveryId;
  } else {
    action = opDisplayName(op);
    discoveryId = `${csp}.${service}.${action}`;
  }

  const itemsFor = getDiscoveryItemsFor(csp, op);
  const itemFieldMap = getDiscoveryItemFields(csp, op);
  const cappedFields = Object.keys(itemFieldMap).slice(0, 40);

  let yaml = `- discovery_id: ${discoveryId}\n`;
  yaml += `  calls:\n`;
  yaml += `  - action: ${action}\n`;
  yaml += `    save_as: response\n`;
  yaml += `    on_error: continue\n`;
  yaml += `  emit:\n`;
  yaml += `    as: item\n`;
  if (itemsFor) yaml += `    items_for: '${itemsFor}'\n`;
  yaml += `    item:\n`;
  for (const field of cappedFields) {
    yaml += `      ${field}: '{{ item.${field} }}'\n`;
  }

  return { yaml, discoveryId };
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StepDots({ step }) {
  return (
    <div className="flex items-center gap-0 mb-6">
      {STEPS.map((s, i) => (
        <div key={s.n} className="flex items-center">
          <div className="flex flex-col items-center">
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold transition-all"
              style={{
                backgroundColor:
                  step === s.n
                    ? 'var(--accent-primary)'
                    : step > s.n
                    ? 'var(--accent-success)'
                    : 'var(--bg-tertiary)',
                color:
                  step >= s.n ? '#fff' : 'var(--text-muted)',
              }}
            >
              {step > s.n ? <Check className="w-4 h-4" /> : s.n}
            </div>
            <span
              className="text-xs mt-1 whitespace-nowrap"
              style={{ color: step === s.n ? 'var(--accent-primary)' : 'var(--text-muted)' }}
            >
              {s.label}
            </span>
          </div>
          {i < STEPS.length - 1 && (
            <div
              className="h-0.5 w-12 mt-[-12px] mx-1"
              style={{ backgroundColor: step > s.n ? 'var(--accent-success)' : 'var(--border-primary)' }}
            />
          )}
        </div>
      ))}
    </div>
  );
}

// Input helper
function Field({ label, required, children, hint }) {
  return (
    <div className="space-y-1">
      <label className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
        {label}{required && <span className="text-red-400 ml-1">*</span>}
      </label>
      {children}
      {hint && <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{hint}</p>}
    </div>
  );
}

const inputCls =
  'w-full px-3 py-2 rounded-lg border text-sm outline-none focus:ring-2 focus:ring-blue-500/40 transition-all';
const inputStyle = {
  backgroundColor: 'var(--bg-tertiary)',
  borderColor: 'var(--border-primary)',
  color: 'var(--text-primary)',
};

// ─── Step 1: Metadata ─────────────────────────────────────────────────────────

function Step1({ form, setForm }) {
  const generatedId =
    form.csp && form.service && form.ruleName
      ? `${form.csp}.${form.service}.${form.category}.${slugify(form.ruleName)}`
      : '(complete CSP, service, and rule name)';

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
          Rule Metadata
        </h2>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)' }}>
          Define the name, severity, and compliance mappings for this rule.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2">
          <Field label="Rule Name" required>
            <input
              className={inputCls}
              style={inputStyle}
              placeholder="e.g. S3 Bucket Encryption Required"
              value={form.ruleName}
              onChange={(e) => setForm((f) => ({ ...f, ruleName: e.target.value }))}
            />
          </Field>
        </div>

        <div className="col-span-2">
          <Field label="Description">
            <textarea
              className={inputCls}
              style={inputStyle}
              rows={2}
              placeholder="What does this rule check for?"
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
          </Field>
        </div>

        <Field label="Severity" required>
          <div className="flex gap-2 flex-wrap">
            {SEVERITIES.map((s) => (
              <button
                key={s.value}
                onClick={() => setForm((f) => ({ ...f, severity: s.value }))}
                className="px-3 py-1.5 rounded-lg text-xs font-bold border-2 transition-all"
                style={{
                  borderColor: form.severity === s.value ? s.color : 'var(--border-primary)',
                  backgroundColor: form.severity === s.value ? s.color + '22' : 'transparent',
                  color: form.severity === s.value ? s.color : 'var(--text-secondary)',
                }}
              >
                {s.value}
              </button>
            ))}
          </div>
        </Field>

        <Field label="Category" required>
          <select
            className={inputCls}
            style={inputStyle}
            value={form.category}
            onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))}
          >
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </Field>
      </div>

      <Field label="Compliance Frameworks">
        <div className="flex flex-wrap gap-2 mt-1">
          {FRAMEWORKS.map((fw) => {
            const active = form.frameworks.includes(fw);
            return (
              <button
                key={fw}
                onClick={() =>
                  setForm((f) => ({
                    ...f,
                    frameworks: active
                      ? f.frameworks.filter((x) => x !== fw)
                      : [...f.frameworks, fw],
                  }))
                }
                className="px-2.5 py-1 rounded text-xs font-medium border transition-all"
                style={{
                  borderColor: active ? 'var(--accent-primary)' : 'var(--border-primary)',
                  backgroundColor: active ? 'rgba(59,130,246,0.12)' : 'transparent',
                  color: active ? 'var(--accent-primary)' : 'var(--text-secondary)',
                }}
              >
                {fw}
              </button>
            );
          })}
        </div>
      </Field>

      <div
        className="rounded-lg px-4 py-3 text-xs font-mono border"
        style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)', color: 'var(--text-muted)' }}
      >
        <span className="font-semibold" style={{ color: 'var(--text-secondary)' }}>Rule ID preview: </span>
        <span style={{ color: 'var(--accent-primary)' }}>{generatedId}</span>
      </div>
    </div>
  );
}

// ─── Step 2: CSP & Service ────────────────────────────────────────────────────

function Step2({ form, setForm, services, loadingServices }) {
  const [serviceSearch, setServiceSearch] = useState('');
  const filtered = services.filter((s) =>
    s.toLowerCase().includes(serviceSearch.toLowerCase())
  );

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
          Cloud Provider & Service
        </h2>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)' }}>
          Select the cloud provider and service this rule targets.
        </p>
      </div>

      {/* CSP grid */}
      <div>
        <p className="text-sm font-medium mb-2" style={{ color: 'var(--text-primary)' }}>
          Cloud Provider <span className="text-red-400">*</span>
        </p>
        <div className="grid grid-cols-4 gap-2">
          {CSPS.map(({ id, label, color, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setForm((f) => ({ ...f, csp: id, service: '' }))}
              className="flex flex-col items-center gap-1.5 px-3 py-3 rounded-xl border-2 transition-all"
              style={{
                borderColor: form.csp === id ? color : 'var(--border-primary)',
                backgroundColor: form.csp === id ? color + '18' : 'var(--bg-tertiary)',
              }}
            >
              <Icon
                className="w-5 h-5"
                style={{ color: form.csp === id ? color : 'var(--text-muted)' }}
              />
              <span
                className="text-xs font-semibold"
                style={{ color: form.csp === id ? color : 'var(--text-secondary)' }}
              >
                {label}
              </span>
              {form.csp === id && (
                <Check className="w-3 h-3" style={{ color }} />
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Service list */}
      {form.csp && (
        <div>
          <p className="text-sm font-medium mb-2" style={{ color: 'var(--text-primary)' }}>
            Service <span className="text-red-400">*</span>
            <span className="ml-2 text-xs font-normal" style={{ color: 'var(--text-muted)' }}>
              {services.length} available
            </span>
          </p>
          <div
            className="relative mb-2"
            style={{ backgroundColor: 'var(--bg-tertiary)', borderRadius: 8 }}
          >
            <Search
              className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
              style={{ color: 'var(--text-muted)' }}
            />
            <input
              className="w-full pl-9 pr-3 py-2 text-sm bg-transparent border rounded-lg outline-none"
              style={{ borderColor: 'var(--border-primary)', color: 'var(--text-primary)' }}
              placeholder={`Search ${form.csp} services…`}
              value={serviceSearch}
              onChange={(e) => setServiceSearch(e.target.value)}
            />
          </div>

          {loadingServices ? (
            <div className="h-40 flex items-center justify-center" style={{ color: 'var(--text-muted)' }}>
              Loading services…
            </div>
          ) : (
            <div
              className="border rounded-lg overflow-y-auto"
              style={{ maxHeight: 220, borderColor: 'var(--border-primary)' }}
            >
              {filtered.length === 0 ? (
                <div className="p-4 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                  No services match your search
                </div>
              ) : (
                filtered.map((svc) => (
                  <button
                    key={svc}
                    onClick={() => setForm((f) => ({ ...f, service: svc }))}
                    className="w-full text-left px-4 py-2 text-sm flex items-center justify-between transition-colors"
                    style={{
                      backgroundColor:
                        form.service === svc
                          ? 'rgba(59,130,246,0.12)'
                          : 'transparent',
                      color:
                        form.service === svc
                          ? 'var(--accent-primary)'
                          : 'var(--text-primary)',
                      borderBottom: '1px solid var(--border-primary)',
                    }}
                  >
                    <span className="font-mono">{svc}</span>
                    {form.service === svc && <Check className="w-4 h-4" />}
                  </button>
                ))
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Step 3: Operation ────────────────────────────────────────────────────────

function Step3({ operations, selectedOperation, onSelect, csp }) {
  const [search, setSearch] = useState('');
  const [showIndepOnly, setShowIndepOnly] = useState(false);

  const opList = Object.entries(operations).map(([key, op]) => ({ key, ...op }));
  // Only show read operations for GCP (kind: read_list, read_describe, read_get)
  const readOpList = opList.filter((op) =>
    csp !== 'gcp' || (op.kind || '').toLowerCase().startsWith('read')
  );
  const filtered = readOpList.filter((op) => {
    const q = search.toLowerCase();
    const name = opDisplayName(op).toLowerCase();
    const matches = !q || name.includes(q) || (op.kind || '').toLowerCase().includes(q);
    return matches && (!showIndepOnly || op.independent);
  });

  const fieldCount = (op) => {
    if (csp === 'gcp') return (op.outputs?.produces_fields || []).length;
    const ofs = op.output_fields || op.item_fields || {};
    if (Array.isArray(ofs)) return ofs.length;
    return typeof ofs === 'object' ? Object.keys(ofs).length : 0;
  };

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
          Select Operation
        </h2>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)' }}>
          Choose the API read operation that your rule will iterate over.
        </p>
      </div>

      <div className="flex gap-3">
        <div className="relative flex-1">
          <Search
            className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
            style={{ color: 'var(--text-muted)' }}
          />
          <input
            className={`${inputCls} pl-9`}
            style={inputStyle}
            placeholder="Search operations…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <button
          onClick={() => setShowIndepOnly((v) => !v)}
          className="px-3 py-2 rounded-lg text-xs font-medium border transition-all whitespace-nowrap"
          style={{
            borderColor: showIndepOnly ? 'var(--accent-primary)' : 'var(--border-primary)',
            backgroundColor: showIndepOnly ? 'rgba(59,130,246,0.12)' : 'transparent',
            color: showIndepOnly ? 'var(--accent-primary)' : 'var(--text-secondary)',
          }}
        >
          Independent only
        </button>
      </div>

      <div
        className="border rounded-lg overflow-y-auto space-y-0 divide-y"
        style={{ maxHeight: 320, borderColor: 'var(--border-primary)', divideColor: 'var(--border-primary)' }}
      >
        {filtered.length === 0 ? (
          <div className="p-6 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
            No operations found
          </div>
        ) : (
          filtered.map((op) => {
            const isSelected = selectedOperation?.key === op.key;
            return (
              <button
                key={op.key}
                onClick={() => onSelect(op)}
                className="w-full text-left px-4 py-3 transition-colors"
                style={{
                  backgroundColor: isSelected ? 'rgba(59,130,246,0.1)' : 'transparent',
                  borderLeft: isSelected ? '3px solid var(--accent-primary)' : '3px solid transparent',
                }}
              >
                <div className="flex items-start justify-between">
                  <div>
                    <p
                      className="text-sm font-mono font-semibold"
                      style={{ color: isSelected ? 'var(--accent-primary)' : 'var(--text-primary)' }}
                    >
                      {opDisplayName(op)}
                    </p>
                    {/* GCP: show http path as subtitle */}
                    {op.http?.path && (
                      <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--text-muted)', maxWidth: 300 }}>
                        {op.http.path}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-2 ml-3 flex-shrink-0">
                    <span
                      className="text-xs px-2 py-0.5 rounded-full"
                      style={{
                        backgroundColor: op.independent
                          ? 'rgba(34,197,94,0.15)'
                          : 'rgba(245,158,11,0.15)',
                        color: op.independent ? 'var(--accent-success)' : 'var(--accent-warning)',
                      }}
                    >
                      {op.independent ? 'independent' : 'dependent'}
                    </span>
                    <span
                      className="text-xs px-2 py-0.5 rounded-full"
                      style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)' }}
                    >
                      {op.kind || 'read'}
                    </span>
                    {fieldCount(op) > 0 && (
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                        {fieldCount(op)} fields
                      </span>
                    )}
                    {isSelected && <Check className="w-4 h-4" style={{ color: 'var(--accent-primary)' }} />}
                  </div>
                </div>
                {/* Required params hint (AWS/Azure style) */}
                {op.required_params?.length > 0 && (
                  <p className="text-xs mt-1" style={{ color: 'var(--accent-warning)' }}>
                    Requires: {op.required_params.join(', ')}
                  </p>
                )}
                {/* GCP required inputs hint */}
                {op.inputs?.required?.filter((p) => p.slots?.[0]?.source !== 'always_available').length > 0 && (
                  <p className="text-xs mt-1" style={{ color: 'var(--accent-warning)' }}>
                    Requires: {op.inputs.required
                      .filter((p) => p.slots?.[0]?.source !== 'always_available')
                      .map((p) => p.param).join(', ')}
                  </p>
                )}
              </button>
            );
          })
        )}
      </div>

      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Showing {filtered.length} of {readOpList.length} read operations
      </p>
    </div>
  );
}

// ─── Step 4: Condition Builder ────────────────────────────────────────────────

let _condId = 0;
const newCond = () => ({ id: String(++_condId), var: '', op: 'equals', value: '' });

function ConditionRow({ cond, fields, onChange, onDelete, showDelete }) {
  const opDef = OPERATORS.find((o) => o.value === cond.op);

  return (
    <div className="flex items-center gap-2">
      {/* Field */}
      <select
        className={`${inputCls} flex-1 min-w-0`}
        style={{ ...inputStyle, fontFamily: 'monospace', fontSize: 12 }}
        value={cond.var}
        onChange={(e) => onChange({ ...cond, var: e.target.value })}
      >
        <option value="">-- select field --</option>
        {fields.map((f) => (
          <option key={f} value={`item.${f}`}>{f}</option>
        ))}
      </select>

      {/* Operator */}
      <select
        className={`${inputCls}`}
        style={{ ...inputStyle, width: 160 }}
        value={cond.op}
        onChange={(e) => onChange({ ...cond, op: e.target.value, value: '' })}
      >
        {OPERATORS.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>

      {/* Value */}
      {opDef?.noValue ? (
        <span
          className="px-3 py-2 rounded-lg text-xs"
          style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--text-muted)', width: 120, textAlign: 'center' }}
        >
          (no value)
        </span>
      ) : (
        <input
          className={inputCls}
          style={{ ...inputStyle, width: 160 }}
          placeholder="value"
          value={cond.value}
          onChange={(e) => onChange({ ...cond, value: e.target.value })}
        />
      )}

      {/* Delete */}
      {showDelete && (
        <button
          onClick={onDelete}
          className="p-2 rounded-lg transition-colors flex-shrink-0"
          style={{ color: 'var(--accent-danger)' }}
        >
          <Trash2 className="w-4 h-4" />
        </button>
      )}
    </div>
  );
}

function Step4({ selectedOperation, csp, conditionLogic, setConditionLogic, conditions, setConditions }) {
  const fields = selectedOperation ? extractConditionFields(csp, selectedOperation) : [];

  const yamlPreview =
    '  conditions:\n' + buildConditionsYaml(conditionLogic, conditions, 4);

  const handleChange = (id, updated) => {
    setConditions((cs) => cs.map((c) => (c.id === id ? updated : c)));
  };
  const handleDelete = (id) => {
    setConditions((cs) => cs.filter((c) => c.id !== id));
  };
  const handleAdd = () => setConditions((cs) => [...cs, newCond()]);

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
          Build Conditions
        </h2>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)' }}>
          Define when this rule should trigger a finding. Fields come from{' '}
          <code
            className="px-1 py-0.5 rounded text-xs"
            style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--accent-primary)' }}
          >
            {selectedOperation ? opDisplayName(selectedOperation) : ''}
          </code>
          .
        </p>
      </div>

      {/* Logic toggle */}
      {conditions.length > 1 && (
        <div className="flex items-center gap-3">
          <span className="text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>
            Match:
          </span>
          <div className="flex rounded-lg overflow-hidden border" style={{ borderColor: 'var(--border-primary)' }}>
            {['all', 'any'].map((l) => (
              <button
                key={l}
                onClick={() => setConditionLogic(l)}
                className="px-4 py-1.5 text-sm font-medium transition-colors"
                style={{
                  backgroundColor:
                    conditionLogic === l ? 'var(--accent-primary)' : 'var(--bg-tertiary)',
                  color: conditionLogic === l ? '#fff' : 'var(--text-secondary)',
                }}
              >
                {l === 'all' ? 'ALL (AND)' : 'ANY (OR)'}
              </button>
            ))}
          </div>
          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            {conditionLogic === 'all' ? 'All conditions must pass' : 'At least one condition must pass'}
          </span>
        </div>
      )}

      {/* Conditions list */}
      <div className="space-y-2">
        {conditions.map((cond, idx) => (
          <div key={cond.id} className="flex items-center gap-2">
            {conditions.length > 1 && (
              <span
                className="text-xs w-8 text-right flex-shrink-0"
                style={{ color: 'var(--text-muted)' }}
              >
                {idx === 0 ? 'IF' : conditionLogic === 'all' ? 'AND' : 'OR'}
              </span>
            )}
            <div className="flex-1">
              <ConditionRow
                cond={cond}
                fields={fields}
                onChange={(updated) => handleChange(cond.id, updated)}
                onDelete={() => handleDelete(cond.id)}
                showDelete={conditions.length > 1}
              />
            </div>
          </div>
        ))}
      </div>

      <button
        onClick={handleAdd}
        className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm border transition-colors"
        style={{ borderColor: 'var(--border-primary)', color: 'var(--text-secondary)' }}
      >
        <Plus className="w-4 h-4" />
        Add Condition
      </button>

      {/* YAML preview */}
      <div>
        <p className="text-xs font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
          YAML preview
        </p>
        <pre
          className="rounded-lg p-3 text-xs font-mono overflow-x-auto"
          style={{
            backgroundColor: 'var(--bg-tertiary)',
            color: 'var(--accent-primary)',
            border: '1px solid var(--border-primary)',
          }}
        >
          {yamlPreview}
        </pre>
      </div>

      {fields.length === 0 && (
        <div
          className="p-3 rounded-lg border flex items-center gap-2 text-sm"
          style={{
            backgroundColor: 'rgba(245,158,11,0.1)',
            borderColor: 'var(--accent-warning)',
            color: 'var(--accent-warning)',
          }}
        >
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          No output fields found for this operation. You can still type field paths manually.
        </div>
      )}
    </div>
  );
}

// ─── Step 5: Review & Save ────────────────────────────────────────────────────

function YamlBlock({ label, yaml, filename }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(yaml);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  const download = () => {
    const blob = new Blob([yaml], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
  };
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{label}</p>
        <div className="flex gap-1">
          <button
            onClick={copy}
            className="p-1.5 rounded transition-colors"
            style={{ color: 'var(--text-muted)' }}
          >
            {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
          <button
            onClick={download}
            className="p-1.5 rounded transition-colors"
            style={{ color: 'var(--text-muted)' }}
          >
            <Download className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
      <pre
        className="rounded-lg p-3 text-xs font-mono overflow-auto"
        style={{
          backgroundColor: 'var(--bg-tertiary)',
          color: 'var(--text-primary)',
          border: '1px solid var(--border-primary)',
          maxHeight: 220,
        }}
      >
        {yaml}
      </pre>
    </div>
  );
}

function Step5({ form, ruleYaml, ruleId, discoveryYaml, discoveryId, duplicates, checkingDuplicates, onSave, saving, saved, saveResult }) {
  const checked = duplicates !== null;

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold" style={{ color: 'var(--text-primary)' }}>
          Review & Save
        </h2>
        <p className="text-sm mt-0.5" style={{ color: 'var(--text-secondary)' }}>
          Review the generated YAML and save your rule.
        </p>
      </div>

      {/* Summary bar */}
      <div
        className="grid grid-cols-4 gap-3 rounded-xl p-3 border"
        style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}
      >
        {[
          { label: 'CSP', value: form.csp?.toUpperCase() },
          { label: 'Service', value: form.service },
          { label: 'Severity', value: form.severity },
          { label: 'Frameworks', value: form.frameworks.join(', ') || '—' },
        ].map(({ label, value }) => (
          <div key={label}>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</p>
            <p className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>{value}</p>
          </div>
        ))}
      </div>

      {/* YAML panels */}
      <div className="grid grid-cols-2 gap-4">
        <YamlBlock
          label="Rule Check YAML"
          yaml={ruleYaml}
          filename={`${form.service}.checks.yaml`}
        />
        <YamlBlock
          label="Discovery YAML"
          yaml={discoveryYaml}
          filename={`${form.service}.discovery.yaml`}
        />
      </div>

      {/* Duplicate check — auto result */}
      <div className="space-y-3">
        {checkingDuplicates && (
          <div
            className="rounded-lg border p-3 flex items-center gap-2"
            style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-primary)' }}
          >
            <div className="w-4 h-4 border-2 border-t-transparent rounded-full animate-spin" style={{ borderColor: 'var(--accent-primary)', borderTopColor: 'transparent' }} />
            <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
              Checking for duplicate rules…
            </p>
          </div>
        )}

        {!checkingDuplicates && duplicates !== null && (
          duplicates.length > 0 ? (
            <div
              className="rounded-lg border p-4 space-y-2"
              style={{ backgroundColor: 'rgba(245,158,11,0.08)', borderColor: 'var(--accent-warning)' }}
            >
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" style={{ color: 'var(--accent-warning)' }} />
                <p className="text-sm font-semibold" style={{ color: 'var(--accent-warning)' }}>
                  {duplicates.length} existing rule{duplicates.length > 1 ? 's' : ''} use the same operation
                </p>
              </div>
              <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>
                These rules already iterate over{' '}
                <code
                  className="px-1 rounded"
                  style={{ backgroundColor: 'var(--bg-tertiary)', color: 'var(--accent-primary)' }}
                >
                  {discoveryId}
                </code>
                . Your new rule has different conditions so it can still be saved.
              </p>
              <ul className="space-y-1.5 mt-2">
                {duplicates.map((d) => (
                  <li
                    key={d.rule_id}
                    className="flex items-center justify-between px-3 py-2 rounded-lg"
                    style={{ backgroundColor: 'var(--bg-tertiary)' }}
                  >
                    <span className="text-xs font-mono" style={{ color: 'var(--text-primary)' }}>
                      {d.rule_id}
                    </span>
                    <div className="flex items-center gap-2 ml-3 flex-shrink-0">
                      <span
                        className="text-xs px-2 py-0.5 rounded-full font-semibold"
                        style={{
                          backgroundColor:
                            d.severity === 'critical' ? 'rgba(239,68,68,0.15)' :
                            d.severity === 'high'     ? 'rgba(249,115,22,0.15)' :
                            d.severity === 'medium'   ? 'rgba(245,158,11,0.15)' :
                                                         'rgba(34,197,94,0.15)',
                          color:
                            d.severity === 'critical' ? '#ef4444' :
                            d.severity === 'high'     ? '#f97316' :
                            d.severity === 'medium'   ? '#f59e0b' : '#22c55e',
                        }}
                      >
                        {d.severity?.toUpperCase()}
                      </span>
                      <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                        {d.title}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <div
              className="rounded-lg border p-3 flex items-center gap-2"
              style={{ backgroundColor: 'rgba(34,197,94,0.08)', borderColor: 'var(--accent-success)' }}
            >
              <Check className="w-4 h-4" style={{ color: 'var(--accent-success)' }} />
              <p className="text-sm" style={{ color: 'var(--accent-success)' }}>
                No duplicate rules found.
              </p>
            </div>
          )
        )}
      </div>

      {/* Save result */}
      {saved && saveResult && (
        <div
          className="rounded-lg border p-4 space-y-2"
          style={{ backgroundColor: 'rgba(34,197,94,0.08)', borderColor: 'var(--accent-success)' }}
        >
          <div className="flex items-center gap-2">
            <Check className="w-5 h-5" style={{ color: 'var(--accent-success)' }} />
            <p className="text-sm font-semibold" style={{ color: 'var(--accent-success)' }}>
              {saveResult.message || 'Rule saved successfully'}
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3 mt-1">
            {[
              { label: 'Table', value: 'user_check_rules' },
              { label: 'Rule ID', value: saveResult.rule?.rule_id || ruleId },
              { label: 'Discovery Table', value: 'user_check_discoveries' },
              { label: 'Discovery ID', value: saveResult.discovery?.discovery_id || discoveryId },
            ].map(({ label, value }) => (
              <div key={label}>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>{label}</p>
                <p className="text-xs font-mono truncate" style={{ color: 'var(--text-secondary)' }}>{value}</p>
              </div>
            ))}
          </div>
          {saveResult.rule?.created_at && (
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
              Saved at {new Date(saveResult.rule.created_at).toLocaleString()}
            </p>
          )}
        </div>
      )}

      {/* Save button — shown as soon as duplicate check completes */}
      {!saved && checked && !checkingDuplicates && (
        <button
          onClick={onSave}
          disabled={saving}
          className="w-full py-3 rounded-xl text-sm font-semibold text-white transition-all"
          style={{
            backgroundColor: saving ? 'var(--text-muted)' : 'var(--accent-primary)',
            cursor: saving ? 'default' : 'pointer',
          }}
        >
          {saving ? 'Saving…' : 'Create Rule & Discovery'}
        </button>
      )}
    </div>
  );
}

// ─── Main Wizard ──────────────────────────────────────────────────────────────

export default function RuleBuilderWizard({ onClose, onSaved }) {
  const [step, setStep] = useState(1);

  const [form, setForm] = useState({
    ruleName: '',
    description: '',
    severity: 'MEDIUM',
    category: 'configuration',
    frameworks: [],
    csp: '',
    service: '',
  });

  const [services, setServices] = useState([]);
  const [loadingServices, setLoadingServices] = useState(false);

  const [operations, setOperations] = useState({});
  const [loadingOps, setLoadingOps] = useState(false);
  const [selectedOperation, setSelectedOperation] = useState(null);

  const [conditionLogic, setConditionLogic] = useState('all');
  const [conditions, setConditions] = useState([newCond()]);

  const [duplicates, setDuplicates] = useState(null);
  const [checkingDuplicates, setCheckingDuplicates] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [saveResult, setSaveResult] = useState(null);

  // Load services when CSP changes
  const CATALOG_BASE = process.env.NEXT_PUBLIC_BASE_PATH || '';

  useEffect(() => {
    if (!form.csp) { setServices([]); return; }
    setLoadingServices(true);
    setServices([]);
    setSelectedOperation(null);
    setOperations({});
    fetch(`${CATALOG_BASE}/api/catalog/services?csp=${form.csp}`)
      .then((r) => r.json())
      .then((d) => setServices(d.services || []))
      .catch(() => setServices([]))
      .finally(() => setLoadingServices(false));
  }, [form.csp]);

  // Load operations when service changes
  useEffect(() => {
    if (!form.csp || !form.service) { setOperations({}); setSelectedOperation(null); return; }
    setLoadingOps(true);
    setSelectedOperation(null);
    fetch(`${CATALOG_BASE}/api/catalog/operations?csp=${form.csp}&service=${form.service}`)
      .then((r) => r.json())
      .then((d) => setOperations(d.operations || {}))
      .catch(() => setOperations({}))
      .finally(() => setLoadingOps(false));
  }, [form.csp, form.service]);

  // Generate YAMLs (and derive ruleId / discoveryId for DB save)
  const { yaml: ruleYaml, ruleId, discoveryId } =
    selectedOperation && form.ruleName && form.csp && form.service
      ? buildRuleYaml(form, selectedOperation, conditionLogic, conditions)
      : { yaml: '# (incomplete — fill all steps)', ruleId: '', discoveryId: '' };

  // discovery_action: for GCP strip csp+service prefix; for others use opDisplayName
  const discoveryAction = (() => {
    if (!selectedOperation) return '';
    if (form.csp === 'gcp') {
      const parts = (selectedOperation.op || '').split('.');
      return parts.length >= 4 ? parts.slice(2).join('.') : (selectedOperation.op || '');
    }
    return opDisplayName(selectedOperation);
  })();

  const { yaml: discoveryYaml } =
    selectedOperation && form.csp && form.service
      ? buildDiscoveryYaml(form.csp, form.service, selectedOperation)
      : { yaml: '# (no operation selected)' };

  // Auto-check duplicates when user lands on step 5
  useEffect(() => {
    if (step !== 5 || !discoveryId) return;
    setDuplicates(null);
    setCheckingDuplicates(true);
    fetch(`${CATALOG_BASE}/api/catalog/save-rule`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        checkDuplicate: true,
        provider: form.csp,
        service: form.service,
        for_each: discoveryId,
        tenant_id: null,
      }),
    })
      .then((r) => r.json())
      .then((d) => setDuplicates(d.duplicates || []))
      .catch(() => setDuplicates([]))
      .finally(() => setCheckingDuplicates(false));
  }, [step]); // eslint-disable-line react-hooks/exhaustive-deps

  // Navigation validation
  const canAdvance = () => {
    if (step === 1) return form.ruleName.trim().length >= 3;
    if (step === 2) return !!form.csp && !!form.service;
    if (step === 3) return !!selectedOperation;
    if (step === 4) return conditions.some((c) => c.var.trim());
    return false;
  };

  const handleSave = async () => {
    setSaving(true);
    const itemsFor = selectedOperation ? getDiscoveryItemsFor(form.csp, selectedOperation) : null;
    const itemFields = selectedOperation ? getDiscoveryItemFields(form.csp, selectedOperation) : {};

    const res = await fetch(`${CATALOG_BASE}/api/catalog/save-rule`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        checkDuplicate: false,
        // Rule
        rule_id: ruleId,
        provider: form.csp,
        service: form.service,
        severity: form.severity,
        category: form.category,
        title: form.ruleName,
        description: form.description,
        frameworks: form.frameworks,
        for_each: discoveryId,
        conditions: buildConditionsObject(conditionLogic, conditions),
        condition_logic: conditionLogic,
        // Discovery
        discovery_id: discoveryId,
        discovery_action: discoveryAction,
        discovery_items_for: itemsFor,
        discovery_item_fields: itemFields,
        tenant_id: null,
        customer_id: null,
      }),
    }).then((r) => r.json()).catch((e) => ({ error: e.message }));
    setSaving(false);
    if (!res.error) {
      setSaved(true);
      setSaveResult(res);
      onSaved?.(res);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ backgroundColor: 'rgba(0,0,0,0.65)' }}>
      <div
        className="w-full rounded-2xl flex flex-col shadow-2xl"
        style={{
          backgroundColor: 'var(--bg-card)',
          maxWidth: step === 5 ? 960 : 700,
          maxHeight: '92vh',
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-6 py-4 border-b flex-shrink-0"
          style={{ borderColor: 'var(--border-primary)' }}
        >
          <h1 className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>
            Rule Builder
          </h1>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg transition-colors"
            style={{ color: 'var(--text-muted)' }}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Step dots */}
        <div className="px-6 pt-5 flex-shrink-0 overflow-x-auto">
          <StepDots step={step} />
        </div>

        {/* Content */}
        <div className="px-6 pb-4 overflow-y-auto flex-1">
          {step === 1 && <Step1 form={form} setForm={setForm} />}
          {step === 2 && (
            <Step2
              form={form}
              setForm={setForm}
              services={services}
              loadingServices={loadingServices}
            />
          )}
          {step === 3 && (
            loadingOps ? (
              <div className="flex items-center justify-center h-40" style={{ color: 'var(--text-muted)' }}>
                Loading operations…
              </div>
            ) : (
              <Step3
                csp={form.csp}
                operations={operations}
                selectedOperation={selectedOperation}
                onSelect={setSelectedOperation}
              />
            )
          )}
          {step === 4 && (
            <Step4
              csp={form.csp}
              selectedOperation={selectedOperation}
              conditionLogic={conditionLogic}
              setConditionLogic={setConditionLogic}
              conditions={conditions}
              setConditions={setConditions}
            />
          )}
          {step === 5 && (
            <Step5
              form={form}
              ruleYaml={ruleYaml}
              ruleId={ruleId}
              discoveryYaml={discoveryYaml}
              discoveryId={discoveryId}
              duplicates={duplicates}
              checkingDuplicates={checkingDuplicates}
              onSave={handleSave}
              saving={saving}
              saved={saved}
              saveResult={saveResult}
            />
          )}
        </div>

        {/* Footer */}
        <div
          className="flex items-center justify-between px-6 py-4 border-t flex-shrink-0"
          style={{ borderColor: 'var(--border-primary)' }}
        >
          <button
            onClick={() => step > 1 ? setStep((s) => s - 1) : onClose()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
            style={{ backgroundColor: 'var(--bg-secondary)', color: 'var(--text-secondary)' }}
          >
            <ChevronLeft className="w-4 h-4" />
            {step === 1 ? 'Cancel' : 'Back'}
          </button>

          <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Step {step} of {STEPS.length}
          </span>

          {step < STEPS.length ? (
            <button
              onClick={() => setStep((s) => s + 1)}
              disabled={!canAdvance()}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white transition-all"
              style={{
                backgroundColor: canAdvance() ? 'var(--accent-primary)' : 'var(--text-muted)',
                cursor: canAdvance() ? 'pointer' : 'default',
              }}
            >
              Next
              <ChevronRight className="w-4 h-4" />
            </button>
          ) : (
            saved && (
              <button
                onClick={onClose}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white"
                style={{ backgroundColor: 'var(--accent-success)' }}
              >
                <Check className="w-4 h-4" />
                Done
              </button>
            )
          )}
        </div>
      </div>
    </div>
  );
}
