#!/usr/bin/env node
/* eslint-disable */
/**
 * extract-bff-fields.js (JNY-14, Layer 3)
 *
 * Scans frontend/src/app/**\/page.jsx and frontend/src/components/**\/*.jsx,
 * finds every `useViewFetch('<view>')` / `fetchView('<view>')` call and
 * records every MemberExpression chain on the variable bound to that
 * response (commonly `data`, `view`, `response`, `res`, `j`, `viewData`).
 *
 * AST mode: tries to require @babel/parser (transitive via next).
 * Fallback mode: pure-regex heuristic, less accurate but good enough to
 *                catch obvious drift (`data.attackPath.steps`).
 *
 * Output: scripts/.cache/ui-consumed-fields.json
 *   {
 *     "<viewName>": {
 *       "files": ["frontend/src/app/threat/page.jsx", ...],
 *       "paths": ["pageContext.title", "threats.0.severity", ...]
 *     }
 *   }
 *
 * Usage: node scripts/extract-bff-fields.js
 *
 * Performance budget: < 30s on full repo.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..');
const FRONTEND_DIR = path.join(REPO_ROOT, 'frontend', 'src');
const OUT_PATH = path.join(__dirname, '.cache', 'ui-consumed-fields.json');
// JNY-16: bypass scanner output (separate file so the JNY-14 contract diff
// remains untouched).
const BYPASS_OUT_PATH = path.join(
  __dirname,
  '.cache',
  'ui-consumed-bypass-fields.json'
);

// JNY-16: hardcoded direct-engine bypass list. DO NOT auto-discover from
// next.config.js — too brittle. Updates here are an intentional, reviewable
// signal (see ALLOWED_BYPASSES.md when JNY-16 ships docs).
const BYPASSES = [
  {
    name: 'vulnerability',
    prefix: '/vulnerability',
    // Captures path arg of vulnFetch/vulnPublicFetch + raw /vulnerability/api/v1 URLs.
    patterns: [
      { re: /vulnFetch\s*\(\s*[`'"]([^`'"]+)[`'"]/g, normalize: 'vulnFetch' },
      { re: /vulnPublicFetch\s*\(\s*[`'"]([^`'"]+)[`'"]/g, normalize: 'vulnFetch' },
      { re: /[`'"](\/vulnerability\/api\/v1\/[^`'"?\s]+)/g, normalize: 'strip-prefix' },
    ],
  },
  {
    name: 'sbom',
    prefix: '/sbom',
    patterns: [
      { re: /[`'"](\/sbom\/api\/v1\/[^`'"?\s]+)/g, normalize: 'strip-prefix' },
    ],
  },
  {
    name: 'onboarding-write',
    prefix: '/onboarding',
    patterns: [
      { re: /[`'"](\/onboarding\/api\/v1\/[^`'"?\s]+)/g, normalize: 'strip-prefix' },
    ],
  },
  {
    name: 'cspm-auth',
    prefix: '/cspm',
    patterns: [
      // /api/auth/* — handled by Next.js proxy → cspm-django backend.
      { re: /fetchFromCspm\s*\(\s*[`'"]([^`'"]+)[`'"]/g, normalize: 'asis' },
      { re: /[`'"](\/api\/auth\/[a-zA-Z0-9_\-\/]+)[`'"]/g, normalize: 'asis' },
    ],
  },
];

// Variable names that typically hold a BFF response in this codebase.
const RESPONSE_VAR_NAMES = new Set([
  'data',
  'view',
  'viewData',
  'response',
  'res',
  'j',
  'json',
  'result',
  'payload',
  'bff',
  'resp',
]);

// Try to load babel parser (bundled transitively via next).
let parser = null;
let traverse = null;
let mode = 'regex';
try {
  parser = require(path.join(REPO_ROOT, 'frontend', 'node_modules', '@babel', 'parser'));
  try {
    const traverseMod = require(path.join(
      REPO_ROOT,
      'frontend',
      'node_modules',
      '@babel',
      'traverse'
    ));
    traverse = traverseMod.default || traverseMod;
  } catch (_) {
    // traverse unavailable – we'll walk the AST manually
    traverse = null;
  }
  mode = 'babel';
} catch (_) {
  mode = 'regex';
}

// ─────────────────────────────────────────────────────────────────────────────
// File discovery
// ─────────────────────────────────────────────────────────────────────────────
function walk(dir, out, predicate) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (_) {
    return;
  }
  for (const ent of entries) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (ent.name === 'node_modules' || ent.name.startsWith('.')) continue;
      walk(full, out, predicate);
    } else if (ent.isFile() && predicate(full)) {
      out.push(full);
    }
  }
}

function discoverFiles() {
  const files = [];
  walk(path.join(FRONTEND_DIR, 'app'), files, (f) => f.endsWith('page.jsx'));
  walk(path.join(FRONTEND_DIR, 'components'), files, (f) => f.endsWith('.jsx'));
  return files;
}

// ─────────────────────────────────────────────────────────────────────────────
// Regex extractor (fallback)
// ─────────────────────────────────────────────────────────────────────────────
function extractRegex(source) {
  // Find all view-fetch calls with their bound destructure variable.
  // Patterns we recognize:
  //   const { data, ... } = useViewFetch('<view>')
  //   const { data: foo } = useViewFetch('<view>')
  //   const data = await fetchView('<view>')
  //   const j = await fetchView('<view>')
  const viewCalls = [];
  const callRe =
    /(?:const|let|var)\s+(\{[^}]+\}|\w+)\s*=\s*(?:await\s+)?(?:useViewFetch|fetchView)\s*\(\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = callRe.exec(source)) !== null) {
    const lhs = m[1];
    const view = m[2];
    let bound = null;
    if (lhs.startsWith('{')) {
      // destructure – look for `data` (or rename of `data: x`).
      const inner = lhs.slice(1, -1);
      const dataMatch = inner.match(/\bdata(?:\s*:\s*(\w+))?/);
      if (dataMatch) bound = dataMatch[1] || 'data';
    } else {
      bound = lhs;
    }
    if (bound) viewCalls.push({ view, bound });
  }

  if (viewCalls.length === 0) return [];

  // For each bound var, walk source character-by-character to extract
  // MemberExpression chains. We capture `<bound>(.<id>|[<num>])+` greedily
  // and convert numeric indexes to '0' (collapse to a positional marker).
  const results = [];
  for (const { view, bound } of viewCalls) {
    const chainRe = new RegExp(
      `\\b${bound}((?:\\??\\.[A-Za-z_$][\\w$]*|\\[\\s*(?:\\d+|['\"][^'\"]*['\"])\\s*\\])+)`,
      'g'
    );
    let cm;
    const paths = new Set();
    while ((cm = chainRe.exec(source)) !== null) {
      const tail = cm[1]
        // turn ?.foo into .foo
        .replace(/\?\./g, '.')
        // [0], [12] -> .0 (positional)
        .replace(/\[\s*(\d+)\s*\]/g, '.$1')
        // ['key'] / ["key"] -> .key
        .replace(/\[\s*['"]([^'"]+)['"]\s*\]/g, '.$1')
        .replace(/^\./, '');
      if (tail && /^[A-Za-z_]/.test(tail)) paths.add(tail);
    }
    results.push({ view, paths: [...paths].sort() });
  }
  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// Babel extractor
// ─────────────────────────────────────────────────────────────────────────────
function memberChain(node) {
  // Walk a MemberExpression / OptionalMemberExpression chain inward.
  const parts = [];
  let cur = node;
  while (
    cur &&
    (cur.type === 'MemberExpression' || cur.type === 'OptionalMemberExpression')
  ) {
    let prop;
    if (cur.computed) {
      if (cur.property.type === 'NumericLiteral') prop = String(cur.property.value);
      else if (cur.property.type === 'StringLiteral') prop = cur.property.value;
      else prop = null; // dynamic – skip whole chain
    } else {
      prop = cur.property.name;
    }
    if (prop === null) return null;
    parts.unshift(prop);
    cur = cur.object;
  }
  if (!cur || cur.type !== 'Identifier') return null;
  return { rootName: cur.name, parts };
}

function walkAst(node, visit) {
  if (!node || typeof node !== 'object') return;
  visit(node);
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'range') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const c of child) walkAst(c, visit);
    } else if (child && typeof child === 'object' && child.type) {
      walkAst(child, visit);
    }
  }
}

function extractBabel(source) {
  let ast;
  try {
    ast = parser.parse(source, {
      sourceType: 'module',
      plugins: ['jsx', 'typescript', 'optionalChaining', 'nullishCoalescingOperator'],
      errorRecovery: true,
    });
  } catch (_) {
    return extractRegex(source); // fall through on parse error
  }

  // Pass 1: find useViewFetch / fetchView calls and their bound LHS.
  const viewBindings = []; // { view, bound }
  walkAst(ast, (n) => {
    if (n.type !== 'VariableDeclarator') return;
    const init = n.init;
    if (!init) return;
    let callee = null;
    let args = null;
    if (init.type === 'CallExpression') {
      callee = init.callee;
      args = init.arguments;
    } else if (init.type === 'AwaitExpression' && init.argument && init.argument.type === 'CallExpression') {
      callee = init.argument.callee;
      args = init.argument.arguments;
    }
    if (!callee || callee.type !== 'Identifier') return;
    if (callee.name !== 'useViewFetch' && callee.name !== 'fetchView') return;
    const first = args && args[0];
    if (!first || first.type !== 'StringLiteral') return;
    const view = first.value;

    let bound = null;
    if (n.id.type === 'Identifier') {
      bound = n.id.name;
    } else if (n.id.type === 'ObjectPattern') {
      for (const prop of n.id.properties) {
        if (prop.type !== 'ObjectProperty' && prop.type !== 'Property') continue;
        if (prop.key && prop.key.name === 'data') {
          if (prop.value && prop.value.type === 'Identifier') bound = prop.value.name;
          else bound = 'data';
          break;
        }
      }
    }
    if (bound) viewBindings.push({ view, bound });
  });

  if (viewBindings.length === 0) return [];

  // Pass 2: collect MemberExpression chains rooted at each bound var.
  const perBound = new Map(); // bound -> Set<path>
  for (const vb of viewBindings) perBound.set(vb.bound, new Set());

  walkAst(ast, (n) => {
    if (
      n.type !== 'MemberExpression' &&
      n.type !== 'OptionalMemberExpression'
    )
      return;
    const chain = memberChain(n);
    if (!chain) return;
    const set = perBound.get(chain.rootName);
    if (!set) return;
    if (chain.parts.length === 0) return;
    set.add(chain.parts.join('.'));
  });

  // Aggregate paths per view (multiple bindings for same view name merge).
  const byView = new Map();
  for (const { view, bound } of viewBindings) {
    if (!byView.has(view)) byView.set(view, new Set());
    const sink = byView.get(view);
    for (const p of perBound.get(bound) || []) sink.add(p);
  }
  return [...byView.entries()].map(([view, set]) => ({
    view,
    paths: [...set].sort(),
  }));
}

// ─────────────────────────────────────────────────────────────────────────────
// JNY-16: Bypass scanner (regex-only — no AST dependency on bypass paths).
// ─────────────────────────────────────────────────────────────────────────────
function normalizeBypassPath(raw, mode, prefix) {
  let p = raw.split('?')[0].replace(/\/+$/, '');
  if (mode === 'vulnFetch') {
    // vulnFetch('/api/v1/scans/{id}') → engine path is /api/v1/scans/{id}
    if (!p.startsWith('/')) p = '/' + p;
    if (!p.startsWith('/api/v1')) p = ('/api/v1/' + p.replace(/^\/+/, '')).replace(/\/$/, '');
  } else if (mode === 'strip-prefix') {
    if (p.startsWith(prefix)) p = p.slice(prefix.length);
  }
  // Collapse path-params: /scans/abc123 → /scans/{id}, /sbom/<uuid> → /sbom/{id}
  p = p.replace(/\/[0-9a-fA-F]{8,}\b/g, '/{id}')
       .replace(/\/\$\{[^}]+\}/g, '/{id}')
       .replace(/\/[a-zA-Z]+Id\b/g, '/{id}'); // template-literal artifact like /${scanId}
  return p;
}

function discoverAllJsxFiles() {
  const files = [];
  walk(FRONTEND_DIR, files, (f) => /\.(jsx?|tsx?)$/.test(f));
  return files;
}

function collectFieldsNearby(lines, lineIdx) {
  // Heuristic: if this line is `const X = await <bypassFetch>(...)`,
  // scan the next 60 lines for X.<field> accesses. Best-effort.
  const declRe = /(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*await\s+/;
  const declMatch = lines[lineIdx].match(declRe);
  const fields = new Set();
  if (!declMatch) return fields;
  if (declMatch[1]) {
    declMatch[1].split(',').forEach((part) => {
      const name = part.split(':')[0].trim();
      if (name && /^[a-zA-Z_]\w*$/.test(name)) fields.add(name);
    });
    return fields;
  }
  const varName = declMatch[2];
  const propRe = new RegExp(`\\b${varName}\\.(\\w+)`, 'g');
  const SKIP = new Set(['then', 'catch', 'finally', 'map', 'filter', 'forEach', 'length']);
  const horizon = Math.min(lines.length, lineIdx + 60);
  for (let i = lineIdx; i < horizon; i++) {
    let m;
    while ((m = propRe.exec(lines[i])) !== null) {
      if (!SKIP.has(m[1])) fields.add(m[1]);
    }
  }
  return fields;
}

function runBypassScanner(allFiles) {
  const result = {};
  for (const b of BYPASSES) result[b.name] = { prefix: b.prefix, routes: {} };

  for (const file of allFiles) {
    let src;
    try {
      src = fs.readFileSync(file, 'utf8');
    } catch (_) {
      continue;
    }
    const lines = src.split('\n');
    const rel = path.relative(REPO_ROOT, file);

    for (const bypass of BYPASSES) {
      for (const { re, normalize } of bypass.patterns) {
        const localRe = new RegExp(re.source, re.flags);
        let m;
        while ((m = localRe.exec(src)) !== null) {
          const raw = m[1];
          if (!raw) continue;
          const route = normalizeBypassPath(raw, normalize, bypass.prefix);
          if (!route || route === '/api/v1' || route === bypass.prefix) continue;
          const lineIdx = src.slice(0, m.index).split('\n').length - 1;
          const fields = collectFieldsNearby(lines, lineIdx);
          const bucket =
            result[bypass.name].routes[route] || { consumers: [], fields: [] };
          const consumer = `${rel}:${lineIdx + 1}`;
          if (!bucket.consumers.includes(consumer)) bucket.consumers.push(consumer);
          for (const f of fields) {
            if (!bucket.fields.includes(f)) bucket.fields.push(f);
          }
          result[bypass.name].routes[route] = bucket;
        }
      }
    }
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────
function main() {
  const t0 = Date.now();
  const files = discoverFiles();
  const out = {}; // view -> { files: Set, paths: Set }

  for (const file of files) {
    let src;
    try {
      src = fs.readFileSync(file, 'utf8');
    } catch (_) {
      continue;
    }
    if (!/useViewFetch|fetchView/.test(src)) continue;

    const extracted = mode === 'babel' ? extractBabel(src) : extractRegex(src);
    for (const { view, paths } of extracted) {
      if (!out[view]) out[view] = { files: new Set(), paths: new Set() };
      out[view].files.add(path.relative(REPO_ROOT, file));
      for (const p of paths) out[view].paths.add(p);
    }
  }

  const serialised = {};
  for (const [view, { files: fs2, paths }] of Object.entries(out)) {
    serialised[view] = {
      files: [...fs2].sort(),
      paths: [...paths].sort(),
    };
  }

  fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
  fs.writeFileSync(
    OUT_PATH,
    JSON.stringify(
      {
        _meta: {
          mode,
          generated_at: new Date().toISOString(),
          file_count: files.length,
          view_count: Object.keys(serialised).length,
          duration_ms: Date.now() - t0,
        },
        views: serialised,
      },
      null,
      2
    )
  );

  process.stderr.write(
    `extract-bff-fields: mode=${mode} files=${files.length} views=${Object.keys(serialised).length} ${Date.now() - t0}ms -> ${path.relative(REPO_ROOT, OUT_PATH)}\n`
  );

  // ── JNY-16: bypass scan (independent of BFF view scan) ──────────────────
  const tBypass = Date.now();
  const allJsx = discoverAllJsxFiles();
  const bypassResult = runBypassScanner(allJsx);
  fs.writeFileSync(
    BYPASS_OUT_PATH,
    JSON.stringify(
      {
        _meta: {
          generated_at: new Date().toISOString(),
          file_count: allJsx.length,
          bypass_count: Object.keys(bypassResult).length,
          duration_ms: Date.now() - tBypass,
        },
        bypasses: bypassResult,
      },
      null,
      2
    )
  );
  const summary = Object.entries(bypassResult)
    .map(([k, v]) => `${k}=${Object.keys(v.routes).length}`)
    .join(' ');
  process.stderr.write(
    `extract-bff-fields[bypass]: files=${allJsx.length} ${summary} ${Date.now() - tBypass}ms -> ${path.relative(REPO_ROOT, BYPASS_OUT_PATH)}\n`
  );
}

main();
