/**
 * Centralized URL resolution + entity registry for <PivotLink>.
 *
 * Single source of truth for entity-pivot routes across CSPM UI.
 * Consumers: components/shared/PivotLink.jsx, JNY-08 migration sweep.
 *
 * @see .claude/planning/stories/JNY-07_handoff_design.md §2
 */

import {
  Server,
  AlertTriangle,
  Shield,
  Crosshair,
  BookCheck,
  Book,
  Gauge,
  Box,
  ScanLine,
  Cpu,
  User,
} from 'lucide-react';

/**
 * Entity registry: icon + human label for each pivot target.
 * Keep keys identical to the `to` prop on <PivotLink>.
 */
export const ENTITY_REGISTRY = {
  asset:     { icon: Server,        label: 'Asset' },
  threat:    { icon: AlertTriangle, label: 'Threat' },
  finding:   { icon: Shield,        label: 'Finding' },
  technique: { icon: Crosshair,     label: 'Technique' },
  control:   { icon: BookCheck,     label: 'Control' },
  framework: { icon: Book,          label: 'Framework' },
  scenario:  { icon: Gauge,         label: 'Scenario' },
  workload:  { icon: Box,           label: 'Workload' },
  scan:      { icon: ScanLine,      label: 'Scan' },
  agent:     { icon: Cpu,           label: 'Agent' },
  identity:  { icon: User,          label: 'Identity' },
};

/** Targets that accept a `?provider=` query param. */
const PROVIDER_AWARE = new Set(['asset', 'finding', 'scan']);

/**
 * Resolve a pivot URL for the given entity descriptor.
 *
 * @param {Object}  args
 * @param {string}  args.to         Entity type (one of ENTITY_REGISTRY keys).
 * @param {string}  args.id         Entity id; URL-encoded internally.
 * @param {string} [args.engine]    Required when to='finding'.
 * @param {string} [args.framework] Required when to='control'.
 * @param {string} [args.provider]  Optional cloud provider; appended as ?provider=.
 * @param {string} [args.kind]      Optional sub-type for to='scan' (sast|dast|sca|project).
 * @returns {string|null} Resolved path, or null when required extras are missing
 *                        or `to` is unknown. Component falls back to plain text.
 */
export function resolvePivotUrl({ to, id, engine, framework, provider, kind } = {}) {
  if (!to || !id) return null;
  const eid = encodeURIComponent(id);

  let path;
  switch (to) {
    case 'asset':
      path = `/inventory/${eid}`;
      break;
    case 'threat':
      path = `/threats/${eid}`;
      break;
    case 'finding':
      if (!engine) return null;
      // CP-2 B4 closure: secops finding-detail unsupported in Phase B
      // (BFF returns 501 — see STORY-ENG-SECOPS-FINDING-TABLE).
      // Returning null causes PivotLink to render muted plain text instead
      // of a dead link the user could click.
      if (engine === 'secops') return null;
      path = `/finding/${encodeURIComponent(engine)}/${eid}`;
      break;
    case 'technique':
      path = `/threats/technique/${eid}`;
      break;
    case 'control':
      if (!framework) return null;
      path = `/compliance/${encodeURIComponent(framework)}/control/${eid}`;
      break;
    case 'framework':
      path = `/compliance/${eid}`;
      break;
    case 'scenario':
      path = `/risk/scenario/${eid}`;
      break;
    case 'workload':
      path = `/cwpp/workload/${eid}`;
      break;
    case 'scan': {
      const k = (kind || 'sast').toLowerCase();
      if (k === 'dast')        path = `/secops/dast/${eid}`;
      else if (k === 'sca')    path = `/secops/sca/${eid}`;
      else if (k === 'project') path = `/secops/projects/${eid}`;
      else                      path = `/secops/${eid}`;
      break;
    }
    case 'agent':
      path = `/vulnerability/agents/${eid}`;
      break;
    case 'identity':
      path = `/cdr/identity/${eid}`;
      break;
    default:
      return null;
  }

  if (provider && PROVIDER_AWARE.has(to)) {
    path += `?provider=${encodeURIComponent(provider)}`;
  }
  return path;
}
