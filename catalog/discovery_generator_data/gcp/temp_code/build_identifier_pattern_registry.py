#!/usr/bin/env python3
"""
Build GCP Identifier Pattern Registry from step5 resource catalogs.

PURPOSE:
  Derive a registry that maps canonical GCP resource path patterns
  (like "projects/*/locations/*/keyRings/*/cryptoKeys/*") to their
  generic_node_type, service, and resource_type.

  This enables auto-detection of resource references in field values:
  e.g. if a field contains "projects/my-proj/zones/us-east1-b/instances/my-vm",
  you can look up the pattern to know it references a compute.instance.

INPUT:
  gcp_resource_taxonomy.json        — taxonomy mappings (classification per resource)
  step5_resource_catalog_inventory_enrich.json  — per-service identifier templates

OUTPUT (written to BASE_DIR):
  gcp_identifier_pattern_registry.json  — {
    "version": "1.0",
    "generated_at": "...",
    "patterns": [
      {
        "glob_pattern":       "projects/*/locations/*/keyRings/*/cryptoKeys/*",
        "regex_pattern":      "^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$",
        "provider":           "gcp",
        "service":            "cloudkms",
        "resource_type":      "cryptoKeys",
        "generic_node_type":  "crypto.kmsKey",
        "category":           "crypto",
        "identifier_kind":    "gcp_full_name",
        "example_template":   "projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}",
        "named_parts":        ["project", "location", "keyRing", "cryptoKey"],
        "confidence":         0.97,
        "notes":              ""
      },
      ...
    ]
  }

CLI:
  python build_identifier_pattern_registry.py
  python build_identifier_pattern_registry.py --base /path/to/gcp
"""

import json
import re
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

BASE_DIR = Path('/Users/apple/Desktop/data_pythonsdk/gcp')


# ─────────────────────────────────────────────────────────────────────────────
# WELL-KNOWN PATTERNS
# Hand-authored patterns for resources whose step5 templates are "{name}"
# (the full path is passed as the `name` param at runtime) or where the
# canonical pattern can be derived from GCP documentation.
# ─────────────────────────────────────────────────────────────────────────────

_WELL_KNOWN_PATTERNS = [
    # ── Cloud KMS ───────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/locations/{location}/keyRings/{keyRing}',
        'provider': 'gcp', 'service': 'cloudkms', 'resource_type': 'keyRings',
        'generic_node_type': 'crypto.keyRing', 'category': 'crypto',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}',
        'provider': 'gcp', 'service': 'cloudkms', 'resource_type': 'cryptoKeys',
        'generic_node_type': 'crypto.kmsKey', 'category': 'crypto',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}/cryptoKeyVersions/{cryptoKeyVersion}',
        'provider': 'gcp', 'service': 'cloudkms', 'resource_type': 'cryptoKeyVersions',
        'generic_node_type': 'crypto.kmsKeyVersion', 'category': 'crypto',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/locations/{location}/ekmConnections/{ekmConnection}',
        'provider': 'gcp', 'service': 'cloudkms', 'resource_type': 'ekmConnections',
        'generic_node_type': 'crypto.ekmConnection', 'category': 'crypto',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.95,
        'notes': 'well_known_pattern',
    },
    # ── Secret Manager ───────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/secrets/{secret}',
        'provider': 'gcp', 'service': 'secretmanager', 'resource_type': 'secrets',
        'generic_node_type': 'crypto.secret', 'category': 'crypto',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/secrets/{secret}/versions/{version}',
        'provider': 'gcp', 'service': 'secretmanager', 'resource_type': 'versions',
        'generic_node_type': 'crypto.secret', 'category': 'crypto',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.95,
        'notes': 'well_known_pattern',
    },
    # ── GKE / Container ─────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/locations/{location}/clusters/{cluster}',
        'provider': 'gcp', 'service': 'container', 'resource_type': 'clusters',
        'generic_node_type': 'k8s.cluster', 'category': 'kubernetes',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/locations/{location}/clusters/{cluster}/nodePools/{nodePool}',
        'provider': 'gcp', 'service': 'container', 'resource_type': 'nodePools',
        'generic_node_type': 'k8s.nodePool', 'category': 'kubernetes',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── GKE Hub ─────────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/locations/{location}/memberships/{membership}',
        'provider': 'gcp', 'service': 'gkehub', 'resource_type': 'memberships',
        'generic_node_type': 'k8s.hubMembership', 'category': 'kubernetes',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.95,
        'notes': 'well_known_pattern',
    },
    # ── IAM ─────────────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/serviceAccounts/{serviceAccount}',
        'provider': 'gcp', 'service': 'iam', 'resource_type': 'serviceAccounts',
        'generic_node_type': 'identity.serviceAccount', 'category': 'identity',
        'identifier_kind': 'email', 'confidence': 0.97,
        'notes': 'well_known_pattern; serviceAccount is the SA email address',
    },
    {
        'canonical_template': 'projects/{project}/serviceAccounts/{serviceAccount}/keys/{key}',
        'provider': 'gcp', 'service': 'iam', 'resource_type': 'keys',
        'generic_node_type': 'identity.serviceAccountKey', 'category': 'identity',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.95,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/locations/{location}/workloadIdentityPools/{pool}',
        'provider': 'gcp', 'service': 'iam', 'resource_type': 'workloadIdentityPools',
        'generic_node_type': 'identity.workloadIdentityPool', 'category': 'identity',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'locations/{location}/workforcePools/{pool}',
        'provider': 'gcp', 'service': 'iam', 'resource_type': 'workforcePools',
        'generic_node_type': 'identity.workforcePool', 'category': 'identity',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── Access Context Manager ───────────────────────────────────────────────
    {
        'canonical_template': 'accessPolicies/{accessPolicy}',
        'provider': 'gcp', 'service': 'accesscontextmanager', 'resource_type': 'accessPolicies',
        'generic_node_type': 'access.policy', 'category': 'access',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.95,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'accessPolicies/{accessPolicy}/accessLevels/{accessLevel}',
        'provider': 'gcp', 'service': 'accesscontextmanager', 'resource_type': 'accessLevels',
        'generic_node_type': 'access.accessLevel', 'category': 'access',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'accessPolicies/{accessPolicy}/servicePerimeters/{servicePerimeter}',
        'provider': 'gcp', 'service': 'accesscontextmanager', 'resource_type': 'servicePerimeters',
        'generic_node_type': 'access.servicePerimeter', 'category': 'access',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── Cloud Resource Manager ───────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}',
        'provider': 'gcp', 'service': 'cloudresourcemanager', 'resource_type': 'projects',
        'generic_node_type': 'governance.project', 'category': 'governance',
        'identifier_kind': 'raw_id', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'folders/{folder}',
        'provider': 'gcp', 'service': 'cloudresourcemanager', 'resource_type': 'folders',
        'generic_node_type': 'governance.folder', 'category': 'governance',
        'identifier_kind': 'raw_id', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'organizations/{organization}',
        'provider': 'gcp', 'service': 'cloudresourcemanager', 'resource_type': 'organizations',
        'generic_node_type': 'governance.organization', 'category': 'governance',
        'identifier_kind': 'raw_id', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── Pub/Sub ─────────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/topics/{topic}',
        'provider': 'gcp', 'service': 'pubsub', 'resource_type': 'topics',
        'generic_node_type': 'messaging.topic', 'category': 'messaging',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/subscriptions/{subscription}',
        'provider': 'gcp', 'service': 'pubsub', 'resource_type': 'subscriptions',
        'generic_node_type': 'messaging.subscription', 'category': 'messaging',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── Cloud Logging ────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/sinks/{sink}',
        'provider': 'gcp', 'service': 'logging', 'resource_type': 'sinks',
        'generic_node_type': 'observability.logSink', 'category': 'observability',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/locations/{location}/buckets/{bucket}',
        'provider': 'gcp', 'service': 'logging', 'resource_type': 'buckets',
        'generic_node_type': 'observability.logBucket', 'category': 'observability',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── Cloud Run ────────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/locations/{location}/services/{service}',
        'provider': 'gcp', 'service': 'run', 'resource_type': 'services',
        'generic_node_type': 'app.cloudRunService', 'category': 'app',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/locations/{location}/jobs/{job}',
        'provider': 'gcp', 'service': 'run', 'resource_type': 'jobs',
        'generic_node_type': 'app.cloudRunService', 'category': 'app',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.95,
        'notes': 'well_known_pattern',
    },
    # ── Cloud SQL ────────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/instances/{instance}',
        'provider': 'gcp', 'service': 'sqladmin', 'resource_type': 'instances',
        'generic_node_type': 'data.sqlInstance', 'category': 'data',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── Cloud Storage ────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/buckets/{bucket}',
        'provider': 'gcp', 'service': 'storage', 'resource_type': 'buckets',
        'generic_node_type': 'storage.bucket', 'category': 'storage',
        'identifier_kind': 'raw_id', 'confidence': 0.97,
        'notes': 'well_known_pattern; bucket name is globally unique',
    },
    # ── BigQuery ─────────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/datasets/{dataset}',
        'provider': 'gcp', 'service': 'bigquery', 'resource_type': 'datasets',
        'generic_node_type': 'data.bigqueryDataset', 'category': 'data',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/datasets/{dataset}/tables/{table}',
        'provider': 'gcp', 'service': 'bigquery', 'resource_type': 'tables',
        'generic_node_type': 'data.bigqueryDataset', 'category': 'data',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.95,
        'notes': 'well_known_pattern',
    },
    # ── Private CA ───────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/locations/{location}/caPools/{caPool}',
        'provider': 'gcp', 'service': 'privateca', 'resource_type': 'caPools',
        'generic_node_type': 'cert.certificateAuthority', 'category': 'cert',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/locations/{location}/caPools/{caPool}/certificateAuthorities/{certificateAuthority}',
        'provider': 'gcp', 'service': 'privateca', 'resource_type': 'certificateAuthorities',
        'generic_node_type': 'cert.certificateAuthority', 'category': 'cert',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── Certificate Manager ──────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/locations/{location}/certificates/{certificate}',
        'provider': 'gcp', 'service': 'certificatemanager', 'resource_type': 'certificates',
        'generic_node_type': 'cert.certificate', 'category': 'cert',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── Artifact Registry ────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/locations/{location}/repositories/{repository}',
        'provider': 'gcp', 'service': 'artifactregistry', 'resource_type': 'repositories',
        'generic_node_type': 'devops.artifactRepo', 'category': 'devops',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── Cloud Spanner ────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/instances/{instance}',
        'provider': 'gcp', 'service': 'spanner', 'resource_type': 'instances',
        'generic_node_type': 'data.spannerInstance', 'category': 'data',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern; same pattern as sqladmin — distinguish by context',
    },
    # ── Monitoring ───────────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/alertPolicies/{alertPolicy}',
        'provider': 'gcp', 'service': 'monitoring', 'resource_type': 'alertPolicies',
        'generic_node_type': 'observability.alertPolicy', 'category': 'observability',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    {
        'canonical_template': 'projects/{project}/dashboards/{dashboard}',
        'provider': 'gcp', 'service': 'monitoring', 'resource_type': 'dashboards',
        'generic_node_type': 'observability.dashboard', 'category': 'observability',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
    # ── Cloud Functions ──────────────────────────────────────────────────────
    {
        'canonical_template': 'projects/{project}/locations/{location}/functions/{function}',
        'provider': 'gcp', 'service': 'cloudfunctions', 'resource_type': 'functions',
        'generic_node_type': 'app.cloudFunction', 'category': 'app',
        'identifier_kind': 'gcp_full_name', 'confidence': 0.97,
        'notes': 'well_known_pattern',
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_ANCHOR_VARIABLE_PREFIXES = {
    # When a template starts with one of these variable names, prepend the
    # corresponding literal path segment to form the canonical GCP resource name.
    # e.g. template "{project}/zones/{zone}/instances/{instance}"
    #      → canonical "projects/{project}/zones/{zone}/instances/{instance}"
    'project':      'projects',
    'projectid':    'projects',
    'projectname':  'projects',
    'organization': 'organizations',
    'org':          'organizations',
    'folder':       'folders',
    'parent':       None,   # skip — too ambiguous
}


def _canonicalize_template(template: str) -> str:
    """
    Convert a raw step5 identifier template to a canonical GCP resource name template.

    GCP templates in step5 catalogs store paths like:
      {project}/zones/{zone}/instances/{instance}

    The canonical full resource name used in Cloud Asset Inventory etc. is:
      projects/{project}/zones/{zone}/instances/{instance}

    This function prepends the correct segment label before the first variable
    if needed.
    """
    t = template.strip().lstrip('/')
    # Normalize {+var} / {*var} → {var}
    t = re.sub(r'\{[+*]?(\w+)\}', r'{\1}', t)

    segments = t.split('/')
    if not segments:
        return t

    first_seg = segments[0]
    # Check if first segment is a bare variable like {project}
    m = re.match(r'^\{(\w+)\}$', first_seg)
    if m:
        var_name = m.group(1).lower()
        prefix = _ANCHOR_VARIABLE_PREFIXES.get(var_name)
        if prefix is not None:
            # Prepend the literal prefix segment
            t = prefix + '/' + t
    return t


def _template_to_glob(template: str) -> Optional[str]:
    """
    Convert a full_identifier template to a glob pattern.
    e.g. "{project}/zones/{zone}/instances/{instance}"
         → "projects/*/zones/*/instances/*"

    Returns None if the template cannot produce a meaningful pattern.
    """
    if not template or template.strip() in ('', '{name}', '{+name}'):
        return None

    t = _canonicalize_template(template)

    # Replace every {var} with *
    glob = re.sub(r'\{[^}]+\}', '*', t)

    # A useful pattern must have at least one literal segment (non-wildcard)
    segments = glob.split('/')
    literal_segments = [s for s in segments if s != '*']
    if not literal_segments:
        return None
    # Pattern must have at least 2 segments total to be useful
    if len(segments) < 2:
        return None

    return glob


def _template_to_regex(template: str) -> Optional[str]:
    """
    Convert a full_identifier template to an anchored regex.
    e.g. "{project}/zones/{zone}/instances/{instance}"
         → "^projects/[^/]+/zones/[^/]+/instances/[^/]+$"
    """
    if not template or template.strip() in ('', '{name}', '{+name}'):
        return None

    t = _canonicalize_template(template)

    # Escape literal parts, replace variables with [^/]+
    parts = []
    for segment in t.split('/'):
        if re.match(r'^\{[^}]+\}$', segment):
            parts.append('[^/]+')
        else:
            parts.append(re.escape(segment))

    if len(parts) < 2:
        return None

    return '^' + '/'.join(parts) + '$'


def _extract_named_parts(template: str) -> list:
    """Extract variable names from a canonicalized template in order."""
    t = _canonicalize_template(template)
    return re.findall(r'\{(\w+)\}', t)


_API_VERSION_PREFIX = re.compile(
    r'^/?(?:v\d+[a-z0-9]*|alpha|beta|alpha\d*|beta\d*)/'
)

_KNOWN_GCP_PATH_ANCHORS = {
    'projects', 'locations', 'zones', 'regions', 'organizations', 'folders',
    'global', 'aggregated',
}


def _is_useful_template(template: str, kind: str) -> bool:
    """
    Filter out degenerate templates that won't produce useful path patterns.

    Rules:
    - Must be a full_name identifier
    - Must not be a bare single-variable template like "{name}"
    - Must not start with an API version prefix (v1/, v1beta3/, alpha/, etc.)
      because those are raw HTTP paths not canonical resource names
    - Must start with a known GCP resource hierarchy anchor OR use the
      standard GCP resource name format (projects/... etc.)
    - Must have at least one literal path segment
    """
    if not template:
        return False
    if kind != 'full_name':
        return False

    stripped = template.strip()

    # Single variable only like "{name}" or "{+name}" — not useful
    if re.match(r'^\{[+*]?\w+\}$', stripped):
        return False

    # Strip leading slash for analysis
    t = stripped.lstrip('/')

    # Reject templates that start with an HTTP API version prefix
    # e.g. "v1/projects/...", "v1beta3/histories/...", "alpha/projects/..."
    if _API_VERSION_PREFIX.match(t):
        return False

    # Split into segments, identify first literal segment
    segments = t.split('/')
    literal_segs = [s for s in segments if not re.match(r'^\{[^}]+\}$', s)]

    if not literal_segs:
        return False

    first_literal = literal_segs[0].lower()

    # Prefer templates rooted at known GCP hierarchy anchors
    # This catches "projects/.../...", "organizations/...", "folders/..." etc.
    # Also allow templates where first segment is a service-specific resource type
    # as long as they have 2+ segments total
    if len(segments) < 2:
        return False

    return True


# ─────────────────────────────────────────────────────────────────────────────
# MAIN BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def build_pattern_registry(base_dir: Path) -> dict:
    """
    Read all step5 catalogs + taxonomy, produce identifier pattern registry.
    """
    # Load taxonomy for classification lookup
    tax_path = base_dir / 'gcp_resource_taxonomy.json'
    taxonomy_by_key: dict = {}
    if tax_path.exists():
        tax = json.load(open(tax_path))
        for m in tax.get('mappings', []):
            key = (m['service'], m['resource_type'])
            taxonomy_by_key[key] = m

    # Collect all catalog files
    catalog_files = sorted(base_dir.rglob('step5_resource_catalog_inventory_enrich.json'))

    # Pattern dedup: glob_pattern → entry (keep highest-confidence entry)
    patterns_by_glob: dict = {}

    for cat_path in catalog_files:
        try:
            doc = json.load(open(cat_path))
        except Exception:
            continue

        for svc_name, svc_data in doc.get('services', {}).items():
            for rtype, rdata in sorted(svc_data.get('resources', {}).items()):
                identifier = rdata.get('identifier', {})
                kind = identifier.get('kind', 'tuple')
                full_id = identifier.get('full_identifier', {})
                template = full_id.get('template', '')

                if not _is_useful_template(template, kind):
                    continue

                canonical = _canonicalize_template(template)
                glob_pat  = _template_to_glob(template)
                regex_pat = _template_to_regex(template)
                named_parts = _extract_named_parts(template)

                if not glob_pat or not regex_pat:
                    continue

                # Look up taxonomy classification
                tax_entry = taxonomy_by_key.get((svc_name, rtype), {})
                generic_node_type = tax_entry.get('generic_node_type', 'other.unknown')
                category          = tax_entry.get('category', 'other')
                confidence        = tax_entry.get('confidence', 0.5)
                notes             = tax_entry.get('notes', '')

                # Skip consumer/non-infrastructure resources (they clutter the registry
                # and reduce pattern matching precision for GCP infra resources)
                if generic_node_type == 'other.unknown' and confidence < 0.6:
                    continue

                entry = {
                    'glob_pattern':       glob_pat,
                    'regex_pattern':      regex_pat,
                    'provider':           'gcp',
                    'service':            svc_name,
                    'resource_type':      rtype,
                    'generic_node_type':  generic_node_type,
                    'category':           category,
                    'identifier_kind':    kind,
                    'canonical_template': canonical,
                    'raw_template':       template,
                    'named_parts':        named_parts,
                    'confidence':         confidence,
                    'notes':              notes,
                }

                # Dedup by glob_pattern: keep highest confidence, or prefer
                # the entry with longer (more specific) template
                existing = patterns_by_glob.get(glob_pat)
                if existing is None:
                    patterns_by_glob[glob_pat] = entry
                else:
                    existing_specificity = len(existing['named_parts'])
                    new_specificity      = len(named_parts)
                    # Prefer more specific template (more named parts)
                    if new_specificity > existing_specificity:
                        patterns_by_glob[glob_pat] = entry
                    elif (new_specificity == existing_specificity
                          and confidence > existing['confidence']):
                        patterns_by_glob[glob_pat] = entry

    # Merge in well-known patterns (they take priority for their glob if same glob exists)
    for wk in _WELL_KNOWN_PATTERNS:
        template = wk['canonical_template']
        glob_pat  = _template_to_glob(template)
        regex_pat = _template_to_regex(template)
        named_parts = _extract_named_parts(template)

        if not glob_pat or not regex_pat:
            continue

        entry = {
            'glob_pattern':       glob_pat,
            'regex_pattern':      regex_pat,
            'provider':           wk.get('provider', 'gcp'),
            'service':            wk['service'],
            'resource_type':      wk['resource_type'],
            'generic_node_type':  wk['generic_node_type'],
            'category':           wk['category'],
            'identifier_kind':    wk.get('identifier_kind', 'gcp_full_name'),
            'canonical_template': template,
            'raw_template':       template,
            'named_parts':        named_parts,
            'confidence':         wk.get('confidence', 0.90),
            'notes':              wk.get('notes', 'well_known_pattern'),
        }

        existing = patterns_by_glob.get(glob_pat)
        if existing is None or wk.get('notes', '').startswith('well_known'):
            # Well-known patterns always win (they're authored, not derived)
            patterns_by_glob[glob_pat] = entry

    # Sort patterns by specificity (more segments first = more specific = earlier match)
    all_patterns = sorted(
        patterns_by_glob.values(),
        key=lambda p: (
            -len(p['glob_pattern'].split('/')),   # more segments → earlier
            -p['confidence'],
            p['glob_pattern'],
        )
    )

    return {
        'version':      '1.0',
        'generated_at': _now_iso(),
        'description':  (
            'Maps GCP resource path patterns to their node type. '
            'Use regex_pattern for matching field values. '
            'Patterns are sorted most-specific first.'
        ),
        'usage': {
            'field_matching': (
                'For each field value in a discovered resource, '
                'iterate patterns in order and apply regex_pattern. '
                'First match gives you the target generic_node_type.'
            ),
            'example': (
                'Field value "projects/my-proj/zones/us-east1-b/instances/my-vm" '
                'matches pattern "^projects/[^/]+/zones/[^/]+/instances/[^/]+$" '
                '→ generic_node_type = "compute.instance"'
            ),
        },
        'patterns': all_patterns,
    }


# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

def _print_summary(registry: dict):
    patterns = registry['patterns']
    total    = len(patterns)

    # Count by category
    by_cat: dict = {}
    for p in patterns:
        cat = p['category']
        by_cat[cat] = by_cat.get(cat, 0) + 1

    # Count by identifier kind
    by_kind: dict = {}
    for p in patterns:
        k = p['identifier_kind']
        by_kind[k] = by_kind.get(k, 0) + 1

    # Count by segment depth
    depths: dict = {}
    for p in patterns:
        d = len(p['glob_pattern'].split('/'))
        depths[d] = depths.get(d, 0) + 1

    print('=' * 70)
    print('GCP IDENTIFIER PATTERN REGISTRY BUILD SUMMARY')
    print('=' * 70)
    print(f'  Total patterns   : {total}')
    print()
    print('  By category:')
    for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f'    {cat:<22} {cnt:4d}')
    print()
    print('  By identifier kind:')
    for k, cnt in sorted(by_kind.items(), key=lambda x: -x[1]):
        print(f'    {k:<22} {cnt:4d}')
    print()
    print('  By segment depth (number of path parts):')
    for d in sorted(depths.keys()):
        print(f'    depth {d:2d}: {depths[d]:4d} patterns')
    print()
    print('  Sample patterns (most specific first):')
    for p in patterns[:10]:
        print(f'    {p["glob_pattern"]:<60} → {p["generic_node_type"]}')
    print('=' * 70)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Build GCP Identifier Pattern Registry from step5 catalogs'
    )
    parser.add_argument('--base', type=Path, default=BASE_DIR,
                        help=f'Base GCP data directory (default: {BASE_DIR})')
    parser.add_argument('--out', type=Path, default=None,
                        help='Output JSON path (default: <base>/gcp_identifier_pattern_registry.json)')
    args = parser.parse_args()

    base     = args.base
    out_path = args.out or base / 'gcp_identifier_pattern_registry.json'

    print('Building GCP identifier pattern registry...')
    registry = build_pattern_registry(base)

    with open(out_path, 'w') as f:
        json.dump(registry, f, indent=2)
    print(f'  Written: {out_path}')

    _print_summary(registry)


if __name__ == '__main__':
    main()
