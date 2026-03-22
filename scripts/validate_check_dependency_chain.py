#!/usr/bin/env python3
"""
Validate Complete Check Dependency Chain

This script validates:
1. All operations referenced in checks exist in discoveries
2. All fields in check conditions exist in discovery emit schemas
3. Complete dependency chains are valid (transitive dependencies)
4. Variables, operators, and fields align with rule requirements

Usage:
    python3 validate_check_dependency_chain.py [--csp aws|azure|all] [--export-csv errors.csv]
"""

import os
import sys
import json
import psycopg2
from psycopg2.extras import RealDictCursor
import argparse
from collections import defaultdict
import csv
from typing import Dict, List, Set, Optional, Tuple

DB_CONFIG = {
    'host': 'postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com',
    'port': 5432,
    'database': 'threat_engine_check',
    'user': 'postgres',
    'password': 'jtv2BkJF8qoFtAKP'
}

VALID_OPERATORS = {
    'equals', 'not_equals', 'eq', 'ne',
    'greater_than', 'less_than', 'gte', 'lte', 'gt', 'lt',
    'exists', 'not_exists',
    'contains', 'not_contains', 'starts_with', 'ends_with',
    'regex', 'not_regex',
    'in', 'not_in', 'contains_all', 'contains_any',
    'all', 'any', 'not', 'none',
    'is_null', 'is_not_null', 'is_empty', 'is_not_empty',
    'length_equals', 'length_greater_than', 'length_less_than'
}


class DependencyChainValidator:
    def __init__(self):
        self.total_checks = 0
        self.valid_checks = 0
        self.errors = []
        self.warnings = []
        self.service_stats = defaultdict(lambda: {'total': 0, 'valid': 0, 'errors': []})

        # Cache for discovery data
        self.discovery_cache = {}
        self.dependency_graph = {}

    def add_error(self, service: str, rule_id: str, error_type: str, error: str):
        """Add validation error"""
        error_entry = {
            'service': service,
            'rule_id': rule_id,
            'error_type': error_type,
            'error': error
        }
        self.errors.append(error_entry)
        self.service_stats[service]['errors'].append(error_entry)

    def add_warning(self, service: str, rule_id: str, warning: str):
        """Add validation warning"""
        self.warnings.append({
            'service': service,
            'rule_id': rule_id,
            'warning': warning
        })

    def load_discovery_configs(self, conn, csp: str):
        """Load all discovery configurations for a CSP"""
        print(f"Loading discovery configurations for {csp.upper()}...")

        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT service, discoveries_data
                FROM rule_discoveries
                WHERE provider = %s
            """, (csp,))

            for row in cur.fetchall():
                service = row['service']
                data = row['discoveries_data']
                if isinstance(data, str):
                    data = json.loads(data)
                self.discovery_cache[service] = data

                # Build dependency graph
                self._build_dependency_graph(service, data)

        print(f"  ✅ Loaded {len(self.discovery_cache)} discovery configs")

    def _build_dependency_graph(self, service: str, discovery_data: Dict):
        """Build dependency graph for discovery operations"""
        discoveries = discovery_data.get('discovery', [])

        for disc in discoveries:
            disc_id = disc.get('discovery_id')
            if not disc_id:
                continue

            self.dependency_graph[disc_id] = {
                'service': service,
                'depends_on': disc.get('for_each'),
                'emit_fields': self._extract_emit_fields(disc),
                'emit_item_fields': self._extract_emit_item_fields(disc)
            }

    def _extract_emit_fields(self, discovery: Dict) -> Set[str]:
        """Extract fields from discovery emit configuration"""
        fields = set()
        emit = discovery.get('emit', {})

        # Get items_for field
        items_for = emit.get('items_for', '')
        if items_for and '{{' in items_for:
            # Extract field name from {{ response.FieldName }}
            import re
            match = re.search(r'response\.(\w+)', items_for)
            if match:
                fields.add(match.group(1))

        return fields

    def _extract_emit_item_fields(self, discovery: Dict) -> Set[str]:
        """Extract item fields from discovery emit.item configuration"""
        fields = set()
        emit = discovery.get('emit', {})
        item = emit.get('item', {})

        if isinstance(item, dict):
            fields = set(item.keys())

        return fields

    def get_all_dependencies(self, discovery_id: str, visited: Set[str] = None) -> List[str]:
        """Get complete dependency chain for a discovery operation"""
        if visited is None:
            visited = set()

        if discovery_id in visited:
            return []  # Circular dependency

        visited.add(discovery_id)
        chain = [discovery_id]

        if discovery_id in self.dependency_graph:
            depends_on = self.dependency_graph[discovery_id]['depends_on']
            if depends_on:
                chain.extend(self.get_all_dependencies(depends_on, visited))

        return chain

    def extract_field_references(self, conditions: Dict) -> Set[str]:
        """Extract all field references from check conditions"""
        fields = set()

        def extract_fields(obj):
            if isinstance(obj, dict):
                # Check 'var' field
                if 'var' in obj:
                    var = obj['var']
                    if isinstance(var, str):
                        fields.add(var)

                # Recursively check nested objects
                for value in obj.values():
                    extract_fields(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_fields(item)

        extract_fields(conditions)
        return fields

    def extract_discovery_references(self, check_config: Dict) -> Set[str]:
        """Extract all discovery operation references from check"""
        refs = set()

        def extract_refs(obj):
            if isinstance(obj, dict):
                if 'for_each' in obj:
                    refs.add(obj['for_each'])
                if 'discovery_id' in obj:
                    refs.add(obj['discovery_id'])
                for value in obj.values():
                    extract_refs(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_refs(item)

        extract_refs(check_config)
        return refs

    def validate_dependency_chain(self, service: str, rule_id: str, discovery_refs: Set[str]) -> bool:
        """Validate complete dependency chain exists"""
        valid = True

        for disc_ref in discovery_refs:
            # Check if discovery exists
            if disc_ref not in self.dependency_graph:
                self.add_error(service, rule_id, 'missing_discovery',
                             f"Discovery operation '{disc_ref}' not found")
                valid = False
                continue

            # Check complete dependency chain
            chain = self.get_all_dependencies(disc_ref)
            for dep_id in chain:
                if dep_id not in self.dependency_graph:
                    self.add_error(service, rule_id, 'broken_chain',
                                 f"Dependency chain broken: '{dep_id}' not found (required by '{disc_ref}')")
                    valid = False

        return valid

    def validate_field_availability(self, service: str, rule_id: str,
                                   discovery_ref: str, field_refs: Set[str]) -> bool:
        """Validate that fields are available in discovery emit or dependency chain"""
        valid = True

        if discovery_ref not in self.dependency_graph:
            return False  # Already reported as missing discovery

        # Get complete dependency chain
        chain = self.get_all_dependencies(discovery_ref)

        # Collect all available fields from entire chain
        available_fields = set()
        for dep_id in chain:
            if dep_id in self.dependency_graph:
                dep_data = self.dependency_graph[dep_id]
                available_fields.update(dep_data['emit_fields'])
                available_fields.update(dep_data['emit_item_fields'])

        # Validate each field reference
        for field_ref in field_refs:
            # Parse field reference (item.FieldName -> FieldName)
            if '.' in field_ref:
                parts = field_ref.split('.')
                if len(parts) == 2 and parts[0] == 'item':
                    field_name = parts[1]
                else:
                    field_name = parts[-1]
            else:
                field_name = field_ref

            # Skip 'item' itself and 'response'
            if field_name in ['item', 'response']:
                continue

            if field_name not in available_fields and available_fields:
                self.add_error(service, rule_id, 'field_not_emitted',
                             f"Field '{field_name}' not found in emit schema for '{discovery_ref}'. "
                             f"Available: {', '.join(sorted(available_fields))}")
                valid = False

        return valid

    def validate_operators(self, service: str, rule_id: str, conditions: Dict) -> bool:
        """Validate operators are valid"""
        valid = True

        def check_operators(obj, path="conditions"):
            nonlocal valid
            if isinstance(obj, dict):
                if 'op' in obj:
                    op = obj['op']
                    if op not in VALID_OPERATORS:
                        self.add_error(service, rule_id, 'invalid_operator',
                                     f"Invalid operator '{op}' at {path}")
                        valid = False

                for key, value in obj.items():
                    check_operators(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    check_operators(item, f"{path}[{idx}]")

        check_operators(conditions)
        return valid

    def validate_check(self, check: Dict) -> bool:
        """Validate a single check completely"""
        service = check['service']
        rule_id = check['rule_id']
        check_config = check['check_config']

        self.total_checks += 1
        self.service_stats[service]['total'] += 1

        # Parse check_config if string
        if isinstance(check_config, str):
            try:
                check_config = eval(check_config)
            except Exception as e:
                self.add_error(service, rule_id, 'parse_error',
                             f"Failed to parse check_config: {e}")
                return False

        valid = True

        # Extract discovery references
        discovery_refs = self.extract_discovery_references(check_config)

        # Validate dependency chains exist
        if discovery_refs:
            chain_valid = self.validate_dependency_chain(service, rule_id, discovery_refs)
            valid = valid and chain_valid
        else:
            self.add_warning(service, rule_id, "No discovery references found")

        # Validate operators
        conditions = check_config.get('conditions', {})
        if conditions:
            op_valid = self.validate_operators(service, rule_id, conditions)
            valid = valid and op_valid

            # Extract field references
            field_refs = self.extract_field_references(conditions)

            # Validate fields exist in discovery emit for each discovery reference
            for_each = check_config.get('for_each')
            if for_each and for_each in self.dependency_graph:
                field_valid = self.validate_field_availability(service, rule_id, for_each, field_refs)
                valid = valid and field_valid

        if valid:
            self.valid_checks += 1
            self.service_stats[service]['valid'] += 1

        return valid

    def print_summary(self):
        """Print validation summary"""
        print(f"\n{'='*80}")
        print("Dependency Chain Validation Summary")
        print(f"{'='*80}")
        print(f"Total Checks: {self.total_checks}")
        print(f"Valid Checks: {self.valid_checks} ({self.valid_checks/self.total_checks*100:.1f}%)")
        print(f"Errors: {len(self.errors)}")
        print(f"Warnings: {len(self.warnings)}")

        if self.errors:
            print(f"\n❌ Error Breakdown:")
            error_types = defaultdict(int)
            for err in self.errors:
                error_types[err['error_type']] += 1
            for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
                print(f"  {error_type}: {count}")

            print(f"\n❌ Top 10 Services with Errors:")
            service_errors = defaultdict(int)
            for err in self.errors:
                service_errors[err['service']] += 1
            for service, count in sorted(service_errors.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {service}: {count} errors")


def validate_csp(csp: str, verbose: bool = False) -> DependencyChainValidator:
    """Validate all checks for a CSP"""
    print(f"\n{'='*80}")
    print(f"Validating {csp.upper()} Check Dependency Chains")
    print(f"{'='*80}")

    validator = DependencyChainValidator()
    conn = psycopg2.connect(**DB_CONFIG)

    try:
        # Load discovery configurations
        validator.load_discovery_configs(conn, csp)

        # Load checks
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT rule_id, service, provider, check_config, is_active
                FROM rule_checks
                WHERE provider = %s AND is_active = TRUE
                ORDER BY service, rule_id
            """, (csp,))

            checks = cur.fetchall()

        print(f"Loaded {len(checks)} active checks\n")

        # Validate each check
        print("Validating checks...")
        for idx, check in enumerate(checks):
            if verbose:
                print(f"  [{idx+1}/{len(checks)}] {check['service']}.{check['rule_id']}")

            validator.validate_check(check)

            if not verbose and (idx + 1) % 100 == 0:
                print(f"  Processed {idx+1}/{len(checks)} checks...")

    finally:
        conn.close()

    return validator


def export_errors_to_csv(results: Dict, output_file: str):
    """Export validation errors to CSV"""
    print(f"\nExporting errors to {output_file}...")

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['CSP', 'Service', 'Rule ID', 'Error Type', 'Error'])

        for csp, validator in results.items():
            for err in validator.errors:
                writer.writerow([
                    csp,
                    err['service'],
                    err['rule_id'],
                    err['error_type'],
                    err['error']
                ])

    total_errors = sum(len(v.errors) for v in results.values())
    print(f"✅ Exported {total_errors} errors")


def main():
    parser = argparse.ArgumentParser(description='Validate check dependency chains')
    parser.add_argument('--csp', choices=['aws', 'azure', 'gcp', 'oci', 'ibm', 'alicloud', 'k8s', 'all'],
                       default='all', help='CSP to validate (default: all)')
    parser.add_argument('--verbose', action='store_true',
                       help='Print detailed validation progress')
    parser.add_argument('--export-csv', type=str,
                       help='Export errors to CSV file')

    args = parser.parse_args()

    print("="*80)
    print("Check Dependency Chain Validation Tool")
    print("="*80)
    print(f"Database: {DB_CONFIG['database']}@{DB_CONFIG['host']}")
    print(f"CSP: {args.csp}")
    print("="*80)

    # Determine CSPs to validate
    csps_to_validate = []
    if args.csp == 'all':
        csps_to_validate = ['aws', 'azure', 'gcp', 'oci', 'ibm', 'alicloud', 'k8s']
    else:
        csps_to_validate = [args.csp]

    # Validate each CSP
    all_results = {}
    for csp in csps_to_validate:
        try:
            validator = validate_csp(csp, verbose=args.verbose)
            validator.print_summary()
            all_results[csp] = validator
        except Exception as e:
            print(f"\n❌ Fatal error validating {csp}: {e}")
            import traceback
            traceback.print_exc()

    # Export to CSV if requested
    if args.export_csv:
        export_errors_to_csv(all_results, args.export_csv)

    # Print overall summary
    print(f"\n{'='*80}")
    print("Overall Validation Summary")
    print(f"{'='*80}")

    total_checks = sum(v.total_checks for v in all_results.values())
    total_valid = sum(v.valid_checks for v in all_results.values())
    total_errors = sum(len(v.errors) for v in all_results.values())

    print(f"Total Checks: {total_checks}")
    print(f"Valid Checks: {total_valid} ({total_valid/total_checks*100:.1f}%)")
    print(f"Total Errors: {total_errors}")

    for csp, validator in all_results.items():
        if validator.total_checks > 0:
            validity = validator.valid_checks / validator.total_checks * 100
            status = "✅" if validity > 95 else "⚠️" if validity > 80 else "❌"
            print(f"{status} {csp.upper()}: {validator.valid_checks}/{validator.total_checks} ({validity:.1f}%)")

    print(f"{'='*80}")


if __name__ == '__main__':
    main()
