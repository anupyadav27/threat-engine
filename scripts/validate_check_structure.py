#!/usr/bin/env python3
"""
Validate Check Rule Structure and Operations

This validates:
1. Check operators (op) are valid: equals, not_equals, exists, not_exists, contains, etc.
2. Variables (var) are properly formatted
3. Conditions structure is valid (all, any, op)
4. Discovery references exist

Usage:
    python3 validate_check_structure.py [--csp aws|azure|all] [--export-csv]
"""

import os
import sys
import json
import psycopg2
from psycopg2.extras import RealDictCursor
import argparse
from collections import defaultdict
import csv

DB_CONFIG = {
    'host': 'postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com',
    'port': 5432,
    'database': 'threat_engine_check',
    'user': 'postgres',
    'password': 'jtv2BkJF8qoFtAKP'
}

# Valid operators
VALID_OPERATORS = {
    # Comparison
    'equals', 'not_equals', 'eq', 'ne',
    'greater_than', 'less_than', 'gte', 'lte', 'gt', 'lt',
    # Existence
    'exists', 'not_exists',
    # String operations
    'contains', 'not_contains', 'starts_with', 'ends_with',
    'regex', 'not_regex',
    # Array operations
    'in', 'not_in', 'contains_all', 'contains_any',
    # Boolean logic
    'all', 'any', 'not', 'none',
    # Type checks
    'is_null', 'is_not_null', 'is_empty', 'is_not_empty',
    # Length
    'length_equals', 'length_greater_than', 'length_less_than'
}


class StructureValidationResult:
    def __init__(self):
        self.total_checks = 0
        self.valid_structure = 0
        self.operator_errors = []
        self.var_errors = []
        self.discovery_errors = []
        self.structure_errors = []
        self.by_service = defaultdict(lambda: {
            'total': 0,
            'valid': 0,
            'errors': []
        })

    def add_error(self, service: str, rule_id: str, error_type: str, error: str):
        error_entry = {
            'service': service,
            'rule_id': rule_id,
            'error_type': error_type,
            'error': error
        }

        if error_type == 'operator':
            self.operator_errors.append(error_entry)
        elif error_type == 'var':
            self.var_errors.append(error_entry)
        elif error_type == 'discovery':
            self.discovery_errors.append(error_entry)
        else:
            self.structure_errors.append(error_entry)

        self.by_service[service]['errors'].append(error_entry)

    def print_summary(self):
        print(f"\n{'='*80}")
        print("Structure Validation Summary")
        print(f"{'='*80}")
        print(f"Total Checks: {self.total_checks}")
        print(f"Valid Structure: {self.valid_structure} ({self.valid_structure/self.total_checks*100:.1f}%)")
        print(f"\nError Breakdown:")
        print(f"  Operator Errors: {len(self.operator_errors)}")
        print(f"  Variable Errors: {len(self.var_errors)}")
        print(f"  Discovery Errors: {len(self.discovery_errors)}")
        print(f"  Structure Errors: {len(self.structure_errors)}")

        if self.operator_errors:
            print(f"\n❌ Top 10 Invalid Operators:")
            op_counts = defaultdict(int)
            for err in self.operator_errors:
                # Extract operator from error message
                if 'Invalid operator:' in err['error']:
                    op = err['error'].split("'")[1] if "'" in err['error'] else 'unknown'
                    op_counts[op] += 1
            for op, count in sorted(op_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  '{op}': {count} occurrences")

        if self.discovery_errors:
            print(f"\n❌ Top 10 Missing Discovery Operations:")
            disc_counts = defaultdict(int)
            for err in self.discovery_errors:
                if 'not found' in err['error']:
                    disc = err['error'].split("'")[1] if "'" in err['error'] else 'unknown'
                    disc_counts[disc] += 1
            for disc, count in sorted(disc_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                print(f"  '{disc}': {count} checks")


def validate_operator(op: str, path: str) -> list:
    """Validate operator is valid."""
    errors = []
    if op not in VALID_OPERATORS:
        errors.append(f"Invalid operator: '{op}' at {path}")
    return errors


def validate_conditions(conditions: dict, discovery_ops: set, path: str = "conditions") -> tuple:
    """
    Recursively validate condition structure.

    Returns:
        (operator_errors, var_errors, structure_errors)
    """
    operator_errors = []
    var_errors = []
    structure_errors = []

    if not isinstance(conditions, dict):
        structure_errors.append(f"Conditions must be dict at {path}")
        return (operator_errors, var_errors, structure_errors)

    # Check for logical operators (all, any, not, none)
    for logical_op in ['all', 'any', 'not', 'none']:
        if logical_op in conditions:
            items = conditions[logical_op]
            if not isinstance(items, list):
                structure_errors.append(f"'{logical_op}' must be a list at {path}")
                continue

            # Recursively validate each item
            for idx, item in enumerate(items):
                sub_path = f"{path}.{logical_op}[{idx}]"
                op_errs, var_errs, struct_errs = validate_conditions(item, discovery_ops, sub_path)
                operator_errors.extend(op_errs)
                var_errors.extend(var_errs)
                structure_errors.extend(struct_errs)
            return (operator_errors, var_errors, structure_errors)

    # Check for comparison operator
    if 'op' in conditions:
        op = conditions['op']
        operator_errors.extend(validate_operator(op, path))

        # Validate 'var' field
        if 'var' in conditions:
            var = conditions['var']
            if not isinstance(var, str):
                var_errors.append(f"'var' must be string at {path}, got {type(var)}")
            elif not var:
                var_errors.append(f"'var' is empty at {path}")
        elif op not in ['all', 'any', 'not', 'none']:
            # Most operators require 'var'
            var_errors.append(f"Missing 'var' for operator '{op}' at {path}")

    return (operator_errors, var_errors, structure_errors)


def validate_check_structure(check: dict, discovery_configs: dict) -> tuple:
    """
    Validate check structure.

    Returns:
        (is_valid, errors_by_type)
    """
    service = check['service']
    rule_id = check['rule_id']
    check_config = check['check_config']

    errors_by_type = defaultdict(list)

    # Parse check_config if string
    if isinstance(check_config, str):
        try:
            check_config = eval(check_config)
        except Exception as e:
            errors_by_type['structure'].append(f"Failed to parse check_config: {e}")
            return (False, errors_by_type)

    # Get discovery operations for service
    discovery_ops = set()
    if service in discovery_configs:
        discoveries = discovery_configs[service].get('discovery', [])
        discovery_ops = {d['discovery_id'] for d in discoveries}

    # Validate for_each reference
    for_each = check_config.get('for_each')
    if for_each:
        if for_each not in discovery_ops:
            errors_by_type['discovery'].append(f"Discovery operation '{for_each}' not found")

    # Validate conditions
    conditions = check_config.get('conditions')
    if conditions:
        op_errs, var_errs, struct_errs = validate_conditions(conditions, discovery_ops)
        errors_by_type['operator'].extend(op_errs)
        errors_by_type['var'].extend(var_errs)
        errors_by_type['structure'].extend(struct_errs)
    else:
        errors_by_type['structure'].append("Missing 'conditions' field")

    is_valid = sum(len(v) for v in errors_by_type.values()) == 0
    return (is_valid, errors_by_type)


def validate_csp(csp: str) -> StructureValidationResult:
    """Validate all checks for a CSP."""
    print(f"\n{'='*80}")
    print(f"Validating {csp.upper()} Check Structure")
    print(f"{'='*80}")

    result = StructureValidationResult()
    conn = psycopg2.connect(**DB_CONFIG)

    try:
        # Load discovery configs
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT service, discoveries_data
                FROM rule_discoveries
                WHERE provider = %s
            """, (csp,))

            discovery_configs = {}
            for row in cur.fetchall():
                data = row['discoveries_data']
                if isinstance(data, str):
                    data = json.loads(data)
                discovery_configs[row['service']] = data

        print(f"Loaded {len(discovery_configs)} discovery configs")

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
        for idx, check in enumerate(checks):
            result.total_checks += 1
            result.by_service[check['service']]['total'] += 1

            is_valid, errors_by_type = validate_check_structure(check, discovery_configs)

            if is_valid:
                result.valid_structure += 1
                result.by_service[check['service']]['valid'] += 1
            else:
                # Add errors
                for error_type, errors in errors_by_type.items():
                    for error in errors:
                        result.add_error(check['service'], check['rule_id'], error_type, error)

            if (idx + 1) % 200 == 0:
                print(f"  Processed {idx+1}/{len(checks)} checks...")

    finally:
        conn.close()

    return result


def export_errors_to_csv(results: dict, output_file: str):
    """Export validation errors to CSV."""
    print(f"\nExporting errors to {output_file}...")

    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['CSP', 'Service', 'Rule ID', 'Error Type', 'Error'])

        for csp, result in results.items():
            for error_list in [result.operator_errors, result.var_errors,
                              result.discovery_errors, result.structure_errors]:
                for err in error_list:
                    writer.writerow([
                        csp,
                        err['service'],
                        err['rule_id'],
                        err['error_type'],
                        err['error']
                    ])

    print(f"✅ Exported {sum(len(r.operator_errors) + len(r.var_errors) + len(r.discovery_errors) + len(r.structure_errors) for r in results.values())} errors")


def main():
    parser = argparse.ArgumentParser(description='Validate check rule structure')
    parser.add_argument('--csp', choices=['aws', 'azure', 'gcp', 'oci', 'ibm', 'alicloud', 'all'],
                       default='all', help='CSP to validate (default: all)')
    parser.add_argument('--export-csv', type=str, help='Export errors to CSV file')

    args = parser.parse_args()

    print("="*80)
    print("Check Structure Validation Tool")
    print("="*80)
    print(f"Database: {DB_CONFIG['database']}@{DB_CONFIG['host']}")
    print(f"CSP: {args.csp}")
    print("="*80)

    # Determine CSPs to validate
    csps_to_validate = []
    if args.csp == 'all':
        csps_to_validate = ['aws', 'azure', 'gcp', 'oci', 'ibm', 'alicloud']
    else:
        csps_to_validate = [args.csp]

    # Validate each CSP
    all_results = {}
    for csp in csps_to_validate:
        try:
            result = validate_csp(csp)
            result.print_summary()
            all_results[csp] = result
        except Exception as e:
            print(f"\n❌ Fatal error validating {csp}: {e}")
            import traceback
            traceback.print_exc()

    # Export to CSV if requested
    if args.export_csv:
        export_errors_to_csv(all_results, args.export_csv)

    # Print overall summary
    print(f"\n{'='*80}")
    print("Overall Summary")
    print(f"{'='*80}")

    for csp, result in all_results.items():
        if result.total_checks > 0:
            validity = result.valid_structure / result.total_checks * 100
            status = "✅" if validity > 95 else "⚠️" if validity > 80 else "❌"
            print(f"{status} {csp.upper()}: {result.valid_structure}/{result.total_checks} ({validity:.1f}%)")

    print(f"{'='*80}")


if __name__ == '__main__':
    main()
