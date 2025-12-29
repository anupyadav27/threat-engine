#!/usr/bin/env python3
"""
Build dependency indexes for all services in a provider directory.

This script processes all services and builds dependency_index.json for each.
It can be used for AWS, Azure, GCP, IBM, OCI, etc.
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict
import traceback

# Import the build function
import sys
from pathlib import Path
# Add tools directory to path
sys.path.insert(0, str(Path(__file__).parent))
from build_dependency_index import build_dependency_index, validate_index


def find_service_directories(root_path: Path) -> List[Path]:
    """Find all service directories that have operation_registry.json."""
    service_dirs = []
    for item in root_path.iterdir():
        if item.is_dir():
            registry_file = item / "operation_registry.json"
            if registry_file.exists():
                service_dirs.append(item)
    return sorted(service_dirs)


def build_service_index(
    service_path: Path,
    read_only: bool = True,
    include_all_kinds: bool = False,
    validate: bool = False
) -> Dict[str, Any]:
    """Build dependency index for a single service."""
    result = {
        'service': service_path.name,
        'status': 'unknown',
        'error': None,
        'stats': {}
    }
    
    try:
        # Check required files exist
        required_files = ['operation_registry.json', 'adjacency.json']
        missing_files = [f for f in required_files if not (service_path / f).exists()]
        if missing_files:
            result['status'] = 'error'
            result['error'] = f"Missing required files: {', '.join(missing_files)}"
            return result
        
        # Build index
        index = build_dependency_index(
            service_path,
            read_only=read_only,
            include_all_kinds=include_all_kinds
        )
        
        # Write the index file (build_dependency_index returns the index but doesn't write it)
        from build_dependency_index import compact_json_arrays
        index_path = service_path / 'dependency_index.json'
        json_str = json.dumps(index, indent=2)
        json_str = compact_json_arrays(json_str)
        with open(index_path, 'w') as f:
            f.write(json_str)
        
        # Collect stats
        result['stats'] = {
            'num_roots': len(index.get('roots', [])),
            'num_entities_with_paths': len(index.get('entity_paths', {})),
            'read_only': index.get('read_only', True)
        }
        
        # Validate if requested
        if validate:
            try:
                with open(service_path / 'operation_registry.json') as f:
                    operation_registry = json.load(f)
                with open(service_path / 'adjacency.json') as f:
                    adjacency = json.load(f)
                
                validation = validate_index(index, operation_registry, adjacency)
                result['stats']['validation'] = {
                    'num_entities_covered': validation['num_entities_covered'],
                    'num_entities_total': validation['num_entities_total'],
                    'num_entities_missing': validation['num_entities_missing'],
                    'num_invalid_paths': validation['num_invalid_paths']
                }
            except Exception as val_error:
                result['stats']['validation_error'] = str(val_error)
        
        result['status'] = 'success'
        
    except FileNotFoundError as e:
        result['status'] = 'error'
        result['error'] = f"Missing file: {e}"
    except KeyboardInterrupt:
        result['status'] = 'interrupted'
        result['error'] = "Interrupted by user"
        raise
    except Exception as e:
        result['status'] = 'error'
        result['error'] = f"{type(e).__name__}: {str(e)}"
        result['traceback'] = traceback.format_exc()
    
    return result


def build_all_services(
    root_path: Path,
    provider: str = "aws",
    read_only: bool = True,
    include_all_kinds: bool = False,
    validate: bool = False,
    parallel: bool = False,
    limit: Optional[int] = None,
    exclude: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Build dependency indexes for all services."""
    
    service_dirs = find_service_directories(root_path)
    
    # Filter out excluded services
    if exclude:
        exclude_set = set(exclude)
        service_dirs = [d for d in service_dirs if d.name not in exclude_set]
        if exclude_set:
            print(f"⚠️  Excluding services: {', '.join(sorted(exclude_set))}\n")
    
    # Apply limit if specified
    if limit and limit > 0:
        service_dirs = service_dirs[:limit]
        print(f"⚠️  Limited to first {limit} services for testing\n")
    
    if not service_dirs:
        return {
            'provider': provider,
            'total': 0,
            'success': 0,
            'failed': 0,
            'services': [],
            'error': f'No services found in {root_path}'
        }
    
    results = {
        'provider': provider,
        'total': len(service_dirs),
        'success': 0,
        'failed': 0,
        'services': []
    }
    
    print(f"\n{'='*70}")
    print(f"BUILDING DEPENDENCY INDEXES FOR {provider.upper()}")
    print(f"{'='*70}")
    print(f"Found {results['total']} services")
    print(f"Read-only mode: {read_only}")
    print(f"Validate: {validate}")
    print(f"{'='*70}\n")
    
    for i, service_path in enumerate(service_dirs, 1):
        service_name = service_path.name
        print(f"[{i}/{results['total']}] Processing: {service_name}", flush=True)
        
        try:
            result = build_service_index(
                service_path,
                read_only=read_only,
                include_all_kinds=include_all_kinds,
                validate=validate
            )
            
            results['services'].append(result)
            
            if result['status'] == 'success':
                results['success'] += 1
                stats = result['stats']
                print(f"  ✓ Success - Roots: {stats['num_roots']}, Entities: {stats['num_entities_with_paths']}", flush=True)
                if validate and 'validation' in stats:
                    val = stats['validation']
                    print(f"    Coverage: {val['num_entities_covered']}/{val['num_entities_total']} "
                          f"({val['num_entities_missing']} missing, {val['num_invalid_paths']} invalid paths)", flush=True)
            else:
                results['failed'] += 1
                error_msg = result['error'][:100] if result['error'] else 'Unknown error'
                print(f"  ✗ Failed: {error_msg}", flush=True)
            
            print(flush=True)
            
        except KeyboardInterrupt:
            print(f"\n⚠️  Interrupted at service {i}/{results['total']}: {service_name}")
            print("Saving partial results...")
            break
        except Exception as e:
            results['failed'] += 1
            error_result = {
                'service': service_name,
                'status': 'error',
                'error': f"Unexpected error: {type(e).__name__}: {str(e)}",
                'stats': {}
            }
            results['services'].append(error_result)
            print(f"  ✗ Unexpected error: {e}", flush=True)
            print(flush=True)
    
    # Print summary
    print(f"{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Total Services: {results['total']}")
    print(f"  ✓ Success: {results['success']} ({results['success']/results['total']*100:.1f}%)")
    print(f"  ✗ Failed:  {results['failed']} ({results['failed']/results['total']*100:.1f}%)")
    print(f"{'='*70}\n")
    
    # Show failed services if any
    failed_services = [s for s in results['services'] if s['status'] != 'success']
    if failed_services:
        print(f"Failed Services ({len(failed_services)}):")
        for service in failed_services:
            print(f"  - {service['service']}: {service['error']}")
        print()
    
    return results


def generate_quality_report(results: Dict[str, Any], output_path: Path):
    """Generate a quality report from build results."""
    
    successful = [s for s in results['services'] if s['status'] == 'success']
    
    if not successful:
        print("No successful builds to analyze.")
        return
    
    # Aggregate statistics
    total_roots = sum(s['stats']['num_roots'] for s in successful)
    total_entities = sum(s['stats']['num_entities_with_paths'] for s in successful)
    avg_roots = total_roots / len(successful)
    avg_entities = total_entities / len(successful)
    
    # Services with validation
    validated = [s for s in successful if 'validation' in s['stats']]
    
    report = {
        'provider': results['provider'],
        'summary': {
            'total_services': results['total'],
            'successful': results['success'],
            'failed': results['failed'],
            'success_rate': f"{results['success']/results['total']*100:.1f}%"
        },
        'statistics': {
            'average_roots_per_service': round(avg_roots, 2),
            'average_entities_per_service': round(avg_entities, 2),
            'total_roots': total_roots,
            'total_entities_with_paths': total_entities
        },
        'validation': None
    }
    
    if validated:
        total_covered = sum(s['stats']['validation']['num_entities_covered'] for s in validated)
        total_entities_val = sum(s['stats']['validation']['num_entities_total'] for s in validated)
        total_missing = sum(s['stats']['validation']['num_entities_missing'] for s in validated)
        total_invalid = sum(s['stats']['validation']['num_invalid_paths'] for s in validated)
        
        report['validation'] = {
            'services_validated': len(validated),
            'total_entities_covered': total_covered,
            'total_entities': total_entities_val,
            'total_missing': total_missing,
            'coverage_rate': f"{total_covered/total_entities_val*100:.1f}%" if total_entities_val > 0 else "0%",
            'total_invalid_paths': total_invalid
        }
    
    # Services with issues
    services_with_issues = []
    for service in validated:
        val = service['stats']['validation']
        if val['num_entities_missing'] > 0 or val['num_invalid_paths'] > 0:
            services_with_issues.append({
                'service': service['service'],
                'missing_entities': val['num_entities_missing'],
                'invalid_paths': val['num_invalid_paths']
            })
    
    if services_with_issues:
        report['services_with_issues'] = services_with_issues
    
    # Write report
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"Quality report saved to: {output_path}")
    
    # Print report summary
    print(f"\n{'='*70}")
    print(f"QUALITY REPORT")
    print(f"{'='*70}")
    print(f"Provider: {report['provider']}")
    print(f"Success Rate: {report['summary']['success_rate']}")
    print(f"Average Roots per Service: {report['statistics']['average_roots_per_service']}")
    print(f"Average Entities per Service: {report['statistics']['average_entities_per_service']}")
    if report['validation']:
        print(f"Coverage Rate: {report['validation']['coverage_rate']}")
        print(f"Services with Issues: {len(services_with_issues)}")
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Build dependency indexes for all services in a provider directory',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Build for all AWS services
  python tools/build_all_dependency_indexes.py pythonsdk-database/aws --provider aws

  # Build with validation
  python tools/build_all_dependency_indexes.py pythonsdk-database/aws --provider aws --validate

  # Build for Azure
  python tools/build_all_dependency_indexes.py pythonsdk-database/azure --provider azure
        """
    )
    parser.add_argument(
        'root_path',
        type=Path,
        help='Root path to provider directory (e.g., pythonsdk-database/aws)'
    )
    parser.add_argument(
        '--provider',
        default='aws',
        help='Provider name (aws, azure, gcp, ibm, oci) - default: aws'
    )
    parser.add_argument(
        '--all-kinds',
        action='store_true',
        help='Include all operation kinds (not just read-only)'
    )
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Run validation after building each index'
    )
    parser.add_argument(
        '--report',
        type=Path,
        help='Path to save quality report JSON (default: <root_path>/dependency_index_report.json)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of services to process (for testing)'
    )
    parser.add_argument(
        '--exclude',
        nargs='+',
        help='Services to exclude from processing (e.g., --exclude network web)'
    )
    
    args = parser.parse_args()
    
    if not args.root_path.exists():
        print(f"Error: Path not found: {args.root_path}", file=sys.stderr)
        sys.exit(1)
    
    if not args.root_path.is_dir():
        print(f"Error: Not a directory: {args.root_path}", file=sys.stderr)
        sys.exit(1)
    
    # Build all services
    results = build_all_services(
        args.root_path,
        provider=args.provider,
        read_only=True,
        include_all_kinds=args.all_kinds,
        validate=args.validate,
        limit=args.limit,
        exclude=args.exclude
    )
    
    # Generate quality report
    if args.report:
        report_path = args.report
    else:
        report_path = args.root_path / 'dependency_index_report.json'
    
    generate_quality_report(results, report_path)
    
    # Save detailed results
    results_path = args.root_path / 'dependency_index_build_results.json'
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Detailed results saved to: {results_path}\n")
    
    # Exit with error code if any failures
    sys.exit(0 if results['failed'] == 0 else 1)


if __name__ == '__main__':
    main()

