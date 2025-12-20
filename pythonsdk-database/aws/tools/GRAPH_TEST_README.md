# Dependency Graph Test Harness

## Overview

The `graph_test.py` tool validates that all operations in AWS service dependency graphs are "chain-satisfiable" - meaning all required consumes can be produced by some chain of operations starting from independent ops or external entities.

## Usage

### Test a Single Service

```bash
python tools/graph_test.py --service-dir path/to/service_folder --out reports/
```

Example:
```bash
python tools/graph_test.py --service-dir accessanalyzer --out test_reports
```

### Test All Services

```bash
python tools/graph_test.py --root path/to/all_services --out reports/
```

Example:
```bash
python tools/graph_test.py --root . --out test_reports
```

## Output

### Per-Service Reports

Each service generates a report: `reports/<service>_graph_test_report.json`

```json
{
  "service_name": "accessanalyzer",
  "total_ops": 37,
  "satisfiable_ops_count": 37,
  "satisfiable_ops_percent": 100.0,
  "unsatisfiable_ops_count": 0,
  "breakdown_by_kind": {
    "read_list": {"total": 9, "satisfiable": 9, "percent": 100.0},
    "write_create": {"total": 6, "satisfiable": 6, "percent": 100.0},
    ...
  },
  "top_missing_entities": [...],
  "top_external_entities_used": [...],
  "unsat_examples": [...],
  "sat_examples": [...]
}
```

### Global Summary

`reports/global_graph_test_summary.json` contains:
- Total services and operations
- Global satisfiability percentage
- Most common missing entities across all services
- Services ranked by satisfiability
- Suspicious path patterns

## Interpreting Results

### Satisfiability Status

- **100%**: All operations are satisfiable
- **90-99%**: Most operations satisfiable, minor issues
- **50-89%**: Significant gaps, needs investigation
- **<50%**: Major issues, likely missing producers or cycles

### Common Reasons for Unsatisfiability

1. **no_producer**: Entity has no producer operations
   - Check if entity should be marked as external
   - Check if producer operation is missing from spec

2. **needs_derivation**: Entity needs a derivation bridge
   - Example: Operation needs `resource_id` but only `resource` is produced
   - May need to add a derivation rule or alias

3. **cycle**: Circular dependency detected
   - Operations depend on each other in a cycle
   - May indicate a design issue or missing external input

4. **external**: All dependencies are external (this is OK)

### Missing Entities

The `top_missing_entities` list shows which entities are most frequently missing producers. These are candidates for:
- Marking as external if they're truly external inputs
- Adding producer operations if they're missing from the spec
- Creating derivation bridges if they can be derived from other entities

### Example Chains

The `sat_examples` show sample chains for satisfiable operations, demonstrating how dependencies are resolved. This helps verify the dependency graph is correct.

## Performance

The test harness is optimized for speed:
- Runs across all 411 services in < 2 seconds
- Uses efficient BFS algorithm for chain finding
- No network calls or external dependencies

## Integration

This test can be integrated into CI/CD pipelines to ensure dependency graphs remain valid as services are updated.

```bash
# In CI pipeline
python tools/graph_test.py --root . --out reports/
if [ $? -ne 0 ]; then
  echo "Dependency graph test failed"
  exit 1
fi
```

## Troubleshooting

### Service shows 0% satisfiability

- Check if `adjacency.json` and `operation_registry.json` exist
- Verify the service has operations defined
- Check for syntax errors in JSON files

### Many "needs_derivation" errors

- This indicates entities that could be derived from other entities
- Consider adding entity aliases or derivation rules
- These are soft failures - the graph structure is correct but needs enhancement

### High number of missing entities

- Review `top_missing_entities` in the global summary
- Check if these should be marked as `external_entities` in `adjacency.json`
- Verify producer operations exist in the service spec

