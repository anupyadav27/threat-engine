# YAML Action Patterns for Smart Action Parser

## Overview
The GCP engine uses a **smart action parser** that dynamically interprets action names without hardcoded service logic. To work with the parser, YAML actions must follow specific naming patterns.

## Supported Action Patterns

### 1. List Resources
**Pattern:** `list_<resource_type>`
**Example:** `list_firewalls`, `list_topics`, `list_instances`
**Executes:** `client.<resource_type>().list(project=project_id)`

```yaml
discovery:
  - discovery_id: firewalls
    calls:
    - action: list_firewalls
```

### 2. Aggregated List (Compute)
**Pattern:** `aggregatedList_<resource_type>`  
**Example:** `aggregatedList_instances`, `aggregatedList_addresses`
**Executes:** `client.<resource_type>().aggregatedList(project=project_id)`

```yaml
discovery:
  - discovery_id: instances
    calls:
    - action: aggregatedList_instances
```

### 3. SDK-Specific Actions (GCS)
**Pattern:** Custom action names for SDK clients
**Examples:** `list_buckets`, `get_bucket_metadata`
**Note:** These are handled specially for SDK clients (not Discovery API)

```yaml
discovery:
  - discovery_id: list_buckets
    calls:
    - action: list_buckets
```

### 4. Evaluate Fields (Checks)
**Pattern:** `eval`
**Executes:** Direct evaluation on discovered resource data

```yaml
checks:
  - check_id: example.check
    for_each: firewalls
    calls:
    - action: eval
      fields:
      - path: name
        operator: not_contains
        expected: default-allow-
```

### 5. IAM Policy Checks
**Pattern:** Use `eval` with IAM policy data from discovery, OR fetch inline during checks
**Recommendation:** For now, avoid IAM policy actions in discovery; use eval on resource properties

**Current Limitation:** IAM policy fetching during checks requires service-specific implementation
**Workaround:** Structure checks to use eval on discovered metadata

```yaml
# Instead of:
- action: get_topic_iam_policy
  fields: ...

# Use:
- action: eval
  fields:
  - path: iam_policy.bindings  # If IAM policy in discovery
```

## YAML Structure Requirements

### Discovery Section
```yaml
discovery:
  - discovery_id: <unique_id>          # Used in checks' for_each
    for_each: <other_discovery_id>     # Optional: chain discoveries
    calls:
    - action: <action_name>             # Must follow pattern above
      fields:                           # Optional: fields to extract
      - path: <dot.notation.path>
        var: <variable_name>
```

### Checks Section
```yaml
checks:
  - check_id: <unique_check_id>
    title: <description>
    severity: high|medium|low
    for_each: <discovery_id>            # Which discovery to use
    logic: AND|OR                       # How to combine call results
    calls:
    - action: eval                      # Primary action type
      fields:
      - path: <field_path>
        operator: exists|equals|contains|not_contains
        expected: <value>
```

## Guidelines for New Services

1. **Use standard action patterns** - `list_<resource>`, `aggregatedList_<resource>`
2. **Keep actions generic** - Avoid service-specific custom actions
3. **Use eval for checks** - Primary check action should be eval
4. **Extract metadata in discovery** - Get all needed data during discovery
5. **Document exceptions** - If service needs special handling, document why

## Examples

### Good (Works with smart parser):
```yaml
discovery:
  - discovery_id: topics
    calls:
    - action: list_topics  # Parses to: client.topics().list()

checks:
  - check_id: example
    for_each: topics
    calls:
    - action: eval
      fields:
      - path: kmsKeyName
        operator: exists
```

### Needs Work (Requires engine changes):
```yaml
discovery:
  - discovery_id: topic_iam
    calls:
    - action: get_topic_iam_policy  # Custom action not in parser
```

## Migration Path

For services with IAM policy checks:
1. **Option A**: Add generic IAM policy support to smart parser (one-time engine enhancement)
2. **Option B**: Restructure YAML to avoid IAM discovery, use eval on metadata
3. **Option C**: Add IAM bindings to resource metadata during discovery

Recommend Option A for long-term scalability.

