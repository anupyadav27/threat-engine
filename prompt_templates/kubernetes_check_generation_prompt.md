# Kubernetes Compliance Check Generation Prompt Template

## Context
You are a compliance engineer tasked with creating security and compliance checks for Kubernetes clusters. You need to generate YAML rule definitions that can be executed by our Kubernetes compliance engine to validate infrastructure against security best practices.

## Kubernetes Engine Capabilities

### Scope Options
- **`cluster`**: Scans resources across the entire cluster
- **`namespace`**: Scans resources within a specific namespace

### Discovery Actions
Uses Kubernetes API through Python client:
- **Core**: `list_pods`, `list_services`, `list_deployments`, `list_configmaps`
- **RBAC**: `list_roles`, `list_role_bindings`, `list_cluster_roles`, `list_cluster_role_bindings`
- **Security**: `list_pod_security_policies`, `list_network_policies`
- **Storage**: `list_persistent_volumes`, `list_persistent_volume_claims`
- **Networking**: `list_ingresses`, `list_network_policies`

### Field Paths
Dot notation for navigating Kubernetes resource properties:
- **Direct Fields**: `metadata.name`, `metadata.namespace`
- **Nested Objects**: `spec.template.spec.containers[0].securityContext.privileged`
- **Arrays**: `spec.containers[]`, `spec.volumes[]`
- **Special**: `item` for the entire resource object in checks

### Operators
- `equals`: Exact value match
- `not_equals`: Field does not equal the expected value
- `contains`: Field contains the expected value
- `not_contains`: Field does not contain the expected value
- `exists`: Field exists and has a value
- `not_exists`: Field does not exist or is null/empty

### Actions
- **`identity`**: Object reference for complex operations (most common)
- **`list`**: Resource listing operations
- **`eval`**: Direct field evaluation

### Multi-Step Checks
Supports complex validation logic:
```yaml
multi_step: true
logic: AND  # or OR
calls:
  - action: identity
    params: {}
    fields:
      - path: item.spec.containers[0].securityContext.privileged
        operator: not_equals
        expected: true
      - path: item.spec.containers[0].securityContext.readOnlyRootFilesystem
        operator: equals
        expected: true
```

## Prompt Template

```
Generate a Kubernetes compliance check to validate [COMPLIANCE_REQUIREMENT].

**Compliance Standard**: [STANDARD_NAME] - [REQUIREMENT_ID]
**Requirement**: [DETAILED_DESCRIPTION]
**Severity**: [HIGH/MEDIUM/LOW]
**Scope**: [cluster/namespace]

**Target Resources**: [RESOURCE_TYPE] (e.g., Pods, Deployments, Services, RBAC resources)

**Expected Behavior**: [WHAT_SHOULD_BE_TRUE/FALSE]

**Current Infrastructure Context**:
- [ANY_SPECIFIC_INFRASTRUCTURE_DETAILS]
- [EXISTING_RESOURCES_OR_PATTERNS]
- [CLUSTER_OR_NAMESPACE_SCOPE_NEEDS]
- [WORKLOAD_OR_ADMINISTRATIVE_RESOURCE_TYPES]

**Additional Requirements**:
- [ANY_SPECIFIC_OPERATORS_OR_LOGIC_NEEDED]
- [MULTI_STEP_CHECK_REQUIREMENTS]
- [CONTAINER_LEVEL_OR_POD_LEVEL_VALIDATION]

Please generate the complete YAML rule including:
1. Discovery section with appropriate Kubernetes API calls
2. Check section with proper field paths and operators
3. Appropriate scope setting (cluster/namespace)
4. Any special handling needed for Kubernetes-specific resources
```

## Example Prompts

### Pod Security Example
```
Generate a Kubernetes compliance check to validate privileged container restrictions.

**Compliance Standard**: CIS Kubernetes 1.8 - 5.2.1
**Requirement**: Ensure containers are not running with privileged access
**Severity**: HIGH
**Scope**: cluster

**Target Resources**: Kubernetes Pods

**Expected Behavior**: No containers should have securityContext.privileged set to true

**Current Infrastructure Context**:
- Multiple pods across different namespaces
- Need to check container security context
- Cluster-wide scanning for security compliance

Please generate the complete YAML rule including discovery and check sections.
```

### RBAC Security Example
```
Generate a Kubernetes compliance check to validate cluster admin role usage.

**Compliance Standard**: CIS Kubernetes 1.8 - 5.1.1
**Requirement**: Ensure cluster-admin role is not excessively used
**Severity**: HIGH
**Scope**: cluster

**Target Resources**: Kubernetes ClusterRoleBindings

**Expected Behavior**: ClusterRoleBindings should not grant cluster-admin role to regular users

**Current Infrastructure Context**:
- Multiple cluster role bindings
- Need to check role references and subjects
- Cluster-wide RBAC scanning

Please generate the complete YAML rule including discovery and check sections.
```

### Network Policy Example
```
Generate a Kubernetes compliance check to validate network policy enforcement.

**Compliance Standard**: CIS Kubernetes 1.8 - 5.3.1
**Requirement**: Ensure network policies are applied to all pods
**Severity**: MEDIUM
**Scope**: cluster

**Target Resources**: Kubernetes Pods and NetworkPolicies

**Expected Behavior**: All pods should be covered by network policies

**Current Infrastructure Context**:
- Multiple pods across namespaces
- Network policies may be namespace-specific
- Need to check policy coverage

Please generate the complete YAML rule including discovery and check sections.
```

## Response Format

When responding to these prompts, provide:

1. **Complete YAML Rule**: The full rule definition ready to be placed in the appropriate Kubernetes component file
2. **Explanation**: Brief explanation of how the rule works
3. **Field Mapping**: Explanation of the Kubernetes resource structure and field paths
4. **Scope Considerations**: Why the chosen scope (cluster/namespace) is appropriate
5. **Action Strategy**: Whether to use `identity`, `list`, or other actions
6. **Testing Notes**: Any considerations for testing the rule with Kubernetes resources

## Common Kubernetes Patterns

### Container Security Check
```yaml
- check_id: core_minimize_privileged_containers
  name: Core Minimize Privileged Containers
  severity: HIGH
  for_each: list_pods
  param: item
  calls:
  - action: identity
    params: {}
    fields:
    - path: item.spec.containers[0].securityContext.privileged
      operator: not_equals
      expected: true
  logic: AND
  errors_as_fail: []
```

### Pod Configuration Check
```yaml
- check_id: core_minimize_host_network_containers
  name: Core Minimize Host Network Containers
  severity: HIGH
  for_each: list_pods
  param: item
  calls:
  - action: identity
    params: {}
    fields:
    - path: item.spec.hostNetwork
      operator: not_equals
      expected: true
  logic: AND
  errors_as_fail: []
```

### RBAC Security Check
```yaml
- check_id: rbac_minimize_cluster_admin_usage
  name: RBAC Minimize Cluster Admin Usage
  severity: HIGH
  for_each: list_cluster_role_bindings
  param: item
  calls:
  - action: identity
    params: {}
    fields:
    - path: item.roleRef.name
      operator: not_equals
      expected: cluster-admin
  logic: AND
  errors_as_fail: []
```

### Multi-Step Security Check
```yaml
- check_id: core_comprehensive_security_context
  name: Core Comprehensive Security Context
  severity: HIGH
  for_each: list_pods
  param: item
  multi_step: true
  logic: AND
  calls:
  - action: identity
    params: {}
    fields:
    - path: item.spec.containers[0].securityContext.privileged
      operator: not_equals
      expected: true
    - path: item.spec.containers[0].securityContext.readOnlyRootFilesystem
      operator: equals
      expected: true
    - path: item.spec.containers[0].securityContext.runAsNonRoot
      operator: equals
      expected: true
  errors_as_fail: []
```

## Kubernetes-Specific Considerations

### Container Array Handling
Kubernetes pods can have multiple containers. Common patterns:
- Check first container: `spec.containers[0].securityContext.privileged`
- Check all containers: `spec.containers[].securityContext.privileged`
- Validate against each container individually

### Security Context Fields
Key security context fields to validate:
- `privileged`: Should be false
- `readOnlyRootFilesystem`: Should be true
- `runAsNonRoot`: Should be true
- `allowPrivilegeEscalation`: Should be false
- `capabilities.drop[]`: Should contain `ALL`

### RBAC Structure
RBAC resources have specific relationships:
- `Role` → `RoleBinding` → `Subject` (namespace-scoped)
- `ClusterRole` → `ClusterRoleBinding` → `Subject` (cluster-scoped)
- Check both the role reference and the subjects

### Network Policy Coverage
Network policy validation involves:
- Checking if pods have network policies applied
- Validating policy rules and selectors
- Ensuring default deny policies exist

This template ensures consistent, effective Kubernetes compliance checks that integrate seamlessly with your existing Kubernetes compliance engine.
