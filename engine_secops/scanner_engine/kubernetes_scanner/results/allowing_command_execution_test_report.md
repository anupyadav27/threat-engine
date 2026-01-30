# Test Results: Allowing Command Execution Rule

## Rule Information
- **Rule ID**: `allowing_command_execution_is`
- **Title**: Allowing command execution is security sensitive
- **Severity**: Major
- **Category**: Security

## Description
Allowing command execution (exec) for roles in a Kubernetes cluster can pose a significant security risk. This is because it provides the user with the ability to execute arbitrary commands within a container, potentially leading to unauthorized access or data breaches.

In a production Kubernetes cluster, exec permissions are typically unnecessary due to the principle of least privilege. Additionally, containers in production are often treated as immutable infrastructure.

## Test File
`test/role_with_exec_violation.yaml`

## Test Results

### Summary
- **Files Scanned**: 1
- **Total Findings**: 2
- **Violations by Severity**:
  - Major: 2

### Detailed Findings

#### Finding 1: Role with exec permission
```yaml
Resource: Role/pod-exec-role
File: test/role_with_exec_violation.yaml
Line: 1
Severity: Major

Property Path: metadata.all_verbs
Detected Verbs: ["exec", "list", "get"]

Message: RBAC role allows 'exec' verb which enables command execution in 
containers. This is a security risk in production environments.
```

**Violating Code:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-exec-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "exec"]  # ❌ 'exec' verb is a security risk
```

#### Finding 2: ClusterRole with exec permission
```yaml
Resource: ClusterRole/cluster-pod-exec-role
File: test/role_with_exec_violation.yaml
Line: 14
Severity: Major

Property Path: metadata.all_verbs
Detected Verbs: ["watch", "list", "create", "get", "exec"]

Message: RBAC role allows 'exec' verb which enables command execution in 
containers. This is a security risk in production environments.
```

**Violating Code:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-pod-exec-role
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch", "exec"]  # ❌ 'exec' verb allows command execution
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]  # ❌ Also allows exec via pods/exec resource
```

## Compliant Example

The test file also includes a compliant example that was not flagged:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]  # ✅ No exec verb - compliant
```

## Rule Logic

The rule uses the following logic:

```json
{
  "resource_types": ["Role", "ClusterRole"],
  "checks": [
    {
      "type": "property_comparison",
      "property_path": ["metadata", "all_verbs"],
      "operator": "contains",
      "value": "exec",
      "message": "RBAC role allows 'exec' verb which enables command execution..."
    }
  ]
}
```

### How It Works:
1. **Target Resources**: Scans `Role` and `ClusterRole` resources
2. **Property Path**: Navigates to `metadata.all_verbs` (a flattened list of all verbs)
3. **Operator**: Uses `contains` to check if the string `"exec"` is in the list
4. **Detection**: Flags any role that allows the `exec` verb

## AST Structure

The rule leverages the semantic AST model where RBAC roles have their verbs extracted and flattened:

```python
{
  "node_type": "KubernetesResource",
  "type": "Role",
  "kind": "Role",
  "name": "pod-exec-role",
  "metadata": {
    "rules": [...],
    "all_verbs": ["exec", "list", "get"],  # ← This is what the rule checks
    "all_resources": ["pods", "pods/log"]
  }
}
```

## Recommendations

To fix these violations:

1. **Remove exec verb** from RBAC rules:
   ```yaml
   verbs: ["get", "list", "watch"]  # Remove "exec"
   ```

2. **Use read-only permissions** where possible:
   ```yaml
   verbs: ["get", "list"]
   ```

3. **Implement logging and monitoring** instead of exec access:
   - Use centralized logging (Fluentd, ELK stack)
   - Use kubectl logs instead of kubectl exec
   - Use debugging tools like ephemeral containers (K8s 1.23+)

4. **Grant exec permissions only when absolutely necessary** and with strict RBAC policies:
   - Limit to specific namespaces
   - Limit to specific service accounts
   - Use temporary credentials
   - Audit all exec usage

## References
- [SonarSource Rule: RSPEC-6868](https://rules.sonarsource.com/kubernetes/RSPEC-6868)
- [Kubernetes RBAC Best Practices](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Principle of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege)

---

**Test Status**: ✅ PASSED - Rule successfully detected 2 violations as expected
