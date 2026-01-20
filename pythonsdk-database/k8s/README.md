# Kubernetes (K8s) Python SDK Database

This directory contains the Python SDK database structure for Kubernetes resources.

## Structure

In Kubernetes, "services" correspond to **resource types** (e.g., `pod`, `deployment`, `service`, `namespace`) rather than traditional cloud services.

Each resource type has:
- `k8s_dependencies_with_python_names_fully_enriched.json` - SDK operations & fields
- `dependency_index.json` - Entity dependency graph
- `direct_vars.json` - Field definitions & operators

## Resource Types

Core Kubernetes resources include:
- `pod` - Pods (containers)
- `deployment` - Deployments
- `service` - Services
- `namespace` - Namespaces
- `secret` - Secrets
- `configmap` - ConfigMaps
- `statefulset` - StatefulSets
- `daemonset` - DaemonSets
- `networkpolicy` - Network Policies
- `ingress` - Ingresses
- `persistentvolume` - Persistent Volumes
- `persistentvolumeclaim` - Persistent Volume Claims
- `serviceaccount` - Service Accounts
- `role` - RBAC Roles
- `rolebinding` - RBAC Role Bindings
- `clusterrole` - Cluster Roles
- `clusterrolebinding` - Cluster Role Bindings
- And more...

## Entity Naming Convention

K8s entities follow the format: `k8s.<resource_type>.<field_path>`

Examples:
- `k8s.pod.metadata.name`
- `k8s.deployment.spec.replicas`
- `k8s.service.spec.type`
- `k8s.namespace.metadata.name`

## Files

- `generate_dependency_index.py` - Generate dependency_index.json from SDK data
- `generate_direct_vars.py` - Generate direct_vars.json from SDK data
- `k8s_dependencies_with_python_names_fully_enriched.json` - SDK dependencies (generated from k8s_api_catalog)

## Status

🚧 **In Progress** - Initial setup

