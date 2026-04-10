# Discovery Noise Removal — All CSPs

## Principle

A discovery is NOISE if:
1. It does not return a named, persistent resource (monitoring metrics, events, logs)
2. The data returned is not used by ANY check rule, IAM rule, threat rule, or inventory
3. It requires resource-specific parameters without a parent (causes "missing required param" errors)
4. It is managed entirely by the CSP and not configurable by the customer (service endpoints, pricing)

## AWS — Already Done (from 2026-03-21 session)

Disabled: resource-explorer-2, config, osis, greengrass, greengrassv2, resiliencehub,
memorydb, mediaconnect, keyspaces, ram, autoscaling, backup-gateway, backupsearch,
resourcegroupstaggingapi, synthetics, ecr-public
+ elasticbeanstalk/solution_stacks, elb/policies, backup/plans

Remaining parameter-validation errors to fix (require parent data not yet collected):
- iotthingsgraph.get_upload_status (needs uploadId)
- customer-profiles.* (needs DomainName)
- pipes.describe_pipe (needs pipe name)
- parameterstore.describe_association (needs instanceId or associationId)
- wellarchitected.get_answer (needs workload + lens + question IDs)

Action: Set these to `skip_dependents=true` or remove from `rule_discoveries`

## Azure — Audit Required (174 configs)

Categories to remove:
- Billing/Cost: Microsoft.Consumption/*, Microsoft.CostManagement/*
- Monitoring: Microsoft.Insights/metricDefinitions, /logs
- Advisor: Microsoft.Advisor/recommendations (not security-specific)
- Activity Logs: Microsoft.Insights/activityLogs
- Resource Locks: Microsoft.Authorization/locks (admin, not security)
- Tags: tags endpoints (metadata only)
- Service Health: Microsoft.ResourceHealth/*
- Maintenance: Microsoft.Maintenance/*

Categories to keep:
- Microsoft.Compute/* (VMs, disks, images)
- Microsoft.Network/* (NSGs, VNets, load balancers, firewalls, WAF)
- Microsoft.Storage/* (accounts, containers, file shares)
- Microsoft.KeyVault/* (vaults, keys, secrets, certificates)
- Microsoft.Sql/* (servers, databases, firewall rules)
- Microsoft.Authorization/* (RBAC role assignments, policy assignments)
- Microsoft.ContainerService/* (AKS)
- Microsoft.Web/* (App Services)
- Microsoft.DocumentDB/* (CosmosDB)
- Microsoft.AAD/* (EntraID / Azure AD — through Graph API)
- Microsoft.Security/* (Defender for Cloud settings)

Estimated: Remove ~25-35 configs, keep ~140

## GCP — Audit Required (126 configs)

Remove:
- Cloud Billing API (billing.projects.getBillingInfo — unless needed for budget alerts)
- Cloud Monitoring (monitoring.timeSeries.list — metrics, not resources)
- Cloud Logging (logging.entries.list — log entries, not security config)
- Error Reporting (clouderrorreporting.*)
- Cloud Trace (cloudtrace.*)
- Cloud Profiler
- Resource Manager tags (only tag values, not resources)
- Cloud Scheduler (unless checking for SSRF or privilege escalation via HTTP targets)

Keep:
- compute.* (instances, firewalls, networks, subnets, disks, images)
- iam.* (service accounts, policies, roles, bindings)
- storage.* (buckets, ACLs, encryption)
- bigquery.* (datasets, tables — IAM policies)
- container.* (GKE clusters)
- cloudfunctions.* (functions — service account bindings)
- run.* (Cloud Run — service account bindings)
- sqladmin.* (Cloud SQL — encryption, public IP, auth)
- cloudkms.* (key rings, crypto keys)
- secretmanager.* (secrets — not values, just metadata)
- dns.* (managed zones — DNSSEC)
- cloudresourcemanager.* (project IAM policies)
- servicenetworking.* (VPC peering)

Estimated: Remove ~20-30 configs, keep ~100

## Kubernetes — Audit Required (17 configs — small)

Remove:
- events (kubernetes events — monitoring, not security)
- endpoints (derived from services, redundant)
- replicationcontrollers (deprecated, use deployments)
- componentstatuses (deprecated in k8s 1.19+)

Keep:
- pods (security context, privilege escalation, host PID/network)
- services (NodePort/LoadBalancer = external exposure)
- namespaces (isolation boundaries)
- nodes (kubelet config, version, taints)
- serviceaccounts (automountServiceAccountToken)
- configmaps (check for secrets in plaintext)
- secrets (count and type metadata only — never values)
- clusterroles
- clusterrolebindings
- roles
- rolebindings
- networkpolicies
- ingresses (TLS config)
- podsecuritypolicies (deprecated but present on older clusters)
- persistentvolumes (access modes)

Estimated: Remove 4 configs, keep 13

## OCI — Audit Required (156 configs, when creds available)

Remove:
- audit.events (log entries)
- monitoring.metrics
- usage.reports
- announcements
- work-requests (management operations in progress)

Keep: compute, identity, network, objectstorage, database, kms, certificates, waas, bastions

## Implementation

For each CSP, the noise removal is:
1. SQL: `UPDATE rule_discoveries SET enabled=false WHERE provider='{csp}' AND service IN (...)`
2. No code change needed — discovery engine already checks `enabled` flag
3. Document what was removed and why in this file