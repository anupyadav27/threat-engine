# Story PC-P2-03: Network Engine — IBM Cloud + K8s Topology (the two actual stubs)

## Status: done

## Metadata
- **Phase**: P2 — Tier B
- **Sprint**: Posture Coverage Enhancement
- **Points**: 8
- **Priority**: P2
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer

## Correction Note

**The original story said "Azure NSG + GCP VPC topology are stubs."** This was wrong.
After reading the actual provider files:

| CSP | Network L2 Status |
|-----|------------------|
| AWS | ✅ Full 7-layer implementation |
| Azure | ✅ Full 7-layer (VNet/NSG/AppGW/WAF/NetworkWatcher) |
| GCP | ✅ Full 7-layer (VPC/Firewall/Routes/CloudArmor/FlowLogs) |
| OCI | ✅ Full 7-layer (VCN/SecurityLists/NSG/WAAS/FlowLogs) |
| AliCloud | ✅ Full 7-layer (VPC/SecurityGroups/SLB/WAF/ActionTrail) |
| **IBM** | ❌ STUB — `IBMNetworkProvider.analyze()` returns 0 findings |
| **K8s** | ❌ DEFERRED — Layer 1 (check findings) only; no topology analysis |

This story implements the two genuine stubs.

## Gap: IBM Cloud

**Current:** `IBMNetworkProvider` is a stub that logs "not yet implemented" and returns empty.

**IBM Cloud network resources** discoverable (112 discovery files, 107 network-tagged check rules):
- VPC + Subnets (`ibm.vpc.list_vpcs`, `ibm.is.subnets.list_subnets`)
- Security Groups (`ibm.is.security_groups.list_security_groups`)
- Network ACLs (`ibm.is.network_acls.list_network_acls`)
- Public Gateways (`ibm.is.public_gateways.list_public_gateways`) — internet-exposure signal
- Load Balancers (`ibm.is.load_balancers.list_load_balancers`)
- VPN Gateways (`ibm.is.vpn_gateways.list_vpn_gateways`)
- Flow Logs (`ibm.is.flow_log_collectors.list_flow_log_collectors`)

**7-Layer mapping for IBM:**
| Layer | IBM Equivalent | Discovery ID |
|-------|---------------|-------------|
| L1 Isolation | VPC structure | `ibm.vpc.list_vpcs` |
| L2 Routing | Custom routes with internet destination | `ibm.is.routing_tables.list_routing_tables` |
| L3 ACL | Network ACL inbound ALLOW rules | `ibm.is.network_acls.list_network_acls` |
| L4 Firewall | Security Group rules open to 0.0.0.0/0 on critical ports | `ibm.is.security_groups.list_security_groups` |
| L5 LB | Internet-facing LB with HTTP-only listener | `ibm.is.load_balancers.list_load_balancers` |
| L6 WAF | IBM Cloud Internet Services WAF coverage | `ibm.cis.list_instances` (if available) |
| L7 Monitoring | VPC Flow Log collectors enabled | `ibm.is.flow_log_collectors.list_flow_log_collectors` |

**Implementation:** Fill out `engines/network-security/network_security_engine/providers/ibm.py` following the OCI provider as the closest structural reference (VCN ≈ VPC, Security Lists ≈ Network ACLs, NSG ≈ Security Groups).

## Gap: Kubernetes

**Current:** `K8sNetworkProvider` is deferred. Layer 1 (check_findings with `network_security=true`) handles rule-based K8s network findings — but only 7 k8s rules are tagged for network_security, which is very thin.

**K8s network topology analysis is fundamentally different from cloud CSPs:**
- K8s has no VPC/VNet — isolation is via Namespace + NetworkPolicy
- "Internet exposure" = Service type LoadBalancer or NodePort + Ingress resource
- "Firewall" = NetworkPolicy (ingress/egress selectors)
- "WAF" = Ingress controller with ModSecurity / AWS WAF on ALB
- "Monitoring" = Network flow logs via CNI (Calico, Cilium — optional)

**7-Layer mapping for K8s:**
| Layer | K8s Equivalent | Discovery ID |
|-------|---------------|-------------|
| L1 Isolation | Namespace exists + NetworkPolicy present | `k8s.core.list_namespaces_for_all_namespaces` |
| L2 Routing | N/A — CNI handles routing; check Egress NetworkPolicy | `k8s.networking.list_network_policies_for_all_namespaces` |
| L3 ACL | NetworkPolicy ingress rules — missing = permit-all | `k8s.networking.list_network_policies_for_all_namespaces` |
| L4 Firewall | Pods in namespaces with no NetworkPolicy = open | Same as L3 |
| L5 LB | Services of type LoadBalancer or NodePort (internet-exposed) | `k8s.core.list_services_for_all_namespaces` |
| L6 WAF | Ingress annotations: `nginx.ingress.kubernetes.io/modsecurity-*` | `k8s.networking.list_ingresses_for_all_namespaces` |
| L7 Monitoring | CNI flow log annotation (Calico/Cilium) — not universally discoverable | Best-effort |

**K8s posture signals:**
- `is_internet_exposed=TRUE`: Service type=LoadBalancer with externalIP OR NodePort
- `is_in_private_subnet=FALSE`: All K8s pods are in the cluster network; no "private subnet" concept — set FALSE always for K8s
- `has_waf=TRUE`: Ingress has ModSecurity or ALB WAF annotation
- `container_network_policy_missing=TRUE`: Namespace has pods but no NetworkPolicy (write to container posture column, not network column)

## Acceptance Criteria

### IBM Cloud
- [ ] AC-1: `IBMNetworkProvider.analyze()` returns L4 findings for Security Groups with inbound 0.0.0.0/0 on port 22/3389/5432
- [ ] AC-2: `is_internet_exposed=TRUE` for IBM VSIs (Virtual Server Instances) with a Public Gateway attached to their subnet
- [ ] AC-3: `has_waf=FALSE` correctly set for IBM resources not behind IBM CIS WAF (if CIS discovery ID unavailable, default false with INFO log)
- [ ] AC-4: L7 monitoring: `network_findings` includes a finding when VPC Flow Log Collectors count = 0 for a VPC

### K8s
- [ ] AC-5: Services of type LoadBalancer with `externalIP` set → `is_internet_exposed=TRUE` in posture table
- [ ] AC-6: Namespaces with no NetworkPolicy → `container_network_policy_missing=TRUE` (written to posture via container engine signal, not network)
- [ ] AC-7: `has_waf=TRUE` for Ingress resources with ModSecurity annotation
- [ ] AC-8: AWS L2 topology regression: zero change to AWS findings after this PR

### Both
- [ ] AC-9: New image: `yadavanup84/engine-network-security:v-net-ibm-k8s1`
- [ ] AC-10: Post-deploy: `SELECT provider, COUNT(*) FROM network_findings WHERE scan_run_id=<recent> GROUP BY provider` shows `ibm` and `k8s` rows with count > 0

## Definition of Done
- [ ] `ibm.py` fully implemented (7-layer)
- [ ] `k8s.py` implemented (L1-L6, L7 best-effort)
- [ ] Integration tests for both new providers
- [ ] Image deployed and rollout clean