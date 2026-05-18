# Story PC-DEPTH-02: Network Engine — Azure / GCP / OCI / AliCloud 7-Layer Topology Refactor

## Status: done

## Metadata
- **Phase**: Analysis Depth Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 8 (2 pts per CSP × 4 CSPs)
- **Priority**: P1 — 4 CSPs produce flat findings; L1-L7 sub-layer scores and `is_in_private_subnet` are null
- **Depends on**: PC-P1-05 (network `is_in_private_subnet` + `network_detail` writer)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer

## Gap Being Closed

AWS network provider (`providers/aws.py`) is organized into 7 internal sub-layers (L1 isolation → L7 monitoring), each a separate analysis method. Azure, GCP, OCI, and AliCloud providers exist but are **flat implementations** — they return findings in a single analyze() call without sub-layer decomposition.

**Consequences:**
- `is_in_private_subnet` column is never written for non-AWS resources (network engine doesn't mark public vs private)
- `network_exposure_score` is a flat count, not a weighted 7-layer score
- `findings_by_layer` in network_report is always `{"layer1_check": N}` for non-AWS (Layer 2 topology not broken out)
- Attack-path engine can't compute effective exposure for non-AWS resources

---

## Data Required Per CSP

### Azure

**Source: Discovery Engine (`discovery_findings`)**

| Discovery ID | Sub-layer | What it provides |
|-------------|-----------|-----------------|
| `azure.network.list_virtual_networks` | L1 Isolation | VNet address space, peering config, DDoS protection |
| `azure.network.list_subnets` | L2 Reachability | Subnet `privateEndpointNetworkPolicies`, public vs private |
| `azure.networksecuritygroup.list_network_security_groups` | L3 ACL | NSG rules: direction, protocol, source/dest prefix, access |
| `azure.network.list_route_tables` | L2 Reachability | Custom routes, `nextHopType=Internet` on private subnets |
| `azure.network.list_load_balancers` | L5 LB | `frontendIPConfigurations[].publicIPAddress` → internet-facing |
| `azure.application.list_application_gateways` | L5 LB | WAF-enabled AppGW vs basic AppGW |
| `azure.network.list_public_ip_addresses` | L4 Firewall | All public IPs — cross-ref with VM/LB/AppGW |
| `azure.network.list_firewalls` | L6 WAF | Azure Firewall policy, threat intelligence mode |
| `azure.applicationinsights.list_components` | L7 Monitoring | NSG Flow Logs enabled on network watcher |

**Key analysis per sub-layer:**
- **L1**: VNet without DDoS protection → MEDIUM. VNet peering with `allowGatewayTransit=true` to untrusted VNet → HIGH
- **L2**: Subnet with `privateEndpointNetworkPolicies=Disabled` + has private endpoints → reachability gap
- **L3**: NSG rule `0.0.0.0/0` inbound on port 22/3389/1433 → CRITICAL. NSG not attached to subnet (only NIC-level) → HIGH
- **L4**: Public IP attached directly to VM NIC (no LB) → CRITICAL
- **L5**: LB with public frontend and no NSG on backend pool → HIGH. AppGW without WAF policy → HIGH
- **L6**: Azure Firewall in Alert mode (not Deny) → MEDIUM
- **L7**: No NSG flow logs in Network Watcher for the VNet region → HIGH

**CDR data used:** NOT needed for topology (topology is config-based, not log-based).

---

### GCP

**Source: Discovery Engine (`discovery_findings`)**

| Discovery ID | Sub-layer | What it provides |
|-------------|-----------|-----------------|
| `gcp.compute.list_networks` | L1 Isolation | VPC mode (auto vs custom), subnets, peering |
| `gcp.compute.list_subnetworks` | L2 Reachability | `privateIpGoogleAccess`, `purpose` (private vs regular) |
| `gcp.compute.list_firewalls` | L3/L4 ACL | Firewall rules: direction, sourceRanges, targetTags, allowed[].ports |
| `gcp.compute.list_routers` | L2 Reachability | Cloud NAT config — outbound-only vs full-cone |
| `gcp.compute.list_forwarding_rules` | L5 LB | External vs Internal loadBalancingScheme |
| `gcp.networksecurity.list_security_policies` | L6 WAF | Cloud Armor policies: rules, preview vs enforce mode |
| `gcp.compute.list_backend_services` | L5 LB | Cloud Armor policy attached to backend? |
| `gcp.networkservices.list_gateways` | L5 LB | Gateway API resources |
| `gcp.networkmanagement.list_connectivity_tests` | L7 Monitoring | VPC Flow Logs per subnet enabled |

**Key analysis per sub-layer:**
- **L1**: Auto-mode VPC (default routes include RFC-1918 cross-subnet) → MEDIUM for production workloads
- **L2**: Subnet with `privateIpGoogleAccess=false` → VMs need external IP for Google APIs → MEDIUM
- **L3**: Firewall rule `sourceRanges:["0.0.0.0/0"]` on port 22 (SSH) without target tag → CRITICAL. Default-allow-ssh/rdp rules still active → CRITICAL
- **L4**: Compute instance without any deny-all firewall rule → gap
- **L5**: External forwarding rule (EXTERNAL scheme) on port 443 without Cloud Armor → HIGH
- **L6**: Cloud Armor in preview mode (logs but doesn't block) → MEDIUM
- **L7**: `logConfig.enable=false` on subnet → VPC Flow Logs disabled → HIGH

---

### OCI

**Source: Discovery Engine (`discovery_findings`)**

| Discovery ID | Sub-layer | What it provides |
|-------------|-----------|-----------------|
| `oci.network.list_vcns` | L1 Isolation | VCN CIDR, DNS label, security attributes |
| `oci.network.list_subnets` | L2 Reachability | `prohibitPublicIpOnVnic` → private subnet flag |
| `oci.network.list_security_lists` | L3 ACL | Security list rules: source/dest, protocol, portRange |
| `oci.network.list_network_security_groups` | L3 ACL | NSG rules attached to specific VNICs |
| `oci.network.list_route_tables` | L2 Reachability | Routes with `networkEntityId` pointing to IGW = internet-facing |
| `oci.network.list_internet_gateways` | L4 Firewall | IGW presence per VCN |
| `oci.network.list_load_balancers` | L5 LB | `isPrivate=false` → internet-facing LB |
| `oci.waas.list_waas_policies` | L6 WAF | WAAS policies: DDoS, bot management, threat feeds |
| `oci.logging.list_log_groups` | L7 Monitoring | VCN flow log groups enabled |

**Key analysis per sub-layer:**
- **L1**: VCN without `securityAttributes` → no fine-grained labeling for ZeroTrust → LOW
- **L2**: Subnet with `prohibitPublicIpOnVnic=false` (allows public IPs on VNICs) → compute can get public IP → MEDIUM
- **L3**: Security list allowing `0.0.0.0/0` TCP on port 22 ingress → CRITICAL
- **L4**: Route table has route to IGW for private subnet CIDR → CRITICAL (traffic egress via internet)
- **L5**: Public-facing LB (`isPrivate=false`) with no WAF policy → HIGH
- **L6**: No WAAS policy for internet-facing LB → HIGH
- **L7**: No flow log enabled for the VCN → HIGH

---

### AliCloud

**Source: Discovery Engine (`discovery_findings`)**

| Discovery ID | Sub-layer | What it provides |
|-------------|-----------|-----------------|
| `alicloud.vpc.list_vpcs` | L1 Isolation | VPC CIDR, classic-mode vs VPC-mode |
| `alicloud.vpc.list_vswitches` | L2 Reachability | VSwitch zone, `availableIpAddressCount` (public IP usage) |
| `alicloud.ecs.list_security_groups` | L3/L4 ACL | SG rules: direction, cidrIp, portRange, nicType |
| `alicloud.vpc.list_route_tables` | L2 Reachability | Route entries with destination `0.0.0.0/0` nextHop=Internet |
| `alicloud.slb.list_load_balancers` | L5 LB | `AddressType=internet` → internet-facing SLB |
| `alicloud.waf.list_instances` | L6 WAF | WAF instances + domain bindings |
| `alicloud.actiontrail.list_trails` | L7 Monitoring | ActionTrail enabled (VPC event logging) |

**Key analysis per sub-layer:**
- **L1**: Classic-mode network (non-VPC) detected → CRITICAL (no isolation boundary)
- **L3**: Security group inbound rule `cidrIp=0.0.0.0/0` on port 22/3389 → CRITICAL
- **L4**: ECS instance in a SG with no deny-all → effective exposure HIGH
- **L5**: SLB with `AddressType=internet` and no WAF binding → HIGH
- **L6**: WAF instance not bound to the internet-facing SLB domain → HIGH
- **L7**: ActionTrail not enabled for the region → HIGH

---

## Implementation Steps

For each CSP provider file (`providers/azure.py`, `providers/gcp.py`, `providers/oci.py`, `providers/alicloud.py`):

1. **Decompose the flat `analyze()` into 7 private methods:**
```python
def analyze(self, scan_run_id, tenant_id, account_id, ...):
    disc_data = self._load_discovery(scan_run_id, tenant_id, account_id)
    findings = []
    findings.extend(self._analyze_isolation(disc_data))       # L1
    findings.extend(self._analyze_reachability(disc_data))    # L2
    findings.extend(self._analyze_acl(disc_data))             # L3
    findings.extend(self._analyze_firewall(disc_data))        # L4
    findings.extend(self._analyze_load_balancer(disc_data))   # L5
    findings.extend(self._analyze_waf(disc_data))             # L6
    findings.extend(self._analyze_monitoring(disc_data))      # L7
    return {"findings": findings, "topology_snapshots": [...], ...}
```

2. **For each subnet resource: set `is_private=True/False`** based on CSP-specific field:
- Azure: subnet has no `publicIPAddress` in connected resources + `privateEndpointNetworkPolicies` settings
- GCP: subnetwork `purpose=PRIVATE` or `privateIpGoogleAccess=true`
- OCI: subnet `prohibitPublicIpOnVnic=true`
- AliCloud: no `eipAddress` on VSwitch resources

3. **Write `is_in_private_subnet` to topology snapshot** so network posture writer (PC-P1-05) can populate the posture column.

---

## Output

### `network_findings` table
Findings now tagged with `network_layer`: `"L1"` through `"L7"`.

### `network_report` table
`findings_by_layer` JSONB now shows layer breakdown for Azure/GCP/OCI/AliCloud (not just `layer1_check`).

### `resource_security_posture` table
`is_in_private_subnet` now populated for Azure/GCP/OCI/AliCloud resources (currently always null for non-AWS).

---

## Acceptance Criteria

- [ ] AC-1: Azure `analyze()` decomposed into L1-L7 private methods; `findings_by_layer` in network_report shows all 7 layers for Azure scans
- [ ] AC-2: GCP `analyze()` same — `gcp.compute.firewalls.default_allow_ssh_disabled` fires for VPCs with default-allow-ssh rule still active
- [ ] AC-3: OCI `analyze()` — `oci.network.subnet.prohibit_public_ip` fires for subnets with `prohibitPublicIpOnVnic=false`
- [ ] AC-4: AliCloud `analyze()` — `alicloud.vpc.security_group.no_open_ssh` fires for SGs with `0.0.0.0/0:22` inbound
- [ ] AC-5: `is_in_private_subnet` written to `resource_security_posture` for at least Azure and GCP resources after scan
- [ ] AC-6: No regression on AWS — AWS Layer 2 topology findings unchanged
- [ ] AC-7: All discovery queries include `AND tenant_id = %s`

## MITRE ATT&CK
| Technique | Addressed by |
|-----------|-------------|
| T1190 | Exploit Public-Facing Application — internet-facing LB without WAF |
| T1021.004 | Remote Services: SSH — open SSH in SG/NSG/security-list |
| T1498 | Network Denial of Service — no DDoS protection on VNet/VPC |

## Definition of Done
- [ ] Azure, GCP, OCI, AliCloud providers refactored to 7 sub-layer methods
- [ ] Each CSP: at least 5 findings per sub-layer category in tests
- [ ] `is_in_private_subnet` populated for non-AWS resources
- [ ] Network engine rebuilt and deployed
- [ ] After Azure scan: `SELECT findings_by_layer FROM network_report WHERE provider='azure' ORDER BY completed_at DESC LIMIT 1` shows all L1-L7 keys
