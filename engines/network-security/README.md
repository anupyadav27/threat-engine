# Network Security Engine

7-layer network posture analysis engine that mirrors the actual network stack.

## Architecture

```
Layer 7: Flow Analysis       — VPC Flow Logs (config vs. runtime gap)
Layer 6: WAF / Shield        — L7 protection on LBs/CloudFront/APIGW
Layer 5: Load Balancers      — ALB/NLB/CLB exposure, TLS, listeners
Layer 4: Security Groups     — stateful firewall (per-resource) ← most findings
Layer 3: Network ACLs        — stateless firewall (subnet boundary)
Layer 2: Network Reachability — route tables, IGW, NAT, cross-VPC paths
Layer 1: Network Topology     — VPC, subnets, peering, TGW
```

Each layer builds on the one below. The key differentiator is **effective exposure** —
combining all layers to determine if a resource is truly internet-reachable, not just
what a single SG rule says.

## 8 Security Modules

| Module | Layers | Focus |
|--------|--------|-------|
| `network_isolation` | L1 | VPC segmentation, peering, TGW, default VPC |
| `network_reachability` | L2 | Route hygiene, blackholes, cross-env paths |
| `network_acl` | L3 | NACL rules, default NACL on public subnets |
| `security_group_rules` | L4 | Open ports, overly permissive, orphaned SGs |
| `load_balancer_security` | L5 | TLS, HTTP-only listeners, internal in public |
| `waf_protection` | L6 | WAF coverage, rule gaps, rate limiting |
| `internet_exposure` | L4+L5 | True internet exposure (all layers combined) |
| `network_monitoring` | L7 | Flow logs, WAF logging, DNS logging |

## Port: 8004

## API Endpoints

```
POST /api/v1/network-security/scan           — Trigger scan
GET  /api/v1/network-security/{id}/status     — Poll status
GET  /api/v1/network-security/ui-data         — Unified UI payload
GET  /api/v1/network-security/findings        — Query with filters
GET  /api/v1/network-security/topology        — VPC topology map
GET  /api/v1/network-security/modules         — List 8 modules
GET  /api/v1/health/live                      — Liveness
GET  /api/v1/health/ready                     — Readiness
```

## Pipeline Position

```
Discovery → Inventory → Check → Threat → Network + Compliance + IAM + DataSec (parallel)
```

## Database: threat_engine_network

Tables: `network_report`, `network_findings`, `network_topology_snapshot`,
`network_sg_analysis`, `network_exposure_paths`, `network_anomalies`, `network_baselines`

## Threat Engine Integration

Produces enriched `finding_data` JSONB with:
- `network_relationships` — consumed by threat graph builder
- `mitre_techniques` — mapped per finding
- `attack_path_category` — exposure / lateral_movement
- `blast_radius` — downstream resource count
- `effective_internet_exposure` — combined L1+L2+L3+L4 assessment
