# Sprint Story Files — Azure Track

Story files are the atomic handoff unit between planning and development.
Each file has full context, acceptance criteria, and definition of done.

**Pick up a story, implement it, mark status: done.**

## Wave Sequence (dependency order)

### Wave 1 — Start immediately (no deps, parallel)
| Story | Title | Status | SME |
|-------|-------|--------|-----|
| [AZ-01](AZ-01_azure_provider_bootstrap.md) | Bootstrap Azure provider directory | ready | Python/azure-mgmt-* |
| [AZ-01b](AZ-01b_remove_azure_stub.md) | Remove Azure scanner stub | ready | Python/azure-mgmt-* |
| [AZ-06](AZ-06_seed_relationships.md) | Seed Azure inventory relationships | ready | DBA + Security analyst |
| [SHARED-06](SHARED-06_argo_provider_url.md) | Fix Argo discovery URL (provider-dynamic) | done | DevOps |

### Wave 2 — After AZ-01
| Story | Title | Status | SME |
|-------|-------|--------|-----|
| [AZ-02](AZ-02_azure_client_factory.md) | AzureClientFactory | ready | Python/azure-mgmt-* |
| [AZ-02b](AZ-02b_timeout_wrapper.md) | Per-call timeout wrapper | ready | Python/azure-mgmt-* |

### Wave 3 — After AZ-02
| Story | Title | Status | SME |
|-------|-------|--------|-----|
| [AZ-03](AZ-03_azure_pagination.md) | Azure pagination helpers | ready | Python/azure-mgmt-* |

### Wave 4 — After AZ-03
| Story | Title | Status | SME |
|-------|-------|--------|-----|
| [AZ-04](AZ-04_azure_discovery_scanner.md) | AzureDiscoveryScanner (DB-driven) | ready | Python/azure-mgmt-* |

### Wave 5 — After AZ-04
| Story | Title | Status | SME |
|-------|-------|--------|-----|
| [AZ-05](AZ-05_register_provider.md) | Register provider + noise removal | ready | Backend |

### Wave 6 — After AZ-05 + all Wave 1 DB seeds
| Story | Title | Status | SME |
|-------|-------|--------|-----|
| [AZ-12](AZ-12_docker_build.md) | Docker build + EKS deploy | ready | DevOps |

### Wave 7 — After AZ-12 + AZ-06
| Story | Title | Status | SME |
|-------|-------|--------|-----|
| [AZ-13](AZ-13_e2e_scan.md) | E2E Azure scan validation | ready | QA + Backend |
| [AZ-15](AZ-15_neo4j_multicsp.md) | Neo4j multi-CSP label fix | ready | Backend/Neo4j |

### Wave 8 — After AZ-13 + AZ-15
| Story | Title | Status | SME |
|-------|-------|--------|-----|
| [AZ-16](AZ-16_toxic_combinations.md) | Seed Azure toxic combinations | ready | Threat analyst |
| [AZ-17b](AZ-17b_credential_resolution.md) | Credential resolution path | ready | Backend |

## Stories pending (not yet written)
AZ-07, AZ-08, AZ-08b, AZ-09, AZ-10, AZ-11, AZ-13b, AZ-14, AZ-17, AZ-18, CROSS-01,
SHARED-01 through SHARED-08 (except SHARED-06)

## BMAD Agent Workflow

```
bmad-po  → generates story files (this dir)
bmad-sm  → validates dependencies, sequences waves
bmad-dev → implements one story at a time
bmad-qa  → validates acceptance criteria
bmad-architect → reviews complex stories before merge
```

Invoke agents via: `/agents/{agent-name}` in Claude Code