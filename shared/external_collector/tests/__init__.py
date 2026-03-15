"""
Unit Tests — External Collector
Task 0.3.17 [Seq 41 | QA]

Test suite for all External Collector components:
  - Registry Adapter (Docker Hub, ECR, manifest parsing)
  - Trivy Scanner (CVE extraction, SBOM generation)
  - Code Repo Adapter (GitHub, GitLab manifest files)
  - NVD Adapter (CVE parsing, bulk download)
  - Package Registry Adapter (npm, PyPI, Maven, Crates)
  - Threat Intel Adapter (AbuseIPDB, OTX IOC parsing)
  - Cache Manager (TTL expiration, refresh scheduling)
  - Rate Limiter (token bucket, per-source limits)
"""

__version__ = "0.3.17"
