import logging
from typing import Any, Dict, List

from api_security_engine.providers.base import BaseAPISecProvider
from api_security_engine.input.check_finding_reader import load_check_findings
from api_security_engine.input.discovery_reader import load_api_discoveries

logger = logging.getLogger("api_security.k8s_provider")

# Annotations that indicate authentication is enforced at the ingress layer
_AUTH_ANNOTATIONS = {
    "nginx.ingress.kubernetes.io/auth-url",
    "nginx.ingress.kubernetes.io/auth-signin",
    "konghq.com/plugins",
    "traefik.ingress.kubernetes.io/router.middlewares",
    "alb.ingress.kubernetes.io/auth-type",
}

# Annotations that enforce TLS redirect
_TLS_REDIRECT_ANNOTATIONS = {
    "nginx.ingress.kubernetes.io/ssl-redirect",
    "nginx.ingress.kubernetes.io/force-ssl-redirect",
}


def _has_auth_annotation(annotations: dict) -> bool:
    return bool(set(annotations.keys()) & _AUTH_ANNOTATIONS)


def _has_tls_configured(spec: dict) -> bool:
    tls = spec.get("tls") or []
    return len(tls) > 0


def _has_tls_redirect(annotations: dict) -> bool:
    for key in _TLS_REDIRECT_ANNOTATIONS:
        if annotations.get(key, "false").lower() == "true":
            return True
    return False


class K8sAPISecProvider(BaseAPISecProvider):
    """K8s API Security provider — Ingress + Gateway API analysis."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn,
        check_conn,
    ) -> List[Dict[str, Any]]:
        check_findings = load_check_findings(check_conn, scan_run_id, tenant_id)
        logger.info(f"K8s provider: {len(check_findings)} check findings")

        api_resources = load_api_discoveries(
            discoveries_conn, scan_run_id, tenant_id, provider="k8s"
        )
        logger.info(f"K8s provider: {len(api_resources)} K8s Ingress/Gateway resources")

        all_findings: List[Dict[str, Any]] = list(check_findings)

        for res in api_resources:
            config = res.get("configuration") or {}
            rtype = res["resource_type"]
            metadata = config.get("metadata", {}) or {}
            annotations = metadata.get("annotations", {}) or {}
            spec = config.get("spec", {}) or {}
            name = metadata.get("name") or res.get("resource_name", "")
            namespace = metadata.get("namespace", "")

            if rtype == "k8s.networking.ingress":
                has_auth = _has_auth_annotation(annotations)
                has_tls = _has_tls_configured(spec)
                has_tls_redirect = _has_tls_redirect(annotations)
                rules = spec.get("rules", []) or []

                # Check: no auth annotation on ingress
                if not has_auth:
                    all_findings.append({
                        "rule_id": "k8s.networking.ingress.no_auth_annotation",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "high",
                        "title": "Kubernetes Ingress has no authentication annotation",
                        "description": (
                            f"Ingress '{name}' in namespace '{namespace}' has no auth-url, "
                            "auth-type, or equivalent authentication middleware annotation. "
                            "Traffic reaches backend services without identity verification."
                        ),
                        "remediation": (
                            "Add nginx.ingress.kubernetes.io/auth-url or "
                            "alb.ingress.kubernetes.io/auth-type annotation to enforce "
                            "OAuth2/OIDC authentication at the ingress layer."
                        ),
                        "owasp_api_category": "API2",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": f"{namespace}/{name}",
                        "api_stage": "",
                        "evidence": {
                            "annotationKeys": list(annotations.keys()),
                            "ruleCount": len(rules),
                        },
                    })

                # Check: TLS not configured
                if not has_tls:
                    all_findings.append({
                        "rule_id": "k8s.networking.ingress.no_tls",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "high",
                        "title": "Kubernetes Ingress has no TLS configuration",
                        "description": (
                            f"Ingress '{name}' in namespace '{namespace}' has no TLS block. "
                            "All traffic is served over plain HTTP."
                        ),
                        "remediation": (
                            "Add a spec.tls block referencing a TLS Secret, or use "
                            "cert-manager to automatically provision certificates."
                        ),
                        "owasp_api_category": "API8",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": f"{namespace}/{name}",
                        "api_stage": "",
                        "evidence": {"hasTLS": False, "namespace": namespace},
                    })

                # Check: TLS configured but no redirect (HTTP still open)
                elif has_tls and not has_tls_redirect:
                    all_findings.append({
                        "rule_id": "k8s.networking.ingress.no_tls_redirect",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "medium",
                        "title": "Kubernetes Ingress does not redirect HTTP to HTTPS",
                        "description": (
                            f"Ingress '{name}' has TLS configured but no ssl-redirect or "
                            "force-ssl-redirect annotation. Plain HTTP requests are still accepted."
                        ),
                        "remediation": (
                            "Set nginx.ingress.kubernetes.io/ssl-redirect: 'true' and "
                            "nginx.ingress.kubernetes.io/force-ssl-redirect: 'true' annotations."
                        ),
                        "owasp_api_category": "API8",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": f"{namespace}/{name}",
                        "api_stage": "",
                        "evidence": {"hasTLS": True, "sslRedirect": False},
                    })

            elif rtype == "k8s.gateway.gateway":
                listeners = spec.get("listeners", []) or []
                has_https_listener = any(
                    (li.get("protocol") or "").upper() in {"HTTPS", "TLS"}
                    for li in listeners
                )
                if not has_https_listener:
                    all_findings.append({
                        "rule_id": "k8s.gateway.gateway.no_https_listener",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "high",
                        "title": "Kubernetes Gateway has no HTTPS/TLS listener",
                        "description": (
                            f"Gateway '{name}' in namespace '{namespace}' has no listener "
                            "with HTTPS or TLS protocol. All traffic is served unencrypted."
                        ),
                        "remediation": (
                            "Add an HTTPS listener to the Gateway spec with a certificateRefs "
                            "block pointing to a TLS Secret."
                        ),
                        "owasp_api_category": "API8",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": f"{namespace}/{name}",
                        "api_stage": "",
                        "evidence": {
                            "listeners": [li.get("protocol") for li in listeners]
                        },
                    })

            elif rtype == "k8s.gateway.httproute":
                # Check HTTPRoute for missing filters (auth, rate limiting)
                rules = spec.get("rules", []) or []
                has_ext_auth = any(
                    any(
                        f.get("type") == "ExtensionRef"
                        for f in (rule.get("filters") or [])
                    )
                    for rule in rules
                )
                if not has_ext_auth and rules:
                    all_findings.append({
                        "rule_id": "k8s.gateway.httproute.no_auth_filter",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "medium",
                        "title": "Kubernetes HTTPRoute has no authentication filter",
                        "description": (
                            f"HTTPRoute '{name}' in namespace '{namespace}' has no ExtensionRef "
                            "filter for authentication. Requests pass through without identity checks."
                        ),
                        "remediation": (
                            "Add an ExtensionRef filter pointing to a ReferenceGrant-approved "
                            "auth policy (e.g., AuthPolicy from Gateway API extensions)."
                        ),
                        "owasp_api_category": "API2",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": f"{namespace}/{name}",
                        "api_stage": "",
                        "evidence": {"ruleCount": len(rules)},
                    })

        logger.info(f"K8s provider complete: {len(all_findings)} findings")
        return all_findings
