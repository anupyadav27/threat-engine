"""One-time script to generate dast_docs/ rule metadata files."""
import json, os

DEST = os.path.join(os.path.dirname(__file__), "dast_docs")
os.makedirs(DEST, exist_ok=True)

rules = [
  {
    "filename": "strict_transport_security_missing_metadata.json",
    "rule_id": "Strict-Transport-Security",
    "title": "Strict-Transport-Security header missing",
    "description": "The HTTP Strict-Transport-Security (HSTS) header is not set. HSTS instructs browsers to only connect via HTTPS, preventing protocol downgrade attacks and cookie hijacking.",
    "status": "ready", "defaultSeverity": "High", "category": "Security",
    "recommendation": "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    "impact": "Attackers can perform SSL stripping and intercept traffic over plain HTTP.",
    "tags": ["security", "hsts", "transport"],
    "examples": {"noncompliant": [], "compliant": ["Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"]},
    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security", "https://owasp.org/www-project-secure-headers/"],
    "logic": {"checks": [{"type": "header_missing", "pattern": "Strict-Transport-Security", "message": "HSTS header missing", "context_keywords": ["hsts", "strict-transport", "transport-security", "https"]}]}
  },
  {
    "filename": "content_security_policy_missing_metadata.json",
    "rule_id": "Content-Security-Policy",
    "title": "Content-Security-Policy header missing",
    "description": "The Content-Security-Policy (CSP) header is not set. CSP prevents XSS and data injection attacks by declaring trusted content sources.",
    "status": "ready", "defaultSeverity": "High", "category": "Security",
    "recommendation": "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
    "impact": "Without CSP, the application is vulnerable to XSS and clickjacking.",
    "tags": ["security", "csp", "xss"],
    "examples": {"noncompliant": [], "compliant": ["Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"]},
    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"],
    "logic": {"checks": [{"type": "header_missing", "pattern": "Content-Security-Policy", "message": "CSP header missing", "context_keywords": ["csp", "content-security", "content_security", "xss"]}]}
  },
  {
    "filename": "x_frame_options_missing_metadata.json",
    "rule_id": "X-Frame-Options",
    "title": "X-Frame-Options header missing",
    "description": "The X-Frame-Options header is not set. This header prevents clickjacking by blocking the page from being embedded in iframes.",
    "status": "ready", "defaultSeverity": "High", "category": "Security",
    "recommendation": "Add: X-Frame-Options: DENY  or  X-Frame-Options: SAMEORIGIN",
    "impact": "Application is vulnerable to clickjacking attacks.",
    "tags": ["security", "clickjacking", "iframe"],
    "examples": {"noncompliant": [], "compliant": ["X-Frame-Options: DENY", "X-Frame-Options: SAMEORIGIN"]},
    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
    "logic": {"checks": [{"type": "header_missing", "pattern": "X-Frame-Options", "message": "X-Frame-Options missing", "context_keywords": ["frame", "clickjack", "iframe", "x-frame"]}]}
  },
  {
    "filename": "x_content_type_options_missing_metadata.json",
    "rule_id": "X-Content-Type-Options",
    "title": "X-Content-Type-Options header missing",
    "description": "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses enabling MIME confusion attacks.",
    "status": "ready", "defaultSeverity": "Medium", "category": "Security",
    "recommendation": "Add: X-Content-Type-Options: nosniff",
    "impact": "Browsers may execute files as a different MIME type than intended.",
    "tags": ["security", "mime", "content-type"],
    "examples": {"noncompliant": [], "compliant": ["X-Content-Type-Options: nosniff"]},
    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    "logic": {"checks": [{"type": "header_missing", "pattern": "X-Content-Type-Options", "message": "X-Content-Type-Options missing", "context_keywords": ["content-type", "mime", "nosniff", "x-content"]}]}
  },
  {
    "filename": "referrer_policy_missing_metadata.json",
    "rule_id": "Referrer-Policy",
    "title": "Referrer-Policy header missing",
    "description": "Without Referrer-Policy, the browser sends full URLs as the Referer header, potentially leaking sensitive path and query data to third parties.",
    "status": "ready", "defaultSeverity": "Medium", "category": "Security",
    "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    "impact": "Sensitive tokens or session IDs in URLs may be leaked to third-party sites.",
    "tags": ["security", "referrer", "information-disclosure"],
    "examples": {"noncompliant": [], "compliant": ["Referrer-Policy: strict-origin-when-cross-origin", "Referrer-Policy: no-referrer"]},
    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    "logic": {"checks": [{"type": "header_missing", "pattern": "Referrer-Policy", "message": "Referrer-Policy missing", "context_keywords": ["referrer", "referer", "referrer-policy"]}]}
  },
  {
    "filename": "permissions_policy_missing_metadata.json",
    "rule_id": "Permissions-Policy",
    "title": "Permissions-Policy header missing",
    "description": "The Permissions-Policy header is not set. This controls which browser features the page may use, reducing the attack surface.",
    "status": "ready", "defaultSeverity": "Low", "category": "Security",
    "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    "impact": "Malicious scripts could abuse browser APIs (geolocation, microphone, camera).",
    "tags": ["security", "permissions", "feature-policy"],
    "examples": {"noncompliant": [], "compliant": ["Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()"]},
    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
    "logic": {"checks": [{"type": "header_missing", "pattern": "Permissions-Policy", "message": "Permissions-Policy missing", "context_keywords": ["permissions", "feature-policy", "permissions-policy"]}]}
  },
  {
    "filename": "x_xss_protection_metadata.json",
    "rule_id": "X-XSS-Protection",
    "title": "X-XSS-Protection header misconfigured",
    "description": "X-XSS-Protection is deprecated. Modern applications should use CSP instead. If still present, ensure it does not enable auditor-bypass vulnerabilities.",
    "status": "ready", "defaultSeverity": "Low", "category": "Security",
    "recommendation": "Remove X-XSS-Protection and implement a strong Content-Security-Policy. If retained: X-XSS-Protection: 0",
    "impact": "Legacy XSS filter can be bypassed or exploited in older browsers.",
    "tags": ["security", "xss", "deprecated"],
    "examples": {"noncompliant": [], "compliant": ["X-XSS-Protection: 0  # disabled — use CSP instead", "Content-Security-Policy: default-src 'self'"]},
    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"],
    "logic": {"checks": [{"type": "header_check", "pattern": "X-XSS-Protection", "message": "X-XSS-Protection misconfigured", "context_keywords": ["x-xss", "xss-protection", "xss"]}]}
  },
  {
    "filename": "server_header_disclosure_metadata.json",
    "rule_id": "Server",
    "title": "Server header discloses technology information",
    "description": "The Server response header reveals web server software and version, aiding attacker fingerprinting.",
    "status": "ready", "defaultSeverity": "Info", "category": "Security",
    "recommendation": "Remove or obscure the Server header. nginx: server_tokens off; Apache: ServerTokens Prod; Express: app.disable('x-powered-by')",
    "impact": "Server fingerprinting helps attackers select targeted exploits.",
    "tags": ["security", "information-disclosure", "server"],
    "examples": {"noncompliant": [], "compliant": ["server_tokens off;  # nginx", "ServerTokens Prod   # Apache", "app.disable('x-powered-by')  # Express"]},
    "references": ["https://owasp.org/www-project-secure-headers/#server"],
    "logic": {"checks": [{"type": "header_disclosure", "pattern": "Server", "message": "Server header discloses version", "context_keywords": ["server", "server-header", "server_tokens", "x-powered-by"]}]}
  },
  {
    "filename": "business_logic_method_override_metadata.json",
    "rule_id": "Business Logic \u2013 Method Override",
    "title": "HTTP Method Override vulnerability",
    "description": "The application accepts HTTP method overrides via X-HTTP-Method-Override or _method parameters, allowing attackers to tunnel DELETE/PUT over POST and bypass access controls.",
    "status": "ready", "defaultSeverity": "High", "category": "Security",
    "recommendation": "Disable method-override middleware. If required, validate the caller is authenticated and authorised for the overridden method.",
    "impact": "Attackers can perform DELETE/PUT operations by tunnelling over POST, bypassing firewalls and proxies.",
    "tags": ["security", "business-logic", "method-override", "owasp"],
    "examples": {"noncompliant": [], "compliant": ["# Express: remove app.use(methodOverride())", "# Django: do not process X-HTTP-Method-Override header"]},
    "references": ["https://owasp.org/www-community/attacks/HTTP_Verb_Tampering"],
    "logic": {"checks": [{"type": "request_check", "pattern": "X-HTTP-Method-Override|X-Method-Override|_method", "message": "Method override accepted", "context_keywords": ["method-override", "method override", "x-http-method", "verb tamper", "Method Override"]}]}
  },
  {
    "filename": "business_logic_param_tamper_metadata.json",
    "rule_id": "Business Logic \u2013 Param Tamper",
    "title": "Parameter tampering vulnerability",
    "description": "Critical parameters (price, quantity, user_id) are not validated server-side. Attackers can modify these to manipulate business outcomes.",
    "status": "ready", "defaultSeverity": "High", "category": "Security",
    "recommendation": "Validate all business-critical parameters server-side. Use HMAC signing for tamper-evident values. Never trust client-supplied pricing or IDs.",
    "impact": "Attackers can manipulate prices, access other users data, or bypass business rules.",
    "tags": ["security", "business-logic", "parameter-tampering", "owasp"],
    "examples": {"noncompliant": [], "compliant": ["price = Product.objects.get(id=product_id).price  # fetch from DB, never client", "token = hmac.new(SECRET, param.encode()).hexdigest()  # sign critical params"]},
    "references": ["https://owasp.org/www-community/attacks/Web_Parameter_Tampering"],
    "logic": {"checks": [{"type": "logic_check", "pattern": "param.*tamper|price.*param", "message": "Parameter tampering risk", "context_keywords": ["param tamper", "Param Tamper", "parameter tamper", "price", "quantity"]}]}
  },
  {
    "filename": "business_logic_forced_browsing_metadata.json",
    "rule_id": "Business Logic \u2013 Forced Browsing",
    "title": "Forced browsing / Insecure Direct Object Reference (IDOR)",
    "description": "The application exposes direct object references without authorisation checks. Attackers can access resources by guessing or incrementing IDs.",
    "status": "ready", "defaultSeverity": "High", "category": "Security",
    "recommendation": "Implement authorisation checks on every resource access. Use random UUIDs instead of sequential IDs. Apply deny-by-default access control.",
    "impact": "Unauthorised access to sensitive data, files, admin pages, or other users records.",
    "tags": ["security", "idor", "forced-browsing", "owasp", "access-control"],
    "examples": {"noncompliant": [], "compliant": ["record = Record.objects.get(id=record_id, owner=request.user)  # always check ownership", "id = models.UUIDField(default=uuid.uuid4, editable=False)  # use UUID PKs"]},
    "references": ["https://owasp.org/www-community/attacks/Forced_browsing", "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"],
    "logic": {"checks": [{"type": "logic_check", "pattern": "forced.brows|idor|direct.object", "message": "Forced browsing / IDOR risk", "context_keywords": ["forced browsing", "Forced Browsing", "idor", "direct object", "unauthorised"]}]}
  },
]

for rule in rules:
    path = os.path.join(DEST, rule["filename"])
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rule, f, indent=2)
    print(f"  Created: {rule['filename']}")

print(f"\nTotal: {len(rules)} DAST rules created in dast_docs/")
