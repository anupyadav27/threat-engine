# Noncompliant example: hard-coded sensitive data
api_key = "my_secret_key"
password = "supersecret"
secret = "topsecret"
access_key = "AKIAIOSFODNN7EXAMPLE"
credentials = "user:pass"

def safe_usage():
    # Compliant example: generated securely
    import secrets
    api_key = secrets.token_hex(16)
    return api_key
