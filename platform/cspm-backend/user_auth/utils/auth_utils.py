# utils/auth_utils.py
import secrets
from django.contrib.auth.hashers import make_password, check_password


def generate_token() -> str:
    """
    Generate a cryptographically secure random token.
    Suitable for access/refresh tokens.
    """
    return secrets.token_urlsafe(64)


def hash_token(token: str) -> str:
    """
    Hash a token for secure storage (like a password).
    Uses Django's default hasher (e.g., PBKDF2).
    """
    return make_password(token)


def verify_token(provided_token: str, stored_hashed_token: str) -> bool:
    """
    Verify a raw token against its hashed version in the DB.
    """
    return check_password(provided_token, stored_hashed_token)