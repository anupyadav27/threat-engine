"""
SBOM Engine configuration.
All settings read from environment variables.
"""

import json
import logging
import os
from typing import List

logger = logging.getLogger(__name__)


class Settings:
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 8002))
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"

    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", 5432))
    DB_NAME: str = os.getenv("DB_NAME", "vulnerability_db")
    DB_USER: str = os.getenv("DB_USER", "postgres")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "password")
    DB_MAX_CONNECTIONS: int = int(os.getenv("DB_MAX_CONNECTIONS", 20))
    DB_MIN_CONNECTIONS: int = int(os.getenv("DB_MIN_CONNECTIONS", 5))
    DB_SSLMODE: str = os.getenv("DB_SSLMODE", "prefer")

    ALLOWED_ORIGINS: List[str] = ["*"]

    @property
    def API_KEYS(self) -> List[str]:
        raw = os.getenv("API_KEY", "sbom-api-key-2024")
        if raw == "sbom-api-key-2024":
            logger.warning(
                "API_KEY env var not set — using insecure default key. "
                "Set API_KEY in deployment.yaml before production use."
            )
        try:
            keys = json.loads(raw)
            return keys if isinstance(keys, list) else [keys]
        except (json.JSONDecodeError, TypeError):
            return [k.strip() for k in raw.split(",") if k.strip()]


settings = Settings()
