import logging

from fastapi import FastAPI

try:
    from engine_auth.fastapi.middleware import AuthMiddleware
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

from api_security_engine.api.routes import router

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s","engine":"api-security"}',
)
logger = logging.getLogger("api_security.server")

app = FastAPI(title="API Security Engine", version="1.0.0")
app.include_router(router, prefix="/api/v1")

if _AUTH_AVAILABLE:
    app.add_middleware(AuthMiddleware)
    logger.info("Auth middleware enabled")
else:
    logger.warning("engine_auth not available — running without auth enforcement")
