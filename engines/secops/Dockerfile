# Layer RBAC auth wiring on top of the existing fully-functional secops image
# scanner_plugin, scan_local, and all scanner binaries live in v-unified-fix2
FROM yadavanup84/secops-scanner:v-unified-fix2

WORKDIR /app

# Overlay updated SAST engine files (api_server + routers with require_permission)
COPY engines/secops/sast_engine/ .

# Auth module (destination matches Python imports: engine_auth.*)
COPY shared/auth/ ./engine_auth/

EXPOSE 8009

CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8009", "--workers", "2"]
