FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY engines/threat/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (destination paths match Python imports)
COPY engines/threat/threat_engine/ ./threat_engine/
COPY engines/threat/run_scan.py ./run_scan.py
COPY shared/common/ ./engine_common/
COPY shared/database/ ./consolidated_services/
COPY shared/auth/ ./engine_auth/

# JNY-01: bundled MITRE ATT&CK reference seed + loader (SHA-256 verified at load).
COPY engines/threat/scripts/load_mitre_reference.py ./scripts/load_mitre_reference.py
COPY shared/database/seeds/mitre_technique_reference.csv         ./seeds/mitre_technique_reference.csv
COPY shared/database/seeds/mitre_technique_reference.csv.sha256  ./seeds/mitre_technique_reference.csv.sha256
ENV MITRE_SEED_CSV=/app/seeds/mitre_technique_reference.csv

ENV PYTHONPATH=/app

# Expose port
EXPOSE 8020

# Run API server
CMD ["python", "-m", "uvicorn", "threat_engine.api_server:app", "--host", "0.0.0.0", "--port", "8020"]
