FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Install all requirements
COPY configScan_engines/aws-configScan-engine/requirements.txt ./aws_requirements.txt
COPY compliance-engine/requirements.txt ./compliance_requirements.txt
COPY rule_engine/requirements.txt ./rule_requirements.txt

# Install all Python dependencies
RUN pip install --no-cache-dir -r aws_requirements.txt && \
    pip install --no-cache-dir -r compliance_requirements.txt && \
    pip install --no-cache-dir -r rule_requirements.txt

# Copy AWS ConfigScan Engine
COPY configScan_engines/aws-configScan-engine/engine/ ./engine/
COPY configScan_engines/aws-configScan-engine/auth/ ./auth/
COPY configScan_engines/aws-configScan-engine/utils/ ./utils/
COPY configScan_engines/aws-configScan-engine/services/ ./services/
COPY configScan_engines/aws-configScan-engine/config/ ./config/
COPY configScan_engines/aws-configScan-engine/api_server.py ./aws_api_server.py

# Copy Compliance Engine
COPY compliance-engine/compliance_engine/ ./compliance_engine/
COPY compliance-engine/data/ ./data/
COPY compliance/ ./compliance/

# Copy Rule Engine (copy entire directory)
COPY rule_engine/ ./rule_engine/
COPY pythonsdk-database/ ./pythonsdk-database/
# Create symlinks for easier imports
RUN ln -sf rule_engine/api.py ./rule_api.py && \
    ln -sf rule_engine/api_server.py ./rule_api_server.py || true

# Copy startup script
COPY unified-engine/start-services.sh ./start-services.sh
RUN chmod +x ./start-services.sh

# Copy supervisor config
COPY unified-engine/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Set Python path
ENV PYTHONPATH=/app

# Expose ports
EXPOSE 8000 8001 8002

# Start all services via supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]

