FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY ibm_compliance_python_engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install FastAPI
RUN pip install fastapi uvicorn[standard] pydantic pydantic-settings

# Copy engine code
COPY ibm_compliance_python_engine/ ./ibm_compliance_python_engine/
COPY pythonsdk-database/ ./pythonsdk-database/

# Copy API server
COPY ibm_compliance_python_engine/api_server.py .

# Set Python path
ENV PYTHONPATH=/app

# Expose port
EXPOSE 8000

# Run API server
CMD ["uvicorn", "api_server:app", "--host", "0.0.0.0", "--port", "8000"]

