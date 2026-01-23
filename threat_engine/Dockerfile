FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY threat_engine/ ./threat_engine/

# Expose port
EXPOSE 8000

# Run API server
CMD ["python", "-m", "uvicorn", "threat_engine.api_server:app", "--host", "0.0.0.0", "--port", "8000"]

