FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy onboarding module (for scheduler)
COPY . ./onboarding/

# Set Python path
ENV PYTHONPATH=/app

# Run scheduler
CMD ["python", "-m", "onboarding.scheduler.main"]

