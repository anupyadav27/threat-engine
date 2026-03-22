FROM python:3.11-slim

WORKDIR /app/shared/database

# Install dependencies
COPY shared/database/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy migration assets (built from repo root)
COPY shared/database/ .

CMD ["python", "alembic/migrate_all.py"]
