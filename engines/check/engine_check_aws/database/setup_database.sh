#!/bin/bash
# Setup Check Database

DB_NAME="threat_engine_check"
DB_USER="check_user"
DB_PASSWORD="check_password"

echo "Creating check database: $DB_NAME"

# Create database
psql -U postgres -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || echo "Database $DB_NAME may already exist"

# Create user
psql -U postgres -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';" 2>/dev/null || echo "User $DB_USER may already exist"

# Grant privileges
psql -U postgres -d $DB_NAME -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
psql -U postgres -d $DB_NAME -c "GRANT ALL ON SCHEMA public TO $DB_USER;"

# Run schema
psql -U postgres -d $DB_NAME -f "$(dirname "$0")/schema.sql"

echo "Check database setup complete!"
