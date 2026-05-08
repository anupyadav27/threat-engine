#!/bin/sh
# entrypoint.sh

# Exit immediately if a command exits with a non-zero status
set -e

echo "Running Django migrations..."
python manage.py makemigrations
python manage.py migrate

echo "Starting server..."
exec "$@"
