#!/bin/sh
set -e
mkdir -p /app/instance
python seed.py
exec gunicorn --workers 2 --bind 0.0.0.0:8000 'app:create_app()'
