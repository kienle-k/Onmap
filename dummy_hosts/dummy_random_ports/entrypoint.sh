#!/bin/sh

python3 /app/run_servers.py
exec tail -f /dev/null