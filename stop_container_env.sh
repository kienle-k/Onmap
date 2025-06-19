#!/bin/bash

# Determine which docker version -> "docker-compose" or "docker compose"
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo "Error: Neither 'docker compose' nor 'docker-compose' found. Is docker installed?"
    exit 1
fi

# Stop containers
echo ""
echo "Stopping docker containers..."
echo ""
$COMPOSE_CMD down