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
echo "Making sure previous containers are down..."
echo ""
$COMPOSE_CMD down

# Build containers
echo "Triggering build of the containers..."
echo ""
if ! $COMPOSE_CMD build; then
    echo "Build failed. Check Dockerfile or docker-compose.yml for issues."
    exit 1
fi

echo ""
echo "Build completed successfully."
echo ""
exit 0