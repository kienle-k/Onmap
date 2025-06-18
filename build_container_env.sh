#!/bin/bash

# Determine which docker-compose command to use
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo "Error: Neither 'docker compose' nor 'docker-compose' command found."
    exit 1
fi

echo ""
echo "Making sure previous containers are down..."
echo ""
$COMPOSE_CMD down

echo "Triggering build of the containers..."
if ! $COMPOSE_CMD build; then
    echo "Build failed. Check Dockerfile or docker-compose.yml for issues."
    exit 1
fi

echo ""
echo "Build completed successfully."
echo ""
exit 0