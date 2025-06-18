#!/bin/bash

# Detect which docker-compose command to use
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo "Error: Neither 'docker compose' nor 'docker-compose' found."
    exit 1
fi

echo "Making sure previous containers are down..."
$COMPOSE_CMD down

echo "Starting docker containers in detached mode..."
if ! $COMPOSE_CMD up -d; then
    echo "Failed to start Docker containers. Check logs and configuration."
    exit 1
fi

echo "Docker containers started successfully in detached mode."
echo "Entering onmap container..."
echo "use onmap via ./onmap [options] [hosts]"
docker exec -it onmap bash

exit 0
