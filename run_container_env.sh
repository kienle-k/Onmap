#!/bin/bash
echo "Making sure previous containers are down..."
docker compose down
echo "Starting docker containers in detached mode..."
if ! docker compose up -d; then
    echo "Failed to start Docker containers. Check logs and configuration."
    exit 1
fi
echo "Docker containers started successfully in detached mode."
echo "Entering onmap container..."
echo "use onmap via ./onmap [options] [hosts]"
docker exec -it onmap bash
exit 0