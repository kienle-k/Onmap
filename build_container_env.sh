#!/bin/bash
echo "Making sure previous containers are down..."
docker compose down
echo "Triggering build of the containers..."
if ! docker compose build; then
    echo "Build failed. Check Dockerfile or docker-compose.yml for issues."
    exit 1
fi
echo "Build completed successfully."
exit 0