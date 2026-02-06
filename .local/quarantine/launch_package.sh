#!/bin/bash

echo "Copying production files..."
cp kasbah_state.py apps/api/
cp kasbah_validation.py apps/api/
cp .env.production .env

echo "Starting production stack..."
docker-compose -f docker-compose.production.yml up -d

echo "Waiting for services to start..."
sleep 10

echo "Testing health endpoint..."
curl -f http://localhost:8002/health || echo "Health check failed"

echo "Production deployment complete!"
echo "API available at: http://localhost:8002"
echo "Docs at: http://localhost:8002/docs"
