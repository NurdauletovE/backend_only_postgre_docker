#!/bin/bash

# Secure Deployment Script for Compliance Agent
# This script deploys the application with security best practices

set -e

echo "=========================================="
echo "Security Compliance Agent - Secure Deployment"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo "WARNING: Running as root. Consider running as a regular user with docker permissions."
   echo ""
fi

# Check for Docker and Docker Compose
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "ERROR: Docker Compose v2 is not installed"
    exit 1
fi

# Check if secrets exist
if [ ! -f "secrets/postgres_password.txt" ] || [ ! -f "secrets/grafana_password.txt" ]; then
    echo "Secrets not found. Generating secure passwords..."
    ./secrets/generate_secrets.sh
    echo ""
fi

# Check environment file
if [ ! -f ".env.production" ]; then
    echo "ERROR: .env.production file not found"
    echo "Please configure .env.production with your domain settings"
    exit 1
fi

# Stop existing deployment
echo "Stopping existing services..."
docker-compose down 2>/dev/null || true
docker-compose -f docker-compose-secure.yml down 2>/dev/null || true

# Build images
echo ""
echo "Building Docker images..."
docker-compose -f docker-compose-secure.yml build

# Create volumes if they don't exist
echo ""
echo "Creating Docker volumes..."
docker volume create postgres_data 2>/dev/null || true
docker volume create compliance_logs 2>/dev/null || true
docker volume create compliance_results 2>/dev/null || true
docker volume create prometheus_data 2>/dev/null || true
docker volume create grafana_data 2>/dev/null || true

# Deploy services
echo ""
echo "Starting services..."
docker-compose -f docker-compose-secure.yml --env-file .env.production up -d

# Wait for services to be healthy
echo ""
echo "Waiting for services to be healthy..."
sleep 10

# Check service health
echo ""
echo "Checking service status..."
docker-compose -f docker-compose-secure.yml ps

# Test API health
echo ""
echo "Testing API health..."
if curl -f http://localhost:8003/health 2>/dev/null | grep -q "healthy\|degraded"; then
    echo "✓ API is responding"
else
    echo "✗ API health check failed"
fi

# Display access information
echo ""
echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
echo ""
echo "Access Points:"
echo "  API:      http://localhost:8003"
echo "  API Docs: http://localhost:8003/docs"
echo "  Grafana:  http://localhost:3004"
echo ""
echo "Default Credentials:"
echo "  Grafana: admin / (see secrets/grafana_password.txt)"
echo ""
echo "Security Notes:"
echo "  - Services are only accessible from localhost"
echo "  - Database is not exposed externally"
echo "  - Prometheus is internal only"
echo "  - Configure a reverse proxy (nginx/traefik) for production"
echo ""
echo "To view logs:"
echo "  docker-compose -f docker-compose-secure.yml logs -f"
echo ""
echo "To stop services:"
echo "  docker-compose -f docker-compose-secure.yml down"