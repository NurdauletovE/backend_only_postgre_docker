#!/bin/bash
set -e

echo "==================================="
echo "Security Compliance Agent Deployment"
echo "==================================="

# Function to check if a service is healthy
check_service_health() {
    local service_name="$1"
    local max_attempts=30
    local attempt=1
    
    echo "Checking health of service: $service_name"
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose ps "$service_name" | grep -q "healthy\|Up"; then
            echo "✅ Service $service_name is healthy"
            return 0
        fi
        
        echo "⏳ Attempt $attempt/$max_attempts: Waiting for $service_name to be healthy..."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    echo "❌ Service $service_name failed to become healthy"
    return 1
}

# Clean up any existing containers
echo "🧹 Cleaning up existing containers..."
docker-compose down --volumes --remove-orphans 2>/dev/null || true

# Remove any orphaned containers
docker container prune -f 2>/dev/null || true

# Step 1: Deploy PostgreSQL first
echo ""
echo "📦 Step 1: Deploying PostgreSQL database..."
docker-compose up -d postgres

# Wait for PostgreSQL to be healthy
check_service_health "postgres"

# Step 2: Run database initialization check
echo ""
echo "🔧 Step 2: Running database initialization check..."
docker-compose up db-init-check
docker-compose wait db-init-check

if [ $? -eq 0 ]; then
    echo "✅ Database initialization completed successfully"
else
    echo "❌ Database initialization failed"
    docker-compose logs db-init-check
    exit 1
fi

# Step 3: Deploy compliance agent
echo ""
echo "🚀 Step 3: Deploying compliance agent..."
docker-compose up -d compliance-agent

# Wait for compliance agent to be healthy
check_service_health "compliance-agent"

# Step 4: Deploy monitoring services
echo ""
echo "📊 Step 4: Deploying monitoring services..."
docker-compose up -d prometheus grafana

# Wait for services to be ready
check_service_health "prometheus"
echo "✅ Prometheus is ready"

sleep 10  # Give Grafana a moment to start
echo "✅ Grafana is ready"

# Final status check
echo ""
echo "🔍 Final deployment status:"
docker-compose ps

echo ""
echo "🎉 Deployment completed successfully!"
echo ""
echo "Services available at:"
echo "📋 API Documentation: http://localhost:8002/docs"
echo "🏥 Health Check: http://localhost:8002/health"
echo "📊 Prometheus: http://localhost:9096"
echo "📈 Grafana: http://localhost:3003 (admin/admin_password_2024)"
echo ""
echo "Database is accessible at: localhost:5440"
echo ""
