#!/bin/bash

echo "🧹 Comprehensive Docker and System Cleanup Script"
echo "================================================"

# Function to check if command succeeded
check_success() {
    if [ $? -eq 0 ]; then
        echo "✅ $1"
    else
        echo "❌ $1 (failed)"
    fi
}

# Stop Python applications
echo "🐍 Stopping Python applications..."
pkill -f "python.*main.py" 2>/dev/null
sleep 2
check_success "Python applications stopped"

# Try to stop Docker containers gracefully first
echo "🐳 Attempting graceful Docker container shutdown..."
sudo docker stop $(sudo docker ps -q) 2>/dev/null || true
sleep 3

# Force kill stubborn containers
echo "💥 Force killing remaining containers..."
sudo docker kill $(sudo docker ps -q) 2>/dev/null || true
sleep 2

# Remove all containers (force)
echo "🗑️  Removing all containers..."
sudo docker rm -f $(sudo docker ps -aq) 2>/dev/null || true
check_success "Containers removed"

# Clean up Docker resources
echo "🧼 Cleaning Docker resources..."

# Remove images
sudo docker image prune -a -f 2>/dev/null
check_success "Docker images cleaned"

# Remove volumes
sudo docker volume prune -f 2>/dev/null
check_success "Docker volumes cleaned"

# Remove networks
sudo docker network prune -f 2>/dev/null
check_success "Docker networks cleaned"

# Remove build cache
sudo docker builder prune -a -f 2>/dev/null
check_success "Docker build cache cleaned"

# System-wide cleanup
echo "🔄 Docker system cleanup..."
sudo docker system prune -a -f --volumes 2>/dev/null
check_success "Docker system cleaned"

# Restart Docker service to ensure clean state
echo "🔄 Restarting Docker service..."
sudo systemctl restart docker
sleep 5
check_success "Docker service restarted"

# Clean up temporary files
echo "📁 Cleaning temporary files..."
sudo rm -rf /tmp/docker-* 2>/dev/null || true
sudo rm -rf /tmp/compose-* 2>/dev/null || true
check_success "Temporary files cleaned"

# Show current status
echo ""
echo "📊 Current System Status:"
echo "========================"

echo "🐳 Docker containers:"
docker_containers=$(sudo docker ps -a --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | wc -l)
if [ "$docker_containers" -eq 1 ]; then
    echo "✅ No Docker containers running"
else
    echo "⚠️  Still some containers present:"
    sudo docker ps -a --format "table {{.Names}}\t{{.Status}}" 2>/dev/null
fi

echo ""
echo "💾 Docker disk usage:"
sudo docker system df 2>/dev/null || echo "Docker not accessible"

echo ""
echo "🧠 Memory usage:"
free -h

echo ""
echo "💽 Disk usage:"
df -h / | tail -1

echo ""
echo "🎉 Cleanup completed!"
echo ""
echo "Summary of what was cleaned:"
echo "- All Docker containers stopped and removed"
echo "- All Docker images removed"
echo "- All Docker volumes removed" 
echo "- All Docker networks cleaned"
echo "- Docker build cache cleared"
echo "- Docker service restarted"
echo "- Temporary files cleaned"
echo "- Python applications stopped"
echo ""
