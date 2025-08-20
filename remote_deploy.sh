#!/bin/bash

# Remote Agent Deployment Script
# This script deploys the compliance agent on the target system

set -e

# Configuration
REMOTE_HOST="10.2.246.153"
REMOTE_USER="agent"
REMOTE_PASSWORD="123123"
API_SERVER="10.2.110.246:8003"
PACKAGE_DIR="/home/chironex/backend-main/compliance_agent_package"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to run commands on remote system
run_remote() {
    local cmd="$1"
    log_info "Executing on remote: $cmd"
    
    sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no "$REMOTE_USER@$REMOTE_HOST" "$cmd"
}

# Function to copy files to remote system
copy_to_remote() {
    local src="$1"
    local dest="$2"
    log_info "Copying $src to remote:$dest"
    
    sshpass -p "$REMOTE_PASSWORD" scp -o StrictHostKeyChecking=no -r "$src" "$REMOTE_USER@$REMOTE_HOST:$dest"
}

# Main deployment function
deploy_agent() {
    log_info "Starting deployment to $REMOTE_HOST"
    
    # Check if sshpass is available
    if ! command -v sshpass >/dev/null 2>&1; then
        log_error "sshpass is required but not installed"
        log_info "Install with: sudo apt-get install sshpass"
        exit 1
    fi
    
    # Test connectivity
    log_info "Testing connectivity to $REMOTE_HOST"
    if ! sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$REMOTE_USER@$REMOTE_HOST" "echo 'Connection successful'" >/dev/null 2>&1; then
        log_error "Cannot connect to $REMOTE_HOST"
        exit 1
    fi
    log_success "Connection established"
    
    # Copy agent package
    log_info "Copying agent package to remote system"
    copy_to_remote "$PACKAGE_DIR" "/home/agent/"
    
    # Make scripts executable
    log_info "Making scripts executable"
    run_remote "chmod +x /home/agent/compliance_agent_package/*.sh"
    run_remote "chmod +x /home/agent/compliance_agent_package/scripts/*.sh"
    
    # Check system requirements
    log_info "Checking system requirements on remote"
    run_remote "cd /home/agent/compliance_agent_package && ./setup.sh check"
    
    # Install Docker if needed
    log_info "Checking Docker installation"
    if ! run_remote "docker --version" >/dev/null 2>&1; then
        log_warning "Docker not found, attempting installation"
        run_remote "cd /home/agent/compliance_agent_package && ./setup.sh install-docker"
    else
        log_success "Docker is available"
    fi
    
    # Set environment variables
    log_info "Configuring environment"
    run_remote "cat > /home/agent/.compliance_env << EOF
export COMPLIANCE_API_URL=\"http://$API_SERVER\"
export SCAN_INTERVAL=\"3600\"
export DEFAULT_PROFILE=\"xccdf_org.ssgproject.content_profile_cis\"
export AGENT_PORT=\"8080\"
EOF"
    
    # Source environment and deploy
    log_info "Deploying compliance agent"
    run_remote "cd /home/agent/compliance_agent_package && source /home/agent/.compliance_env && ./deploy.sh deploy"
    
    # Wait for container to start
    log_info "Waiting for agent to start..."
    sleep 10
    
    # Check agent status
    log_info "Checking agent status"
    run_remote "cd /home/agent/compliance_agent_package && ./deploy.sh status"
    
    # Test agent health
    log_info "Testing agent health endpoint"
    if run_remote "curl -f http://localhost:8080/health" >/dev/null 2>&1; then
        log_success "Agent health check passed"
    else
        log_warning "Agent health check failed - checking logs"
        run_remote "cd /home/agent/compliance_agent_package && ./deploy.sh logs | tail -20"
    fi
    
    # Trigger initial scan
    log_info "Triggering initial compliance scan"
    run_remote "cd /home/agent/compliance_agent_package && ./deploy.sh scan"
    
    log_success "Deployment completed successfully!"
    log_info "Agent is running on $REMOTE_HOST:8080"
    log_info "API server: http://$API_SERVER"
}

# Function to check agent status
check_status() {
    log_info "Checking agent status on $REMOTE_HOST"
    run_remote "cd /home/agent/compliance_agent_package && ./deploy.sh status"
}

# Function to view logs
view_logs() {
    log_info "Viewing agent logs on $REMOTE_HOST"
    run_remote "cd /home/agent/compliance_agent_package && ./deploy.sh logs"
}

# Function to trigger scan
trigger_scan() {
    log_info "Triggering compliance scan on $REMOTE_HOST"
    run_remote "cd /home/agent/compliance_agent_package && ./deploy.sh scan"
}

# Function to stop agent
stop_agent() {
    log_info "Stopping agent on $REMOTE_HOST"
    run_remote "cd /home/agent/compliance_agent_package && ./deploy.sh stop"
}

# Function to cleanup
cleanup_agent() {
    log_info "Cleaning up agent on $REMOTE_HOST"
    run_remote "cd /home/agent/compliance_agent_package && ./deploy.sh cleanup"
    run_remote "rm -rf /home/agent/compliance_agent_package"
    run_remote "rm -f /home/agent/.compliance_env"
}

# Main script logic
case "${1:-deploy}" in
    deploy)
        deploy_agent
        ;;
    status)
        check_status
        ;;
    logs)
        view_logs
        ;;
    scan)
        trigger_scan
        ;;
    stop)
        stop_agent
        ;;
    cleanup)
        cleanup_agent
        ;;
    help)
        echo "Usage: $0 {deploy|status|logs|scan|stop|cleanup|help}"
        echo ""
        echo "Commands:"
        echo "  deploy   - Deploy agent to remote system (default)"
        echo "  status   - Check agent status"
        echo "  logs     - View agent logs"
        echo "  scan     - Trigger manual scan"
        echo "  stop     - Stop the agent"
        echo "  cleanup  - Remove agent completely"
        echo "  help     - Show this help"
        ;;
    *)
        log_error "Unknown command: $1"
        log_info "Run '$0 help' for usage information"
        exit 1
        ;;
esac