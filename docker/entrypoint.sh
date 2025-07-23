#!/bin/bash
set -e

# Compliance Agent Docker Entrypoint Script

echo "Starting Security Compliance Automation Agent..."

# Function to generate RSA key pair if not provided
generate_keys() {
    local private_key_path="${JWT_PRIVATE_KEY_PATH:-/app/keys/private.pem}"
    local public_key_path="${JWT_PUBLIC_KEY_PATH:-/app/keys/public.pem}"
    
    if [ ! -f "$private_key_path" ] || [ ! -f "$public_key_path" ]; then
        echo "Generating RSA key pair for JWT signing..."
        
        # Generate private key
        openssl genpkey -algorithm RSA -out "$private_key_path" -pkcs8 -aes-256-cbc -pass pass:${KEY_PASSPHRASE:-compliance123}
        
        # Generate public key
        openssl rsa -pubout -in "$private_key_path" -out "$public_key_path" -passin pass:${KEY_PASSPHRASE:-compliance123}
        
        echo "RSA key pair generated successfully"
    else
        echo "Using existing RSA key pair"
    fi
    
    # Set environment variables
    export JWT_PRIVATE_KEY_PATH="$private_key_path"
    export JWT_PUBLIC_KEY_PATH="$public_key_path"
}

# Function to wait for database with improved reliability
wait_for_db() {
    if [ -n "$DATABASE_URL" ]; then
        echo "Waiting for database to be ready..."
        
        # Extract database connection details
        DB_HOST=$(echo $DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
        DB_PORT=$(echo $DATABASE_URL | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
        DB_USER=$(echo $DATABASE_URL | sed -n 's/.*\/\/\([^:]*\):.*/\1/p')
        DB_NAME=$(echo $DATABASE_URL | sed -n 's/.*\/\([^?]*\).*/\1/p')
        
        echo "Database connection details: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
        
        if [ -n "$DB_HOST" ] && [ -n "$DB_PORT" ]; then
            # First wait for port to be open
            timeout=60
            while ! nc -z "$DB_HOST" "$DB_PORT" 2>/dev/null; do
                echo "Waiting for database port at $DB_HOST:$DB_PORT..."
                sleep 3
                timeout=$((timeout - 3))
                if [ $timeout -le 0 ]; then
                    echo "Database port connection timeout!"
                    exit 1
                fi
            done
            
            echo "Database port is open, checking database readiness..."
            
            # Then check if database is actually ready to accept connections
            timeout=60
            while ! pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" 2>/dev/null; do
                echo "Waiting for database to be ready..."
                sleep 3
                timeout=$((timeout - 3))
                if [ $timeout -le 0 ]; then
                    echo "Database readiness timeout!"
                    exit 1
                fi
            done
            
            echo "Database is ready!"
        else
            echo "Could not parse database connection details from DATABASE_URL"
            exit 1
        fi
    fi
}

# Function to initialize database schema
init_db() {
    if [ -n "$DATABASE_URL" ] && [ "$AUTO_MIGRATE" = "true" ]; then
        echo "Initializing database schema..."
        python -c "
import asyncio
import asyncpg
import os

async def init_schema():
    try:
        conn = await asyncpg.connect(os.getenv('DATABASE_URL'))
        
        # Read and execute schema
        with open('/app/src/db/schema.sql', 'r') as f:
            schema = f.read()
        
        await conn.execute(schema)
        await conn.close()
        print('Database schema initialized successfully')
    except Exception as e:
        print(f'Database initialization error: {e}')

asyncio.run(init_schema())
"
    fi
}

# Function to validate environment
validate_env() {
    local errors=()
    
    # Check required environment variables
    if [ -z "$DATABASE_URL" ]; then
        errors+=("DATABASE_URL is required")
    fi
    
    # Check OpenSCAP content
    if [ ! -d "${OPENSCAP_CONTENT_PATH:-/usr/share/xml/scap/ssg/content/}" ]; then
        errors+=("OpenSCAP content directory not found")
    fi
    
    # Report errors
    if [ ${#errors[@]} -gt 0 ]; then
        echo "Environment validation failed:"
        printf '%s\n' "${errors[@]}"
        exit 1
    fi
    
    echo "Environment validation passed"
}

# Function to set up logging
setup_logging() {
    # Create log directory if it doesn't exist
    mkdir -p /app/logs
    
    # Set log level
    export LOG_LEVEL="${LOG_LEVEL:-INFO}"
    export LOG_FORMAT="${LOG_FORMAT:-json}"
    
    echo "Logging configured: Level=$LOG_LEVEL, Format=$LOG_FORMAT"
}

# Function to display configuration
show_config() {
    echo "=== Compliance Agent Configuration ==="
    echo "Version: 1.0.0"
    echo "Environment: ${ENVIRONMENT:-production}"
    echo "API Host: ${API_HOST:-0.0.0.0}"
    echo "API Port: ${API_PORT:-8000}"
    echo "Prometheus Port: ${PROMETHEUS_PORT:-9090}"
    echo "Scan Interval: ${SCAN_INTERVAL:-3600}s"
    echo "Max Concurrent Scans: ${MAX_CONCURRENT_SCANS:-3}"
    echo "OpenSCAP Content: ${OPENSCAP_CONTENT_PATH:-/usr/share/xml/scap/ssg/content/}"
    echo "Default Profile: ${DEFAULT_SCAN_PROFILE:-xccdf_org.ssgproject.content_profile_cis}"
    echo "======================================="
}

# Main execution
main() {
    # Set up logging first
    setup_logging
    
    # Show configuration
    show_config
    
    # Validate environment
    validate_env
    
    # Generate keys if needed
    generate_keys
    
    # Wait for database
    wait_for_db
    
    # Initialize database if needed
    init_db
    
    echo "Starting compliance agent with command: $@"
    
    # Execute the main command
    exec "$@"
}

# Signal handlers for graceful shutdown
handle_signal() {
    echo "Received shutdown signal, stopping compliance agent..."
    # The application should handle SIGTERM gracefully
    exit 0
}

trap handle_signal SIGTERM SIGINT

# Run main function
main "$@"