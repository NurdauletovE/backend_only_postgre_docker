#!/bin/bash
set -e

echo "Starting FastAPI Compliance Service..."

# Function to wait for database
wait_for_db() {
    if [ -n "$DATABASE_URL" ]; then
        echo "Waiting for database to be ready..."
        
        # Extract database connection details from DATABASE_URL
        DB_HOST=$(echo $DATABASE_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')
        DB_PORT=$(echo $DATABASE_URL | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
        DB_USER=$(echo $DATABASE_URL | sed -n 's/.*\/\/\([^:]*\):.*/\1/p')
        DB_NAME=$(echo $DATABASE_URL | sed -n 's/.*\/\([^?]*\).*/\1/p')
        
        echo "Database: $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
        
        if [ -n "$DB_HOST" ] && [ -n "$DB_PORT" ]; then
            # Wait for database port to be open
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
            
            echo "Database port is open, checking readiness..."
            
            # Check if database is ready to accept connections
            timeout=60
            while ! pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" 2>/dev/null; do
                echo "Database not ready, waiting..."
                sleep 3
                timeout=$((timeout - 3))
                if [ $timeout -le 0 ]; then
                    echo "Database readiness timeout!"
                    exit 1
                fi
            done
            
            echo "Database is ready!"
        else
            echo "Could not parse database connection details"
            exit 1
        fi
    else
        echo "No DATABASE_URL provided, skipping database check"
    fi
}

# Set default environment variables
export API_HOST=${API_HOST:-"0.0.0.0"}
export API_PORT=${API_PORT:-"8000"}
export LOG_LEVEL=${LOG_LEVEL:-"INFO"}
export LOG_FORMAT=${LOG_FORMAT:-"json"}

# Set JWT key paths if not provided
export JWT_PRIVATE_KEY_PATH=${JWT_PRIVATE_KEY_PATH:-"/app/keys/private_unencrypted.pem"}
export JWT_PUBLIC_KEY_PATH=${JWT_PUBLIC_KEY_PATH:-"/app/keys/public_unencrypted.pem"}

echo "API Configuration:"
echo "  Host: $API_HOST"
echo "  Port: $API_PORT"
echo "  Log Level: $LOG_LEVEL"
echo "  JWT Private Key: $JWT_PRIVATE_KEY_PATH"
echo "  JWT Public Key: $JWT_PUBLIC_KEY_PATH"

# Wait for database if configured
wait_for_db

echo "Starting FastAPI application..."

# Execute the provided command
exec "$@"
