#!/bin/bash
set -e

# Replace the pg_hba.conf with trust authentication for all local connections
cat > /var/lib/postgresql/data/pg_hba.conf << 'EOF'
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# All local connections use trust authentication
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust  
host    all             all             ::1/128                 trust
host    all             all             172.16.0.0/12           trust
host    all             all             192.168.0.0/16          trust
host    all             all             10.0.0.0/8              trust

# Replication connections
local   replication     all                                     trust
host    replication     all             127.0.0.1/32            trust
host    replication     all             ::1/128                 trust
EOF

echo "Updated pg_hba.conf for trust authentication"