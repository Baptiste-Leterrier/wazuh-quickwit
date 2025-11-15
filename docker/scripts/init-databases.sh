#!/bin/bash
# Wazuh Database Initialization Script
# Copyright (C) 2015, Wazuh Inc.
# This script initializes required databases for Wazuh Manager

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[DB-INIT]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[DB-INIT]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[DB-INIT]${NC} $1"
}

log_error() {
    echo -e "${RED}[DB-INIT]${NC} $1"
}

WAZUH_HOME=${WAZUH_HOME:-/var/ossec}
DB_DIR="${WAZUH_HOME}/var/db"
MITRE_DB="${DB_DIR}/mitre.db"
VD_DB="${DB_DIR}/vd.db"

log_info "Starting database initialization..."

# Ensure database directory exists
mkdir -p "${DB_DIR}"
chmod 770 "${DB_DIR}"
chown -R ossec:ossec "${DB_DIR}"

#
# 1. Initialize MITRE Database
#
init_mitre_db() {
    log_info "Checking MITRE database..."

    if [ -f "${MITRE_DB}" ]; then
        log_success "MITRE database already exists at ${MITRE_DB}"
        return 0
    fi

    log_info "MITRE database not found, creating it..."

    # Check if enterprise-attack.json exists
    MITRE_JSON="${WAZUH_HOME}/ruleset/mitre/enterprise-attack.json"
    if [ ! -f "${MITRE_JSON}" ]; then
        log_error "MITRE enterprise-attack.json not found at ${MITRE_JSON}"
        log_warning "MITRE matrix information will not be available"
        # Create an empty database to prevent repeated errors
        touch "${MITRE_DB}"
        chmod 660 "${MITRE_DB}"
        chown ossec:ossec "${MITRE_DB}"
        return 1
    fi

    log_info "Found enterprise-attack.json at ${MITRE_JSON}"

    # Check if Python and mitredb.py are available
    MITREDB_PY="${WAZUH_HOME}/tools/mitre/mitredb.py"
    if [ ! -f "${MITREDB_PY}" ]; then
        log_error "mitredb.py script not found at ${MITREDB_PY}"
        log_warning "Creating empty MITRE database to prevent errors"
        touch "${MITRE_DB}"
        chmod 660 "${MITRE_DB}"
        chown ossec:ossec "${MITRE_DB}"
        return 1
    fi

    log_info "Running MITRE database creation..."

    # Try to create the database
    if command -v python3 &> /dev/null; then
        cd "$(dirname ${MITRE_JSON})"
        if python3 "${MITREDB_PY}" --database "${MITRE_DB}" 2>&1; then
            log_success "MITRE database created successfully"
            chmod 660 "${MITRE_DB}"
            chown ossec:ossec "${MITRE_DB}"
            return 0
        else
            log_error "Failed to create MITRE database with Python"
            # Create empty database as fallback
            touch "${MITRE_DB}"
            chmod 660 "${MITRE_DB}"
            chown ossec:ossec "${MITRE_DB}"
            return 1
        fi
    else
        log_error "Python3 not found, cannot create MITRE database"
        # Create empty database to prevent errors
        touch "${MITRE_DB}"
        chmod 660 "${MITRE_DB}"
        chown ossec:ossec "${MITRE_DB}"
        return 1
    fi
}

#
# 2. Initialize Global Database
#
init_global_db() {
    log_info "Checking global database..."

    # Global database is now stored in queue/db/ (not var/db/)
    # This changed in newer Wazuh versions
    GLOBAL_DB="${WAZUH_HOME}/queue/db/global.db"
    LEGACY_GLOBAL_DB="${DB_DIR}/global.db"

    # Check if global.db exists in the new location
    if [ -f "${GLOBAL_DB}" ]; then
        log_success "Global database already exists at ${GLOBAL_DB}"
        return 0
    fi

    # Check if it exists in legacy location (migration case)
    if [ -f "${LEGACY_GLOBAL_DB}" ]; then
        log_info "Found global.db in legacy location, migrating..."
        cp "${LEGACY_GLOBAL_DB}" "${GLOBAL_DB}"
        chown ossec:ossec "${GLOBAL_DB}"
        chmod 660 "${GLOBAL_DB}"
        log_success "Migrated global.db to new location"
        return 0
    fi

    log_info "Global database will be created automatically by wazuh-db at ${GLOBAL_DB}"
    return 0
}

#
# 3. Initialize Vulnerability Scanner Database
#
init_vulnerability_db() {
    log_info "Checking vulnerability scanner database..."

    if [ -f "${VD_DB}" ]; then
        # Check if database is valid/not corrupted
        if sqlite3 "${VD_DB}" "PRAGMA integrity_check;" &> /dev/null; then
            log_success "Vulnerability database exists and is valid"
            return 0
        else
            log_warning "Vulnerability database appears corrupted, removing..."
            rm -f "${VD_DB}"
        fi
    fi

    log_info "Vulnerability database will be created automatically by vulnerability scanner module"
    log_info "Note: Initial feed download may take some time on first run"

    # The vulnerability scanner module creates its own RocksDB database
    # We just need to ensure the directory exists with correct permissions
    mkdir -p "${DB_DIR}/vd_tmp"
    chmod 770 "${DB_DIR}/vd_tmp"
    chown -R ossec:ossec "${DB_DIR}/vd_tmp"

    return 0
}

#
# 4. Ensure wazuh-db socket directory exists
#
init_socket_dir() {
    log_info "Checking wazuh-db socket directory..."

    SOCKET_DIR="${WAZUH_HOME}/queue/db"

    # Create directory if it doesn't exist
    if [ ! -d "${SOCKET_DIR}" ]; then
        mkdir -p "${SOCKET_DIR}"
        log_info "Created socket directory: ${SOCKET_DIR}"
    fi

    # Set correct permissions - critical for wazuh-db to create socket
    chmod 770 "${SOCKET_DIR}"
    chown ossec:ossec "${SOCKET_DIR}"

    # Clean up any stale socket files from previous runs
    if [ -S "${SOCKET_DIR}/wdb" ]; then
        log_warning "Removing stale socket file: ${SOCKET_DIR}/wdb"
        rm -f "${SOCKET_DIR}/wdb"
    fi

    # Verify directory is writable
    if [ ! -w "${SOCKET_DIR}" ]; then
        log_error "Socket directory ${SOCKET_DIR} is not writable!"
        return 1
    fi

    # List current contents for debugging
    log_info "Socket directory contents:"
    ls -la "${SOCKET_DIR}" 2>/dev/null || log_info "  (empty)"

    log_success "Socket directory configured at ${SOCKET_DIR}"
    return 0
}

# Execute initialization
log_info "=== Database Initialization ==="

init_socket_dir
init_global_db
init_mitre_db
init_vulnerability_db

# Set final permissions
chmod -R 770 "${DB_DIR}"
chown -R ossec:ossec "${DB_DIR}"

log_success "=== Database initialization complete ==="
log_info "Databases location: ${DB_DIR}"
ls -lah "${DB_DIR}" || true

exit 0
