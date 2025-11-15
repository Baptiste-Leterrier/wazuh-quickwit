#!/bin/bash
# Wazuh Docker Entrypoint Script
# Copyright (C) 2015, Wazuh Inc.

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Wazuh home directory
WAZUH_HOME=${WAZUH_HOME:-/var/ossec}

# Configuration
#QUICKWIT_HOST=${QUICKWIT_HOST:-quickwit-server}
QUICKWIT_HOST="172.25.0.2"
QUICKWIT_PORT=${QUICKWIT_PORT:-7280}
QUICKWIT_INDEX=${QUICKWIT_INDEX:-wazuh-alerts}

log_info "Starting Wazuh Manager with Quickwit integration..."

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    log_error "This script must be run as root"
    exit 1
fi

# Create necessary directories
log_info "Creating necessary directories..."
mkdir -p \
    ${WAZUH_HOME}/logs \
    ${WAZUH_HOME}/queue/alerts \
    ${WAZUH_HOME}/queue/rids \
    ${WAZUH_HOME}/queue/fts \
    ${WAZUH_HOME}/queue/syscheck \
    ${WAZUH_HOME}/queue/rootcheck \
    ${WAZUH_HOME}/queue/diff \
    ${WAZUH_HOME}/queue/fim/db \
    ${WAZUH_HOME}/stats \
    ${WAZUH_HOME}/tmp \
    ${WAZUH_HOME}/var/run \
    ${WAZUH_HOME}/etc/decoders \
    ${WAZUH_HOME}/etc/rules

log_success "Directories created successfully"

# Verify custom decoder/rules directories
# These directories are for user customization
log_info "Verifying custom decoder and rules directories..."
if [ -d "${WAZUH_HOME}/etc/decoders" ]; then
    decoder_count=$(find ${WAZUH_HOME}/etc/decoders -name "*.xml" 2>/dev/null | wc -l)
    log_info "Found ${decoder_count} custom decoder file(s) in ${WAZUH_HOME}/etc/decoders/"
    if [ ${decoder_count} -gt 0 ]; then
        log_info "Custom decoder files:"
        find ${WAZUH_HOME}/etc/decoders -name "*.xml" -type f -exec basename {} \; 2>/dev/null | while read file; do
            log_info "  - ${file}"
        done
    fi
else
    log_warning "Custom decoder directory not found: ${WAZUH_HOME}/etc/decoders"
fi

if [ -d "${WAZUH_HOME}/etc/rules" ]; then
    rules_count=$(find ${WAZUH_HOME}/etc/rules -name "*.xml" 2>/dev/null | wc -l)
    log_info "Found ${rules_count} custom rules file(s) in ${WAZUH_HOME}/etc/rules/"
else
    log_warning "Custom rules directory not found: ${WAZUH_HOME}/etc/rules"
fi
log_success "Custom directories verified"
log_info "Verifying critical directories exist..."
log_info "  - ${WAZUH_HOME}/var/run: $([ -d "${WAZUH_HOME}/var/run" ] && echo "EXISTS" || echo "MISSING")"
log_info "  - ${WAZUH_HOME}/logs: $([ -d "${WAZUH_HOME}/logs" ] && echo "EXISTS" || echo "MISSING")"
log_info "  - ${WAZUH_HOME}/queue: $([ -d "${WAZUH_HOME}/queue" ] && echo "EXISTS" || echo "MISSING")"

# Verify users exist
log_info "Verifying required users and groups..."
if ! getent passwd ossec > /dev/null 2>&1; then
    log_error "User 'ossec' does not exist!"
    exit 1
fi
if ! getent passwd wazuh > /dev/null 2>&1; then
    log_warning "User 'wazuh' does not exist (this may be normal)"
fi
if ! getent group ossec > /dev/null 2>&1; then
    log_error "Group 'ossec' does not exist!"
    exit 1
fi
log_success "Users and groups verified"

# Set permissions
log_info "Setting permissions..."
if chown -R ossec:ossec \
    ${WAZUH_HOME}/logs \
    ${WAZUH_HOME}/queue \
    ${WAZUH_HOME}/stats \
    ${WAZUH_HOME}/tmp \
    ${WAZUH_HOME}/var \
    ${WAZUH_HOME}/etc 2>&1; then
    log_success "Permissions set successfully"
else
    log_error "Failed to set permissions!"
    exit 1
fi

# Ensure all config files and directories are fully readable
chmod 755 ${WAZUH_HOME}/etc 2>/dev/null || true
chmod 644 ${WAZUH_HOME}/etc/*.conf 2>/dev/null || true
chmod 644 ${WAZUH_HOME}/etc/*.keys 2>/dev/null || true
chmod 755 ${WAZUH_HOME}/etc/decoders 2>/dev/null || true
chmod 755 ${WAZUH_HOME}/etc/rules 2>/dev/null || true
chmod 755 ${WAZUH_HOME}/etc/lists 2>/dev/null || true
chmod 755 ${WAZUH_HOME}/etc/shared 2>/dev/null || true
chmod 644 ${WAZUH_HOME}/etc/decoders/* 2>/dev/null || true
chmod 644 ${WAZUH_HOME}/etc/rules/* 2>/dev/null || true
chmod 644 ${WAZUH_HOME}/etc/lists/* 2>/dev/null || true
chmod 644 ${WAZUH_HOME}/etc/shared/* 2>/dev/null || true
# Fix nested directory permissions (for lists subdirectories like malicious-ioc/)
find ${WAZUH_HOME}/etc/lists -type d 2>/dev/null | xargs chmod 755 2>/dev/null || true
find ${WAZUH_HOME}/etc/lists -type f 2>/dev/null | xargs chmod 644 2>/dev/null || true
chown -R ossec:ossec ${WAZUH_HOME}/etc 2>/dev/null || true
log_info "Configuration file permissions set to 644 (rw-r--r--)"

# Verify var/run permissions specifically
log_info "Verifying ${WAZUH_HOME}/var/run permissions..."
chmod 770 ${WAZUH_HOME}/var/run
chown ossec:ossec ${WAZUH_HOME}/var/run
ls -la ${WAZUH_HOME}/var/run
log_success "Permissions verified for ${WAZUH_HOME}/var/run"

# Update ossec.conf with environment variables if not already configured
OSSEC_CONF="${WAZUH_HOME}/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
    log_info "Checking configuration..."

    # Check for database configuration
    if grep -q "<database>" "$OSSEC_CONF" 2>/dev/null; then
        log_success "Database configuration found in ossec.conf"
    else
        log_warning "Database configuration NOT found in ossec.conf - wazuh-dbd may not start"
        log_warning "Please ensure database section is in your ossec.conf configuration"
    fi

    # Update Quickwit host if needed
    if grep -q "quickwit" "$OSSEC_CONF" 2>/dev/null; then
        log_info "Quickwit configuration found in ossec.conf"
    else
        log_warning "Quickwit configuration not found, using default settings"
    fi
else
    log_warning "ossec.conf not found at $OSSEC_CONF"
fi

# Wait for Quickwit to be ready
log_info "Waiting for Quickwit at ${QUICKWIT_HOST}:${QUICKWIT_PORT}..."
MAX_RETRIES=30
RETRY_INTERVAL=2
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -sf "http://${QUICKWIT_HOST}:${QUICKWIT_PORT}/api/v1/cluster" > /dev/null 2>&1; then
        log_success "Quickwit is ready!"
        break
    else
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
            log_info "Quickwit not ready yet, retrying in ${RETRY_INTERVAL}s... (${RETRY_COUNT}/${MAX_RETRIES})"
            sleep $RETRY_INTERVAL
        else
            log_warning "Quickwit is not responding after ${MAX_RETRIES} attempts"
            log_warning "Wazuh will start anyway, but indexing may not work until Quickwit is available"
        fi
    fi
done

# Check if index exists in Quickwit
log_info "Checking if Wazuh index exists in Quickwit..."
if curl -sf "http://${QUICKWIT_HOST}:${QUICKWIT_PORT}/api/v1/indexes/${QUICKWIT_INDEX}" > /dev/null 2>&1; then
    log_success "Wazuh index '${QUICKWIT_INDEX}' exists in Quickwit"
else
    log_warning "Wazuh index '${QUICKWIT_INDEX}' does not exist in Quickwit"
    log_info "The index should be created automatically when Quickwit starts"
    log_info "If indexing doesn't work, check Quickwit logs"
fi

# Initialize Wazuh if first run
if [ ! -f "${WAZUH_HOME}/.docker_initialized" ]; then
    log_info "First run detected, initializing Wazuh..."

    # Create marker file
    touch "${WAZUH_HOME}/.docker_initialized"

    log_success "Wazuh initialized"
fi

# Cleanup stale PID files from previous runs (but not state files)
log_info "Cleaning up stale PID files..."
rm -f ${WAZUH_HOME}/var/run/*.pid.* 2>/dev/null || true
rm -f ${WAZUH_HOME}/var/run/*.failed 2>/dev/null || true

# Start Wazuh
log_info "Starting Wazuh Manager..."

# If a command was provided, execute it
if [ $# -gt 0 ]; then
    log_info "Executing custom command: $@"
    exec "$@"
else
    # Default: start Wazuh services directly (avoiding recursive entrypoint calls)
    log_info "Starting Wazuh services directly..."

    # Start Wazuh using wazuh-control (handles all daemons and proper setup)
    log_info "Starting all Wazuh services with wazuh-control..."
    ${WAZUH_HOME}/bin/wazuh-control start
    WAZUH_START_EXIT=$?

    if [ $WAZUH_START_EXIT -eq 0 ]; then
        log_success "wazuh-control start completed successfully"
    else
        # wazuh-control may fail if API has issues, but other services are OK
        log_warning "wazuh-control start reported exit code $WAZUH_START_EXIT, but continuing..."
        log_info "Some services may not be running - checking logs..."
    fi

    # Give services time to start and daemonize
    sleep 3

    # Give more time for services to stabilize
    sleep 5

    # Check daemon status
    log_info "Checking Wazuh service status..."
    ${WAZUH_HOME}/bin/wazuh-control status 2>&1 || true

    # Check if any Wazuh process is running (including modulesd which may be starting)
    log_info "Waiting for Wazuh daemons to fully initialize..."
    MAX_WAIT=60
    WAIT_COUNT=0

    while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
        # Count actual daemon processes (not control/shell processes)
        DAEMON_COUNT=$(pgrep -f "wazuh-(analysisd|remoted|authd|execd|logcollector|syscheckd|monitord|modulesd)" 2>/dev/null | wc -l)

        if [ $DAEMON_COUNT -gt 0 ]; then
            log_success "Wazuh daemons are running ($DAEMON_COUNT processes)"
            log_info "Quickwit endpoint: http://${QUICKWIT_HOST}:${QUICKWIT_PORT}"
            log_info "Quickwit index: ${QUICKWIT_INDEX}"
            log_info "Tailing Wazuh logs..."
            # Keep the container alive by tailing logs
            exec tail -f ${WAZUH_HOME}/logs/ossec.log
        fi

        WAIT_COUNT=$((WAIT_COUNT + 1))
        if [ $WAIT_COUNT -lt $MAX_WAIT ]; then
            log_info "Wazuh daemons starting up... waiting ($WAIT_COUNT/$MAX_WAIT)"
            sleep 1
        fi
    done

    # If we get here, services didn't start in time
    log_error "Wazuh daemons failed to start within ${MAX_WAIT} seconds"
    log_error "Last 100 lines of ${WAZUH_HOME}/logs/ossec.log:"
    tail -100 ${WAZUH_HOME}/logs/ossec.log 2>/dev/null || true
    sleep 10
    exit 1
fi
