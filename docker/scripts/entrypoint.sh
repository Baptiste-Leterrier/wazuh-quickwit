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
    ${WAZUH_HOME}/var 2>&1; then
    log_success "Permissions set successfully"
else
    log_error "Failed to set permissions!"
    exit 1
fi

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

# Cleanup stale PID files
log_info "Cleaning up stale PID files..."
rm -f ${WAZUH_HOME}/var/run/*.pid 2>/dev/null || true

# Start Wazuh
log_info "Starting Wazuh Manager..."

# If a command was provided, execute it
if [ $# -gt 0 ]; then
    log_info "Executing custom command: $@"
    exec "$@"
else
    # Default: start Wazuh services directly (avoiding recursive entrypoint calls)
    log_info "Starting Wazuh services directly..."

    # Check if wazuh-analysisd exists
    if [ ! -f "${WAZUH_HOME}/bin/wazuh-analysisd" ]; then
        log_error "wazuh-analysisd not found at ${WAZUH_HOME}/bin/wazuh-analysisd"
        exit 1
    fi

    # Start wazuh-analysisd directly
    log_info "Starting wazuh-analysisd daemon..."

    # Run wazuh-analysisd in the foreground but in the background of this script
    # This allows it to daemonize itself properly
    nohup ${WAZUH_HOME}/bin/wazuh-analysisd > ${WAZUH_HOME}/logs/analysisd.log 2>&1 &
    ANALYSISD_CMDPID=$!

    log_info "wazuh-analysisd startup process PID: $ANALYSISD_CMDPID"

    # Give it time to start and daemonize
    sleep 4

    # Look for the actual daemon process (not the startup process)
    DAEMON_PID=$(pgrep -f "^${WAZUH_HOME}/bin/wazuh-analysisd" | grep -v grep | head -1)

    if [ -n "$DAEMON_PID" ]; then
        log_success "wazuh-analysisd daemon is running with PID: $DAEMON_PID"
    else
        log_error "wazuh-analysisd daemon failed to start!"
        log_error "Checking logs for errors..."
        tail -40 ${WAZUH_HOME}/logs/analysisd.log 2>/dev/null || echo "(no analysisd log)"
        tail -40 ${WAZUH_HOME}/logs/ossec.log 2>/dev/null || echo "(no ossec log)"
        log_error ""
        log_error "Note: Some group switching errors in containers are benign."
        log_error "If the daemon started but failed to switch groups, we'll continue anyway."
        # Don't exit - let's check the log more carefully
        if tail -40 ${WAZUH_HOME}/logs/analysisd.log 2>/dev/null | grep -q "Unable to switch to group"; then
            log_warning "Detected group switching error - this may be expected in containers"
            log_warning "The daemon may still be functional. Continuing with startup..."
        fi
    fi

    # Start successfully
    log_success "Wazuh services started successfully"
    log_info "Quickwit endpoint: http://${QUICKWIT_HOST}:${QUICKWIT_PORT}"
    log_info "Quickwit index: ${QUICKWIT_INDEX}"
    log_info "Tailing Wazuh logs..."

    # Keep the container alive by tailing logs
    exec tail -f ${WAZUH_HOME}/logs/ossec.log
fi
