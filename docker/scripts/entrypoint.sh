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
ls -la ${WAZUH_HOME}/var/run
log_success "Permissions: $(stat -c '%a %U:%G' ${WAZUH_HOME}/var/run)"

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
    log_info "Executing command: $@"
    exec "$@"
else
    # Default: start Wazuh in foreground
    log_info "Starting Wazuh control process..."
    log_info "Running: ${WAZUH_HOME}/bin/wazuh-control start"

    # Check if wazuh-control exists
    if [ ! -f "${WAZUH_HOME}/bin/wazuh-control" ]; then
        log_error "wazuh-control not found at ${WAZUH_HOME}/bin/wazuh-control"
        exit 1
    fi

    # Run wazuh-control and capture its output
    log_info "Executing wazuh-control start..."
    output="$(${WAZUH_HOME}/bin/wazuh-control start 2>&1)"
    exit_code=$?

    log_info "wazuh-control exit code: ${exit_code}"
    log_info "=== wazuh-control output START ==="
    echo "$output"
    log_info "=== wazuh-control output END ==="

    # Determine success by matching "Completed."
    if echo "$output" | grep -q "Completed."; then
        log_success "Wazuh Control started successfully"
        log_info "Quickwit endpoint: http://${QUICKWIT_HOST}:${QUICKWIT_PORT}"
        log_info "Quickwit index: ${QUICKWIT_INDEX}"
    else
        log_error "Wazuh Control failed to start (exit code: ${exit_code})"
        log_error "Output did not contain 'Completed.' string"

        # Check for common issues
        if [ -f "${WAZUH_HOME}/logs/ossec.log" ]; then
            log_info "Last 20 lines of ossec.log:"
            tail -20 ${WAZUH_HOME}/logs/ossec.log || true

            # Check for decoder-specific errors
            if grep -q "Error.*decoder" ${WAZUH_HOME}/logs/ossec.log 2>/dev/null; then
                log_error "=== DECODER ERRORS DETECTED ==="
                log_error "Decoder-related errors found in ossec.log:"
                grep -i "decoder" ${WAZUH_HOME}/logs/ossec.log | tail -10 || true

                log_info "Checking decoder directories..."
                log_info "Default decoders location: ${WAZUH_HOME}/ruleset/decoders/"
                if [ -d "${WAZUH_HOME}/ruleset/decoders" ]; then
                    default_decoder_count=$(find ${WAZUH_HOME}/ruleset/decoders -name "*.xml" 2>/dev/null | wc -l)
                    log_info "  - Found ${default_decoder_count} default decoder files"
                else
                    log_error "  - Default decoder directory NOT FOUND!"
                fi

                log_info "Custom decoders location: ${WAZUH_HOME}/etc/decoders/"
                if [ -d "${WAZUH_HOME}/etc/decoders" ]; then
                    custom_decoder_count=$(find ${WAZUH_HOME}/etc/decoders -name "*.xml" 2>/dev/null | wc -l)
                    log_info "  - Found ${custom_decoder_count} custom decoder files"
                    if [ ${custom_decoder_count} -gt 0 ]; then
                        log_info "  - Custom decoder files:"
                        find ${WAZUH_HOME}/etc/decoders -name "*.xml" -type f 2>/dev/null | while read file; do
                            log_info "    - ${file}"
                            log_info "      Size: $(stat -c%s ${file} 2>/dev/null || echo 'unknown') bytes"
                            log_info "      First 5 lines:"
                            head -5 "${file}" 2>/dev/null | sed 's/^/        /' || true
                        done
                    fi
                else
                    log_error "  - Custom decoder directory NOT FOUND!"
                fi
                log_error "=== END DECODER ERROR DIAGNOSTICS ==="
            fi
        fi

        # Check for specific error patterns
        if echo "$output" | grep -iq "Unable to create PID"; then
            log_error "PID file creation error detected!"
            log_error "Checking ${WAZUH_HOME}/var/run directory:"
            ls -la ${WAZUH_HOME}/var/run || log_error "Directory does not exist or cannot be accessed"
        fi

        exit 1
    fi

    # Keep the container alive by tailing logs
    log_info "Tailing Wazuh logs..."
    exec tail -f ${WAZUH_HOME}/logs/ossec.log
fi
