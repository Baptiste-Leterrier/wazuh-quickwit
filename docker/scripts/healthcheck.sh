#!/bin/bash
# Wazuh Docker Health Check Script
# Copyright (C) 2015, Wazuh Inc.

set -e

WAZUH_HOME=${WAZUH_HOME:-/var/ossec}
QUICKWIT_HOST=${QUICKWIT_HOST:-quickwit-server}
QUICKWIT_PORT=${QUICKWIT_PORT:-7280}

# Exit codes
EXIT_OK=0
EXIT_ERROR=1

# Check if Wazuh control script exists
if [ ! -f "${WAZUH_HOME}/bin/wazuh-control" ]; then
    echo "ERROR: Wazuh control script not found"
    exit $EXIT_ERROR
fi

# Check if Wazuh processes are running
if ! ${WAZUH_HOME}/bin/wazuh-control status > /dev/null 2>&1; then
    echo "ERROR: Wazuh is not running"
    exit $EXIT_ERROR
fi

# Check critical Wazuh processes
CRITICAL_PROCESSES=(
    "wazuh-analysisd"
    "wazuh-remoted"
    "wazuh-execd"
    "wazuh-logcollector"
    "wazuh-syscheckd"
    "wazuh-monitord"
)

for process in "${CRITICAL_PROCESSES[@]}"; do
    if ! pgrep -x "$process" > /dev/null 2>&1; then
        echo "ERROR: Critical process '$process' is not running"
        exit $EXIT_ERROR
    fi
done

# Check if Wazuh can reach Quickwit (optional, warning only)
if command -v curl > /dev/null 2>&1; then
    if ! curl -sf --max-time 5 "http://${QUICKWIT_HOST}:${QUICKWIT_PORT}/health" > /dev/null 2>&1; then
        echo "WARNING: Cannot reach Quickwit at ${QUICKWIT_HOST}:${QUICKWIT_PORT}"
        # Don't fail health check, just warn
    fi
fi

# Check if log file exists and is being written to
LOG_FILE="${WAZUH_HOME}/logs/ossec.log"
if [ ! -f "$LOG_FILE" ]; then
    echo "ERROR: Log file not found: $LOG_FILE"
    exit $EXIT_ERROR
fi

# Check if log file was modified in the last 5 minutes (sign of activity)
if [ "$(find "$LOG_FILE" -mmin -5 2>/dev/null)" ]; then
    # Log file was recently modified - good sign
    :
else
    echo "WARNING: Log file hasn't been modified in the last 5 minutes"
    # Don't fail, might be normal if no alerts
fi

# All checks passed
echo "OK: Wazuh is healthy"
exit $EXIT_OK
