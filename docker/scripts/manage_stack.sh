#!/bin/bash
# Wazuh-Quickwit Docker Stack Management Script
# Copyright (C) 2015, Wazuh Inc.

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKER_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="${DOCKER_DIR}/docker-compose.yml"

# Check if Docker Compose file exists
if [ ! -f "$COMPOSE_FILE" ]; then
    echo -e "${RED}ERROR:${NC} Docker Compose file not found: $COMPOSE_FILE"
    exit 1
fi

# Functions
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

# Help message
show_help() {
    cat << EOF
Wazuh-Quickwit Docker Stack Management

Usage: $(basename "$0") [COMMAND]

Commands:
  start           Start all services
  stop            Stop all services
  restart         Restart all services
  status          Show service status
  logs            Show logs for all services
  logs-wazuh      Show Wazuh logs
  logs-quickwit   Show Quickwit logs
  build           Rebuild images
  rebuild         Rebuild and restart
  shell-wazuh     Open shell in Wazuh container
  shell-quickwit  Open shell in Quickwit container
  test            Run health checks
  clean           Stop and remove everything (keep volumes)
  purge           Stop and remove everything (including volumes)
  ps              Show running containers
  top             Show container resource usage
  help            Show this help message

Examples:
  $(basename "$0") start
  $(basename "$0") logs-wazuh
  $(basename "$0") test

EOF
}

# Check Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        log_error "Docker is not running or you don't have permission to access it"
        exit 1
    fi
}

# Start services
start_services() {
    log_info "Starting Wazuh-Quickwit stack..."
    docker compose -f "$COMPOSE_FILE" up -d
    log_success "Services started"
    log_info "Waiting for services to be healthy..."
    sleep 5
    show_status
}

# Stop services
stop_services() {
    log_info "Stopping Wazuh-Quickwit stack..."
    docker compose -f "$COMPOSE_FILE" stop
    log_success "Services stopped"
}

# Restart services
restart_services() {
    log_info "Restarting Wazuh-Quickwit stack..."
    docker compose -f "$COMPOSE_FILE" restart
    log_success "Services restarted"
    sleep 5
    show_status
}

# Show status
show_status() {
    log_info "Service status:"
    docker compose -f "$COMPOSE_FILE" ps
    echo ""

    # Check Quickwit health
    log_info "Checking Quickwit health..."
    if curl -sf http://localhost:7280/health > /dev/null 2>&1; then
        log_success "Quickwit is healthy"
        QUICKWIT_HEALTH=$(curl -s http://localhost:7280/health)
        echo "  Response: $QUICKWIT_HEALTH"
    else
        log_warning "Quickwit health check failed"
    fi

    echo ""

    # Check Wazuh health
    log_info "Checking Wazuh health..."
    if docker exec wazuh-manager /usr/local/bin/healthcheck.sh > /dev/null 2>&1; then
        log_success "Wazuh is healthy"
    else
        log_warning "Wazuh health check failed"
    fi
}

# Show logs
show_logs() {
    local service=$1
    if [ -z "$service" ]; then
        log_info "Showing logs for all services (Ctrl+C to exit)..."
        docker compose -f "$COMPOSE_FILE" logs -f --tail=100
    else
        log_info "Showing logs for $service (Ctrl+C to exit)..."
        docker compose -f "$COMPOSE_FILE" logs -f --tail=100 "$service"
    fi
}

# Build images
build_images() {
    log_info "Building Docker images..."
    docker compose -f "$COMPOSE_FILE" build --no-cache
    log_success "Images built"
}

# Rebuild and restart
rebuild_services() {
    log_info "Rebuilding and restarting services..."
    docker compose -f "$COMPOSE_FILE" up -d --build
    log_success "Services rebuilt and started"
    sleep 5
    show_status
}

# Open shell
open_shell() {
    local container=$1
    log_info "Opening shell in $container..."
    docker exec -it "$container" bash 2>/dev/null || docker exec -it "$container" sh
}

# Run tests
run_tests() {
    log_info "Running health checks..."
    echo ""

    # Test 1: Check if containers are running
    log_info "Test 1: Checking if containers are running..."
    if docker ps | grep -q "wazuh-manager" && docker ps | grep -q "quickwit-server"; then
        log_success "All containers are running"
    else
        log_error "Some containers are not running"
        docker compose -f "$COMPOSE_FILE" ps
        return 1
    fi

    echo ""

    # Test 2: Check Quickwit health
    log_info "Test 2: Checking Quickwit health endpoint..."
    if curl -sf http://localhost:7280/health > /dev/null 2>&1; then
        HEALTH=$(curl -s http://localhost:7280/health)
        log_success "Quickwit health check passed: $HEALTH"
    else
        log_error "Quickwit health check failed"
        return 1
    fi

    echo ""

    # Test 3: Check Quickwit index
    log_info "Test 3: Checking Wazuh index in Quickwit..."
    if curl -sf http://localhost:7280/api/v1/indexes/wazuh-alerts > /dev/null 2>&1; then
        log_success "Wazuh index exists in Quickwit"
    else
        log_warning "Wazuh index not found in Quickwit (may be created on first alert)"
    fi

    echo ""

    # Test 4: Check Wazuh processes
    log_info "Test 4: Checking Wazuh processes..."
    if docker exec wazuh-manager /var/ossec/bin/wazuh-control status > /dev/null 2>&1; then
        log_success "All Wazuh processes are running"
        docker exec wazuh-manager /var/ossec/bin/wazuh-control status
    else
        log_error "Some Wazuh processes are not running"
        return 1
    fi

    echo ""

    # Test 5: Test connectivity between containers
    log_info "Test 5: Testing connectivity between containers..."
    if docker exec wazuh-manager curl -sf http://quickwit-server:7280/health > /dev/null 2>&1; then
        log_success "Wazuh can reach Quickwit"
    else
        log_error "Wazuh cannot reach Quickwit"
        return 1
    fi

    echo ""

    # Test 6: Check if alerts can be searched
    log_info "Test 6: Testing Quickwit search..."
    SEARCH_RESULT=$(curl -s "http://localhost:7280/api/v1/wazuh-alerts/search?query=*&max_hits=1")
    if echo "$SEARCH_RESULT" | grep -q "num_hits"; then
        NUM_HITS=$(echo "$SEARCH_RESULT" | grep -o '"num_hits":[0-9]*' | cut -d':' -f2)
        log_success "Search query successful. Found $NUM_HITS alerts"
    else
        log_warning "Search query returned unexpected result (index may be empty)"
    fi

    echo ""
    log_success "All tests completed!"
}

# Clean up
clean_stack() {
    local remove_volumes=$1

    log_warning "This will stop and remove all containers"
    if [ "$remove_volumes" = "volumes" ]; then
        log_error "This will also DELETE all data in volumes!"
    fi

    read -p "Are you sure? (yes/no): " -r
    echo
    if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
        log_info "Aborted"
        return 0
    fi

    log_info "Stopping and removing containers..."
    if [ "$remove_volumes" = "volumes" ]; then
        docker compose -f "$COMPOSE_FILE" down -v
        log_warning "All data has been deleted"
    else
        docker compose -f "$COMPOSE_FILE" down
        log_info "Volumes preserved. Data is still available."
    fi

    log_success "Cleanup complete"
}

# Show container resource usage
show_top() {
    log_info "Container resource usage:"
    docker stats --no-stream $(docker compose -f "$COMPOSE_FILE" ps -q)
}

# Show running containers
show_ps() {
    docker compose -f "$COMPOSE_FILE" ps
}

# Main
main() {
    check_docker

    case "${1:-}" in
        start)
            start_services
            ;;
        stop)
            stop_services
            ;;
        restart)
            restart_services
            ;;
        status)
            show_status
            ;;
        logs)
            show_logs
            ;;
        logs-wazuh)
            show_logs wazuh-manager
            ;;
        logs-quickwit)
            show_logs quickwit-server
            ;;
        build)
            build_images
            ;;
        rebuild)
            rebuild_services
            ;;
        shell-wazuh)
            open_shell wazuh-manager
            ;;
        shell-quickwit)
            open_shell quickwit-server
            ;;
        test)
            run_tests
            ;;
        clean)
            clean_stack
            ;;
        purge)
            clean_stack volumes
            ;;
        ps)
            show_ps
            ;;
        top)
            show_top
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            if [ -n "$1" ]; then
                log_error "Unknown command: $1"
                echo ""
            fi
            show_help
            exit 1
            ;;
    esac
}

main "$@"
