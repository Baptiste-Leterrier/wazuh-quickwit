# Running Wazuh with Quickwit in Docker Containers

This guide explains how to build and run Wazuh with Quickwit support in Docker containers, with Wazuh and Quickwit running in separate containers that communicate over a Docker network.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Setup](#detailed-setup)
  - [Docker Compose Setup](#docker-compose-setup)
  - [Manual Setup](#manual-setup)
- [Configuration](#configuration)
- [Management](#management)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Advanced Topics](#advanced-topics)

## Overview

This setup provides:

- **Wazuh Manager** container with Quickwit integration built-in
- **Quickwit Server** container for log indexing and search
- **Docker network** for inter-container communication
- **Persistent volumes** for data retention
- **Health checks** for monitoring
- **Easy management** with helper scripts

## Architecture

```
┌─────────────────────────────────────────────────┐
│             Docker Host                          │
│                                                  │
│  ┌──────────────────┐    ┌──────────────────┐  │
│  │  Wazuh Container │    │ Quickwit Container│  │
│  │                  │    │                   │  │
│  │  - Wazuh Manager │───▶│  - Quickwit Server│  │
│  │  - Quickwit SDK  │    │  - REST API :7280 │  │
│  │  - Configuration │    │  - Data storage   │  │
│  │                  │    │                   │  │
│  └──────────────────┘    └──────────────────┘  │
│         │                         │             │
│         │                         │             │
│  ┌──────▼─────────┐    ┌─────────▼─────────┐  │
│  │ wazuh-data     │    │ quickwit-data     │  │
│  │ (volume)       │    │ (volume)          │  │
│  └────────────────┘    └───────────────────┘  │
│                                                 │
│         wazuh-quickwit-network                 │
└─────────────────────────────────────────────────┘
```

### Components

1. **Wazuh Container**
   - Based on Ubuntu/Debian
   - Wazuh Manager built with Quickwit support
   - Python SDK for Quickwit integration
   - Configured to send alerts to Quickwit

2. **Quickwit Container**
   - Official Quickwit image or custom build
   - Exposed on port 7280
   - Pre-configured with Wazuh alerts index
   - Persistent data storage

3. **Docker Network**
   - Bridge network for container communication
   - Internal DNS resolution
   - Isolated from host network (optional)

## Prerequisites

### Required Software

```bash
# Docker (20.10+)
docker --version

# Docker Compose (2.0+)
docker compose version

# Git
git --version

# Optional: curl for testing
curl --version
```

### Install Docker

**Linux:**
```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker
```

**macOS:**
```bash
# Install Docker Desktop
brew install --cask docker
```

**Windows:**
Download and install Docker Desktop from https://www.docker.com/products/docker-desktop

### System Requirements

- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Disk**: Minimum 20GB free space
- **CPU**: 2+ cores recommended

## Quick Start

### One-Command Setup

```bash
# Clone the repository
git clone https://github.com/wazuh/wazuh.git
cd wazuh

# Start everything with Docker Compose
docker compose -f docker/docker-compose.yml up -d

# Check status
docker compose -f docker/docker-compose.yml ps

# View logs
docker compose -f docker/docker-compose.yml logs -f
```

### Using Helper Script

```bash
# Start the stack
./docker/scripts/manage_stack.sh start

# Check status
./docker/scripts/manage_stack.sh status

# View logs
./docker/scripts/manage_stack.sh logs

# Stop the stack
./docker/scripts/manage_stack.sh stop
```

### Verify Setup

```bash
# Check Quickwit health
curl http://localhost:7280/health

# Check Wazuh is running
docker exec wazuh-manager /var/ossec/bin/wazuh-control status

# Search for alerts (after some time)
curl "http://localhost:7280/api/v1/wazuh-alerts/search?query=*&max_hits=10"
```

## Detailed Setup

### Docker Compose Setup

The Docker Compose file orchestrates both containers.

#### File Structure

```
docker/
├── docker-compose.yml           # Main orchestration file
├── Dockerfile                   # Wazuh build instructions
├── config/
│   ├── ossec.conf              # Wazuh configuration
│   └── quickwit-index.yaml     # Quickwit index configuration
├── scripts/
│   ├── entrypoint.sh           # Wazuh container entrypoint
│   ├── healthcheck.sh          # Health check script
│   └── manage_stack.sh         # Management helper script
└── .env                        # Environment variables
```

#### Environment Variables

Create `docker/.env`:

```bash
# Wazuh Configuration
WAZUH_VERSION=4.9.0
WAZUH_API_PORT=55000
WAZUH_REGISTRATION_PORT=1514
WAZUH_CLUSTER_PORT=1516

# Quickwit Configuration
QUICKWIT_VERSION=0.8.1
QUICKWIT_REST_PORT=7280
QUICKWIT_GRPC_PORT=7281
QUICKWIT_INDEX_NAME=wazuh-alerts

# Network Configuration
NETWORK_NAME=wazuh-quickwit-network

# Volume Configuration
WAZUH_DATA_VOLUME=wazuh-data
QUICKWIT_DATA_VOLUME=quickwit-data

# Build Configuration
BUILD_JOBS=4
BUILD_DEBUG=false
```

#### Starting the Stack

```bash
# Start in foreground (see logs)
docker compose -f docker/docker-compose.yml up

# Start in background
docker compose -f docker/docker-compose.yml up -d

# Start and rebuild
docker compose -f docker/docker-compose.yml up --build -d

# Start specific service
docker compose -f docker/docker-compose.yml up quickwit -d
```

#### Stopping the Stack

```bash
# Stop containers (keep data)
docker compose -f docker/docker-compose.yml down

# Stop and remove volumes (delete data)
docker compose -f docker/docker-compose.yml down -v

# Stop and remove images
docker compose -f docker/docker-compose.yml down --rmi all
```

### Manual Setup

If you prefer manual setup without Docker Compose:

#### 1. Create Network

```bash
docker network create wazuh-quickwit-network
```

#### 2. Start Quickwit Container

```bash
docker run -d \
  --name quickwit-server \
  --network wazuh-quickwit-network \
  -p 7280:7280 \
  -v quickwit-data:/quickwit/qwdata \
  quickwit/quickwit:0.8.1 \
  run
```

#### 3. Create Quickwit Index

```bash
# Copy index configuration
docker cp docker/config/quickwit-index.yaml quickwit-server:/tmp/

# Create index
docker exec quickwit-server \
  quickwit index create --index-config /tmp/quickwit-index.yaml
```

#### 4. Build Wazuh Image

```bash
docker build -t wazuh-quickwit:latest -f docker/Dockerfile .
```

#### 5. Start Wazuh Container

```bash
docker run -d \
  --name wazuh-manager \
  --network wazuh-quickwit-network \
  -p 55000:55000 \
  -p 1514:1514/udp \
  -p 1515:1515 \
  -p 1516:1516 \
  -v wazuh-data:/var/ossec \
  -e QUICKWIT_HOST=quickwit-server \
  -e QUICKWIT_PORT=7280 \
  wazuh-quickwit:latest
```

## Configuration

### Wazuh Configuration

The Wazuh configuration is in `docker/config/ossec.conf`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
  </global>

  <indexer>
    <enabled>yes</enabled>
    <type>quickwit</type>
    <hosts>
      <host>http://quickwit-server:7280</host>
    </hosts>
  </indexer>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>

  <alerts>
    <log_alert_level>3</log_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
```

#### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `<type>` | Indexer backend (quickwit/opensearch) | `opensearch` |
| `<host>` | Quickwit server URL | `http://quickwit-server:7280` |
| `<enabled>` | Enable/disable indexer | `yes` |

### Quickwit Index Configuration

Located at `docker/config/quickwit-index.yaml`:

```yaml
version: 0.8

index_id: wazuh-alerts

doc_mapping:
  field_mappings:
    - name: timestamp
      type: datetime
      input_formats:
        - rfc3339
        - unix_timestamp
      fast: true

    - name: agent.id
      type: text
      tokenizer: raw
      fast: true

    - name: agent.name
      type: text
      tokenizer: default

    - name: agent.ip
      type: ip
      fast: true

    - name: manager.name
      type: text
      tokenizer: raw

    - name: rule.id
      type: u64
      fast: true

    - name: rule.level
      type: u64
      fast: true

    - name: rule.description
      type: text
      tokenizer: default

    - name: rule.mitre.id
      type: text
      tokenizer: raw
      fast: true

    - name: rule.mitre.tactic
      type: text
      tokenizer: raw

    - name: data
      type: json

    - name: full_log
      type: text
      tokenizer: default

    - name: location
      type: text
      tokenizer: raw

  timestamp_field: timestamp
  mode: dynamic

indexing_settings:
  commit_timeout_secs: 10
  merge_policy:
    type: stable_log
    merge_factor: 10
    max_merge_factor: 12

search_settings:
  default_search_fields: [full_log, rule.description]
```

### Environment-based Configuration

You can override configuration via environment variables:

```bash
# In docker-compose.yml or .env
QUICKWIT_HOST=quickwit-server
QUICKWIT_PORT=7280
QUICKWIT_INDEX=wazuh-alerts
WAZUH_LOG_LEVEL=info
WAZUH_ALERT_LEVEL=3
```

## Management

### Using Docker Compose

```bash
# View status
docker compose -f docker/docker-compose.yml ps

# View logs
docker compose -f docker/docker-compose.yml logs -f

# View logs for specific service
docker compose -f docker/docker-compose.yml logs -f wazuh-manager
docker compose -f docker/docker-compose.yml logs -f quickwit-server

# Restart services
docker compose -f docker/docker-compose.yml restart

# Restart specific service
docker compose -f docker/docker-compose.yml restart wazuh-manager

# Execute commands in container
docker compose -f docker/docker-compose.yml exec wazuh-manager bash
docker compose -f docker/docker-compose.yml exec quickwit-server sh

# Scale services (if applicable)
docker compose -f docker/docker-compose.yml up -d --scale wazuh-manager=2
```

### Using Helper Script

```bash
./docker/scripts/manage_stack.sh [command]

Commands:
  start       - Start all services
  stop        - Stop all services
  restart     - Restart all services
  status      - Show service status
  logs        - Show logs (all services)
  logs-wazuh  - Show Wazuh logs
  logs-qw     - Show Quickwit logs
  build       - Rebuild images
  clean       - Stop and remove everything
  shell       - Open shell in Wazuh container
  test        - Run health checks
```

### Container Management

```bash
# Access Wazuh container
docker exec -it wazuh-manager bash

# Access Quickwit container
docker exec -it quickwit-server sh

# Check Wazuh status
docker exec wazuh-manager /var/ossec/bin/wazuh-control status

# Check Wazuh info
docker exec wazuh-manager /var/ossec/bin/wazuh-control info

# Restart Wazuh
docker exec wazuh-manager /var/ossec/bin/wazuh-control restart

# View Wazuh logs
docker exec wazuh-manager tail -f /var/ossec/logs/ossec.log
```

### Volume Management

```bash
# List volumes
docker volume ls | grep -E 'wazuh|quickwit'

# Inspect volume
docker volume inspect wazuh-data
docker volume inspect quickwit-data

# Backup volume
docker run --rm -v wazuh-data:/data -v $(pwd):/backup \
  ubuntu tar czf /backup/wazuh-backup.tar.gz /data

# Restore volume
docker run --rm -v wazuh-data:/data -v $(pwd):/backup \
  ubuntu tar xzf /backup/wazuh-backup.tar.gz -C /

# Remove volumes (caution: deletes data!)
docker volume rm wazuh-data quickwit-data
```

## Testing

### Health Checks

```bash
# Check Quickwit health
curl http://localhost:7280/health

# Check Quickwit cluster info
curl http://localhost:7280/api/v1/cluster

# Check Wazuh is running
docker exec wazuh-manager /var/ossec/bin/wazuh-control status

# Check Wazuh can connect to Quickwit
docker exec wazuh-manager curl http://quickwit-server:7280/health
```

### Verify Index

```bash
# List Quickwit indices
curl http://localhost:7280/api/v1/indexes

# Get index metadata
curl http://localhost:7280/api/v1/indexes/wazuh-alerts

# Check index statistics
curl http://localhost:7280/api/v1/indexes/wazuh-alerts/stats
```

### Generate Test Alerts

```bash
# Generate test alert in Wazuh
docker exec wazuh-manager /var/ossec/bin/wazuh-logtest << EOF
Nov 10 10:30:00 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
EOF

# Wait a few seconds, then search
curl "http://localhost:7280/api/v1/wazuh-alerts/search?query=*&max_hits=10"
```

### Search Alerts

```bash
# Search all alerts
curl "http://localhost:7280/api/v1/wazuh-alerts/search?query=*&max_hits=100"

# Search high severity alerts
curl "http://localhost:7280/api/v1/wazuh-alerts/search?query=rule.level:>=12&max_hits=50"

# Search by agent
curl "http://localhost:7280/api/v1/wazuh-alerts/search?query=agent.id:001"

# Search with time range
curl "http://localhost:7280/api/v1/wazuh-alerts/search?query=*&start_timestamp=1699000000&end_timestamp=1699999999"
```

### Using Python SDK

```python
# Inside Wazuh container
docker exec -it wazuh-manager python3 << 'EOF'
from wazuh.quickwit.client import QuickwitClient
from wazuh.quickwit.dashboard import QuickwitDashboard

# Initialize client
client = QuickwitClient(hosts=["http://quickwit-server:7280"])

# Health check
health = client.health_check()
print(f"Quickwit status: {health['status']}")

# Search alerts
results = client.search(
    index="wazuh-alerts",
    query="*",
    max_hits=10
)
print(f"Found {results['num_hits']} alerts")

# Dashboard
dashboard = QuickwitDashboard(client)
summary = dashboard.get_alerts_summary(time_range_hours=24)
print(f"Total alerts (24h): {summary['total_alerts']}")
EOF
```

## Troubleshooting

### Container Issues

#### Containers won't start

```bash
# Check Docker daemon
sudo systemctl status docker

# Check logs
docker compose -f docker/docker-compose.yml logs

# Check for port conflicts
sudo netstat -tulpn | grep -E '7280|55000|1514'

# Remove and recreate
docker compose -f docker/docker-compose.yml down
docker compose -f docker/docker-compose.yml up -d
```

#### Build failures

```bash
# Clean build cache
docker builder prune

# Rebuild with no cache
docker compose -f docker/docker-compose.yml build --no-cache

# Check build logs
docker compose -f docker/docker-compose.yml build 2>&1 | tee build.log
```

### Network Issues

#### Containers can't communicate

```bash
# Check network exists
docker network ls | grep wazuh-quickwit

# Inspect network
docker network inspect wazuh-quickwit-network

# Check container IPs
docker inspect -f '{{.Name}} - {{.NetworkSettings.Networks}}' $(docker ps -q)

# Test connectivity
docker exec wazuh-manager ping -c 3 quickwit-server
docker exec wazuh-manager curl http://quickwit-server:7280/health
```

#### DNS resolution fails

```bash
# Use IP address instead of hostname
docker inspect quickwit-server | grep IPAddress

# Update ossec.conf with IP:
<host>http://172.18.0.2:7280</host>
```

### Quickwit Issues

#### Index not created

```bash
# Check if index exists
curl http://localhost:7280/api/v1/indexes

# Recreate index
docker exec quickwit-server \
  quickwit index create --index-config /quickwit/config/wazuh-alerts-index.yaml

# Check index creation logs
docker logs quickwit-server | grep -i index
```

#### No data being indexed

```bash
# Check Wazuh logs for indexer errors
docker exec wazuh-manager tail -f /var/ossec/logs/ossec.log | grep -i "quickwit\|indexer"

# Check Quickwit ingest logs
docker logs quickwit-server | grep -i ingest

# Verify configuration
docker exec wazuh-manager cat /var/ossec/etc/ossec.conf | grep -A 10 indexer

# Test manual indexing
docker exec wazuh-manager curl -X POST \
  http://quickwit-server:7280/api/v1/wazuh-alerts/ingest \
  -H 'Content-Type: application/json' \
  -d '{"timestamp": "2025-01-01T00:00:00Z", "rule": {"id": 100, "level": 5, "description": "Test"}}'
```

### Performance Issues

#### High memory usage

```bash
# Check container stats
docker stats

# Limit memory in docker-compose.yml:
services:
  wazuh-manager:
    mem_limit: 4g
  quickwit-server:
    mem_limit: 2g
```

#### Slow indexing

```bash
# Check Quickwit commit settings in index config
# Increase commit_timeout_secs if needed

# Check disk I/O
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.BlockIO}}"

# Check Quickwit logs for performance warnings
docker logs quickwit-server | grep -i "slow\|warn\|performance"
```

### Data Issues

#### Lost data after restart

```bash
# Check volumes are mounted
docker inspect wazuh-manager | grep -A 5 Mounts
docker inspect quickwit-server | grep -A 5 Mounts

# Ensure volumes are defined in docker-compose.yml
```

#### Disk space issues

```bash
# Check Docker disk usage
docker system df

# Clean up
docker system prune -a --volumes

# Check volume sizes
docker volume ls -q | xargs docker volume inspect | grep -E 'Name|Mountpoint'
du -sh /var/lib/docker/volumes/*
```

## Advanced Topics

### Multi-Node Setup

For production deployment with multiple Wazuh managers:

```yaml
# docker-compose-cluster.yml
services:
  wazuh-master:
    # ... master configuration

  wazuh-worker-1:
    # ... worker configuration

  wazuh-worker-2:
    # ... worker configuration

  quickwit-server:
    # ... quickwit configuration
```

### SSL/TLS Configuration

```yaml
# docker-compose.yml
services:
  quickwit-server:
    environment:
      - QW_ENABLE_TLS=true
    volumes:
      - ./certs:/quickwit/certs:ro

  wazuh-manager:
    environment:
      - QUICKWIT_HTTPS=true
      - QUICKWIT_CA_CERT=/var/ossec/certs/ca.pem
```

### Custom Build Arguments

```bash
# Build with custom Wazuh version
docker build \
  --build-arg WAZUH_VERSION=4.9.0 \
  --build-arg BUILD_JOBS=8 \
  -t wazuh-quickwit:4.9.0 \
  -f docker/Dockerfile .
```

### Persistent Configuration

```yaml
# docker-compose.yml
services:
  wazuh-manager:
    volumes:
      - ./config/ossec.conf:/var/ossec/etc/ossec.conf:ro
      - ./config/local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro
```

### Monitoring and Logging

```bash
# Export logs to host
docker compose -f docker/docker-compose.yml logs > logs/all.log

# Centralized logging with syslog
docker run -d \
  --log-driver=syslog \
  --log-opt syslog-address=udp://syslog-server:514 \
  wazuh-manager

# Prometheus metrics (if configured)
curl http://localhost:9090/metrics
```

### Backup and Recovery

```bash
# Backup script
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
docker compose -f docker/docker-compose.yml stop
docker run --rm -v wazuh-data:/data -v $(pwd)/backups:/backup \
  ubuntu tar czf /backup/wazuh-${DATE}.tar.gz /data
docker run --rm -v quickwit-data:/data -v $(pwd)/backups:/backup \
  ubuntu tar czf /backup/quickwit-${DATE}.tar.gz /data
docker compose -f docker/docker-compose.yml start
```

## Additional Resources

- **Build Documentation**: [BUILD_WITH_QUICKWIT.md](BUILD_WITH_QUICKWIT.md)
- **Integration Guide**: [QUICKWIT_INTEGRATION.md](QUICKWIT_INTEGRATION.md)
- **Quick Start**: [QUICKSTART_BUILD.md](QUICKSTART_BUILD.md)
- **Docker Documentation**: https://docs.docker.com
- **Wazuh Docker**: https://documentation.wazuh.com/current/deployment-options/docker/
- **Quickwit Documentation**: https://quickwit.io/docs

## Contributing

When contributing Docker-related changes:

1. Test with clean volumes: `docker compose down -v && docker compose up`
2. Verify on multiple platforms (Linux, macOS)
3. Update documentation for any configuration changes
4. Test with different Docker versions
5. Include health checks and proper logging

## License

Copyright (C) 2015, Wazuh Inc.

This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
