# Wazuh with Quickwit - Docker Setup

This directory contains everything needed to run Wazuh with Quickwit support in Docker containers.

## ⚠️ Build Failing? Start Here!

If your Docker build is failing:

1. **See detailed step-by-step guide:** [DEBUG_BUILD_FAILURE.md](DEBUG_BUILD_FAILURE.md)
2. **Run error diagnostic:** `./get-build-error.sh`
3. **Try minimal Dockerfile:** `cp Dockerfile.minimal Dockerfile`
4. **Quick troubleshooting:** [QUICK_FIX.md](QUICK_FIX.md)
5. **Comprehensive guide:** [DOCKER_BUILD_TROUBLESHOOTING.md](DOCKER_BUILD_TROUBLESHOOTING.md)

## Quick Start

```bash
# 1. Copy environment file
cp .env.example .env

# 2. Start the stack
docker compose up -d

# 3. Check status
docker compose ps

# 4. View logs
docker compose logs -f
```

Or use the management script:

```bash
# Start
./scripts/manage_stack.sh start

# Check status
./scripts/manage_stack.sh status

# Run tests
./scripts/manage_stack.sh test
```

## Directory Structure

```
docker/
├── README.md                    # This file
├── Dockerfile                   # Wazuh image build instructions
├── docker-compose.yml           # Container orchestration
├── .env.example                 # Environment variables template
├── config/                      # Configuration files
│   ├── ossec.conf              # Wazuh configuration
│   └── quickwit-index.yaml     # Quickwit index configuration
└── scripts/                     # Helper scripts
    ├── entrypoint.sh           # Wazuh container entrypoint
    ├── healthcheck.sh          # Health check script
    └── manage_stack.sh         # Stack management script
```

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- At least 4GB RAM
- At least 20GB disk space

## Configuration

### Environment Variables

Edit `.env` to customize:

```bash
# Wazuh version
WAZUH_VERSION=4.9.0

# Quickwit version
QUICKWIT_VERSION=0.8.1

# Ports
QUICKWIT_REST_PORT=7280
WAZUH_API_PORT=55000
```

### Wazuh Configuration

Edit `config/ossec.conf` to customize Wazuh settings. The important section for Quickwit integration:

```xml
<indexer>
  <enabled>yes</enabled>
  <type>quickwit</type>
  <hosts>
    <host>http://quickwit-server:7280</host>
  </hosts>
</indexer>
```

### Quickwit Index

The Quickwit index is defined in `config/quickwit-index.yaml`. This file is automatically loaded when the Quickwit container starts.

## Usage

### Using Docker Compose

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# View logs
docker compose logs -f

# Restart services
docker compose restart

# Rebuild and restart
docker compose up -d --build
```

### Using Management Script

```bash
# Start services
./scripts/manage_stack.sh start

# Stop services
./scripts/manage_stack.sh stop

# Restart services
./scripts/manage_stack.sh restart

# Show status
./scripts/manage_stack.sh status

# Show logs
./scripts/manage_stack.sh logs

# Show Wazuh logs only
./scripts/manage_stack.sh logs-wazuh

# Show Quickwit logs only
./scripts/manage_stack.sh logs-quickwit

# Open shell in Wazuh container
./scripts/manage_stack.sh shell-wazuh

# Open shell in Quickwit container
./scripts/manage_stack.sh shell-quickwit

# Run health checks
./scripts/manage_stack.sh test

# Build images
./scripts/manage_stack.sh build

# Clean up (keep data)
./scripts/manage_stack.sh clean

# Clean up (delete all data)
./scripts/manage_stack.sh purge
```

## Testing

### Verify Services

```bash
# Check Quickwit health
curl http://localhost:7280/health

# Check Wazuh status
docker exec wazuh-manager /var/ossec/bin/wazuh-control status

# Check if Wazuh can reach Quickwit
docker exec wazuh-manager curl http://quickwit-server:7280/health
```

### Search Alerts

```bash
# List Quickwit indices
curl http://localhost:7280/api/v1/indexes

# Search all alerts
curl "http://localhost:7280/api/v1/wazuh-alerts/search?query=*&max_hits=10"

# Search high severity alerts
curl "http://localhost:7280/api/v1/wazuh-alerts/search?query=rule.level:>=12"
```

### Generate Test Alert

```bash
# Create a test log entry
docker exec wazuh-manager /var/ossec/bin/wazuh-logtest << EOF
Nov 10 10:30:00 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
EOF

# Wait a few seconds, then search for it
curl "http://localhost:7280/api/v1/wazuh-alerts/search?query=sshd"
```

## Troubleshooting

### Containers won't start

```bash
# Check Docker daemon
sudo systemctl status docker

# Check logs
docker compose logs

# Check for port conflicts
sudo netstat -tulpn | grep -E '7280|55000|1514'
```

### Build failures

```bash
# Clean build cache
docker builder prune

# Rebuild without cache
docker compose build --no-cache
```

### Quickwit connection issues

```bash
# Check Quickwit logs
docker logs quickwit-server

# Check network
docker network inspect wazuh-quickwit-network

# Test from Wazuh container
docker exec wazuh-manager ping quickwit-server
docker exec wazuh-manager curl http://quickwit-server:7280/health
```

### Data persistence issues

```bash
# List volumes
docker volume ls | grep -E 'wazuh|quickwit'

# Inspect volume
docker volume inspect wazuh-data

# Backup volume
docker run --rm -v wazuh-data:/data -v $(pwd):/backup \
  ubuntu tar czf /backup/wazuh-backup.tar.gz /data
```

## Accessing Services

Once running, services are available at:

- **Quickwit API**: http://localhost:7280
- **Wazuh API**: http://localhost:55000
- **Agent Registration**: TCP port 1515
- **Agent Communication**: TCP/UDP port 1514

## Data Persistence

Data is stored in Docker volumes:

- `wazuh-data`: Wazuh configuration and logs
- `quickwit-data`: Quickwit indices and data

To preserve data across container recreation, never use `docker compose down -v`.

## Resource Limits

Default resource limits (can be adjusted in docker-compose.yml):

**Wazuh:**
- CPU: 2-4 cores
- Memory: 2-4 GB

**Quickwit:**
- CPU: 1-2 cores
- Memory: 1-2 GB

## Security Considerations

1. **Network**: The default network is isolated. Only exposed ports are accessible from host.

2. **Volumes**: Data volumes are only accessible by containers by default.

3. **Credentials**: For production, configure authentication in `config/ossec.conf`:
   ```xml
   <indexer>
     <username>admin</username>
     <password>strong_password</password>
   </indexer>
   ```

4. **SSL/TLS**: For production, enable HTTPS for Quickwit and update Wazuh configuration.

## Advanced Usage

### Custom Build

```bash
# Build with specific version
docker build \
  --build-arg WAZUH_VERSION=4.9.0 \
  --build-arg BUILD_JOBS=8 \
  -t wazuh-quickwit:4.9.0 \
  -f Dockerfile ..
```

### Multi-node Setup

For cluster deployment, modify `docker-compose.yml` to add more Wazuh nodes and configure cluster settings in `config/ossec.conf`.

### Monitoring

```bash
# View resource usage
docker stats

# Export metrics (if configured)
curl http://localhost:9090/metrics
```

## Documentation

For more detailed information:

- **Docker Setup Guide**: [../DOCKER_QUICKWIT_SETUP.md](../DOCKER_QUICKWIT_SETUP.md)
- **Build Documentation**: [../BUILD_WITH_QUICKWIT.md](../BUILD_WITH_QUICKWIT.md)
- **Integration Guide**: [../QUICKWIT_INTEGRATION.md](../QUICKWIT_INTEGRATION.md)
- **Quick Start**: [../QUICKSTART_BUILD.md](../QUICKSTART_BUILD.md)

## Support

For issues or questions:

1. Check logs: `docker compose logs`
2. Run health checks: `./scripts/manage_stack.sh test`
3. Review troubleshooting section in [DOCKER_QUICKWIT_SETUP.md](../DOCKER_QUICKWIT_SETUP.md)
4. Check Wazuh documentation: https://documentation.wazuh.com
5. Check Quickwit documentation: https://quickwit.io/docs

## License

Copyright (C) 2015, Wazuh Inc.

This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
