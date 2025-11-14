# Quickwit Integration Porting Notes

## Version Information

- **Source Repository**: https://github.com/Baptiste-Leterrier/wazuh-qw (Wazuh v5.0.0-alpha0)
- **Target Repository**: wazuh-quickwit (Wazuh v4.14.1-rc2)
- **Porting Date**: 2025-11-13

## Successfully Ported Components

### 1. Documentation Files
- `BUILD_WITH_QUICKWIT.md` - Complete build instructions for Quickwit integration
- `DOCKER_QUICKWIT_SETUP.md` - Docker compose setup and deployment guide
- `QUICKWIT_INTEGRATION.md` - Integration architecture and usage documentation

### 2. Docker Infrastructure
Complete `docker/` directory with:
- `docker-compose.yml` - Orchestration for Wazuh Manager + Quickwit Server
- `Dockerfile` - Multi-stage build for Wazuh with Quickwit support
- `.env.example` - Environment variable templates
- `config/ossec.conf` - Wazuh configuration with Quickwit indexer settings
- `config/quickwit-index.yaml` - Quickwit index schema for wazuh-alerts
- `scripts/entrypoint.sh` - Container initialization with Quickwit connectivity checks
- `scripts/healthcheck.sh` - Health monitoring for Wazuh and Quickwit services
- `scripts/manage_stack.sh` - Stack management utility

### 3. C++ Indexer Connector (src/shared_modules/indexer_connector/)

#### New Files
- `include/quickwitConnector.hpp` - Quickwit async connector interface
- `src/quickwitConnectorAsync.cpp` - Facade implementation
- `src/quickwitConnectorAsyncImpl.hpp` - Core NDJSON-based implementation for Quickwit ingest API

#### Modified Files
- `CMakeLists.txt` - Updated C++ standard to C++20, added simdjson dependency
- `src/monitoring.hpp` - Added Quickwit health check support (`/health/livez` endpoint)
- `src/serverSelector.hpp` - Templatized to support custom health check endpoints

### 4. Python SDK (framework/wazuh/quickwit/)
- `__init__.py` - Module initialization
- `client.py` - REST API client for Quickwit with search, indexing, and cluster operations
- `dashboard.py` - Pre-built analytics queries for security dashboards
- `README.md` - Python SDK usage documentation

## Components NOT Ported (Version Incompatibility)

### engine/wiconnector/ (Wazuh v5.0+ only)
The following files could not be ported as they depend on the `src/engine/` infrastructure which only exists in Wazuh v5.0:

- `src/engine/source/wiconnector/include/wiconnector/connectorFactory.hpp`
- `src/engine/source/wiconnector/include/wiconnector/wquickwitconnector.hpp`
- `src/engine/source/wiconnector/src/wquickwitconnector.cpp`
- `src/engine/source/wiconnector/CMakeLists.txt`

**Impact**: The connector factory pattern is not available in v4.14. Direct usage of `QuickwitConnectorAsync` from `indexer_connector` is required instead.

## Key Technical Changes

### Build System
- **C++ Standard**: Upgraded from C++17 to C++20 (required for Quickwit connector)
- **New Dependency**: simdjson library added for fast JSON parsing

### Quickwit vs OpenSearch Differences
1. **API Format**: NDJSON ingest instead of Elasticsearch bulk API
2. **Endpoint**: `/api/v1/<index>/ingest?commit=auto` vs `/_bulk`
3. **Health Check**: `/health/livez` (text response) vs `/_cat/health` (JSON response)
4. **Document IDs**: Not used by Quickwit (ignores IDs and versions)
5. **Response Format**: `{"num_docs_for_processing": N}` vs Elasticsearch bulk response

## Integration Points

### Configuration (ossec.conf)
```xml
<indexer>
  <enabled>yes</enabled>
  <type>quickwit</type>
  <hosts>
    <host>http://quickwit-server:7280</host>
  </hosts>
</indexer>
```

### Docker Deployment
```bash
cd docker
cp .env.example .env
docker compose up -d
```

### Python Usage
```python
from wazuh.quickwit.client import QuickwitClient

client = QuickwitClient(hosts=["http://localhost:7280"])
results = client.search("wazuh-alerts", query="rule.level:>=12")
```

## Testing Recommendations

1. **Build Test**: Verify compilation with new C++20 standard and simdjson dependency
2. **Integration Test**: Test Quickwit connector against live Quickwit instance
3. **Docker Test**: Validate docker-compose deployment end-to-end
4. **Python SDK Test**: Test client operations against Quickwit API

## Known Limitations

1. **Version Constraint**: Designed for Wazuh 4.14.x, lacks v5.0 engine features
2. **Factory Pattern**: Manual connector instantiation required (no factory in v4.14)
3. **Build Dependencies**: Requires simdjson library in build environment

## Migration Path to v5.0

When upgrading to Wazuh v5.0, additionally port:
1. Complete `src/engine/` directory structure
2. `wiconnector` files with factory pattern support
3. Update build system to use engine's CMake integration
