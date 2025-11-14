# Building Wazuh with Quickwit Support

This guide provides comprehensive instructions for building Wazuh with Quickwit integration support, with specific focus on macOS development environments.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
  - [macOS Prerequisites](#macos-prerequisites)
  - [Linux Prerequisites](#linux-prerequisites)
- [Quick Start](#quick-start)
- [Manual Build Process](#manual-build-process)
  - [Step 1: Install Dependencies](#step-1-install-dependencies)
  - [Step 2: Build Wazuh](#step-2-build-wazuh)
  - [Step 3: Install Wazuh](#step-3-install-wazuh)
  - [Step 4: Setup Quickwit](#step-4-setup-quickwit)
  - [Step 5: Configure Wazuh](#step-5-configure-wazuh)
- [Automated Build Script](#automated-build-script)
- [Testing the Integration](#testing-the-integration)
- [Development Workflow](#development-workflow)
- [Troubleshooting](#troubleshooting)
- [Architecture Details](#architecture-details)

## Overview

The Quickwit integration allows Wazuh to use Quickwit as an alternative indexer backend instead of OpenSearch/Elasticsearch. The integration includes:

- **C++ Connector** (`src/shared_modules/indexer_connector/`): Core async HTTP client for Quickwit ingest API
- **Engine Integration** (`src/engine/source/wiconnector/`): Wazuh engine connector implementation
- **Python SDK** (`framework/wazuh/quickwit/`): Python client and dashboard utilities
- **Factory Pattern**: Automatic backend selection based on configuration

## Prerequisites

### macOS Prerequisites

#### Required Tools

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required build tools
brew install cmake
brew install make
brew install git
brew install wget
brew install curl
brew install pkg-config
```

#### Required Libraries

```bash
# Install build dependencies
brew install openssl@3
brew install sqlite
brew install rocksdb
brew install nlohmann-json
brew install simdjson
brew install cjson
brew install yaml-cpp
brew install libarchive
brew install pcre2
brew install zlib
brew install bzip2
brew install xz

# Python dependencies (Wazuh uses embedded Python)
brew install python@3.10
```

#### Optional Development Tools

```bash
# Code quality tools
brew install cppcheck
brew install llvm  # For scan-build
brew install lcov   # For coverage reports

# Testing tools
brew install googletest
```

### Linux Prerequisites

For Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    gcc \
    g++ \
    make \
    git \
    wget \
    curl \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    libarchive-dev \
    libpcre2-dev \
    zlib1g-dev \
    libbz2-dev \
    liblzma-dev \
    python3-dev \
    python3-pip
```

For CentOS/RHEL:

```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y \
    cmake \
    gcc \
    gcc-c++ \
    make \
    git \
    wget \
    curl \
    pkgconfig \
    openssl-devel \
    sqlite-devel \
    libarchive-devel \
    pcre2-devel \
    zlib-devel \
    bzip2-devel \
    xz-devel \
    python3-devel
```

## Quick Start

For macOS users, use the automated build script:

```bash
# Clone the repository
git clone https://github.com/wazuh/wazuh.git
cd wazuh

# Run the automated build script
./scripts/build_wazuh_with_quickwit_macos.sh

# Follow the prompts to configure and install
```

## Manual Build Process

### Step 1: Install Dependencies

#### macOS

```bash
# Set environment variables for OpenSSL
export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
export PKG_CONFIG_PATH="$OPENSSL_ROOT_DIR/lib/pkgconfig:$PKG_CONFIG_PATH"

# Verify installations
cmake --version
gcc --version
```

#### Build External Dependencies

Wazuh includes a dependency management system:

```bash
cd src
make deps TARGET=server  # For server/manager build
# OR
make deps TARGET=agent   # For agent build
```

This will download and build required external libraries that are not provided by the system.

### Step 2: Build Wazuh

#### Configuration

The Quickwit integration is automatically included in the build. No special flags are needed.

#### Build for macOS (Agent)

```bash
cd src

# Build with default settings
make TARGET=agent build -j$(sysctl -n hw.ncpu)

# Build with debug symbols (recommended for development)
make TARGET=agent DEBUG=1 build -j$(sysctl -n hw.ncpu)

# Build with tests enabled
make TARGET=agent DEBUG=1 TEST=1 build -j$(sysctl -n hw.ncpu)
```

#### Build for macOS (Server/Manager)

Note: macOS is typically used for agent development. For server builds, Linux is recommended.

```bash
cd src

# Build server components
make TARGET=server build -j$(sysctl -n hw.ncpu)
```

#### Build Options

| Variable | Description | Values | Default |
|----------|-------------|--------|---------|
| `TARGET` | Build target | `agent`, `server`, `winagent` | Required |
| `DEBUG` | Include debug symbols | `0`, `1` | `0` |
| `TEST` | Enable unit tests | `0`, `1` | `0` |
| `JOBS` or `-j` | Parallel build jobs | Number | `1` |
| `PREFIX` | Installation prefix | Path | `/var/ossec` |

### Step 3: Install Wazuh

```bash
# Run the installation script
sudo ./install.sh

# Or specify installation directory
sudo INSTALLDIR=/opt/wazuh ./install.sh
```

The installer will:
1. Copy binaries to the installation directory
2. Set up configuration files
3. Create necessary directories
4. Set proper permissions

### Step 4: Setup Quickwit

#### Install Quickwit

```bash
# Download Quickwit (macOS)
QUICKWIT_VERSION="0.8.1"  # Use latest stable version
curl -L https://github.com/quickwit-oss/quickwit/releases/download/v${QUICKWIT_VERSION}/quickwit-v${QUICKWIT_VERSION}-$(uname -m)-apple-darwin.tar.gz | tar -xz

cd quickwit-v${QUICKWIT_VERSION}

# Start Quickwit server
./quickwit run
```

#### Create Wazuh Index

Create an index configuration file `wazuh-alerts-index.yaml`:

```yaml
version: 0.8

index_id: wazuh-alerts

doc_mapping:
  field_mappings:
    - name: timestamp
      type: datetime
      input_formats:
        - rfc3339
      fast: true

    - name: agent.id
      type: text
      tokenizer: raw
      fast: true

    - name: agent.name
      type: text
      tokenizer: default

    - name: rule.id
      type: u64
      fast: true

    - name: rule.level
      type: u64
      fast: true

    - name: rule.description
      type: text
      tokenizer: default

    - name: data
      type: json

    - name: full_log
      type: text
      tokenizer: default

  timestamp_field: timestamp
  mode: dynamic

indexing_settings:
  commit_timeout_secs: 10

search_settings:
  default_search_fields: [full_log, rule.description]
```

Create the index:

```bash
./quickwit index create --index-config wazuh-alerts-index.yaml
```

### Step 5: Configure Wazuh

Edit the Wazuh configuration file (typically `/var/ossec/etc/ossec.conf` or during development in `etc/ossec.conf`):

```xml
<ossec_config>
  <indexer>
    <enabled>yes</enabled>
    <type>quickwit</type>
    <hosts>
      <host>http://localhost:7280</host>
    </hosts>
  </indexer>
</ossec_config>
```

For development, you can use the provided template:

```bash
cp etc/ossec-quickwit.conf /var/ossec/etc/ossec.conf
# Edit as needed
```

## Automated Build Script

An automated build script is provided for macOS: `scripts/build_wazuh_with_quickwit_macos.sh`

### Usage

```bash
./scripts/build_wazuh_with_quickwit_macos.sh [OPTIONS]

Options:
  --target TYPE        Build target: agent, server (default: agent)
  --debug             Enable debug build
  --test              Enable unit tests
  --jobs N            Number of parallel jobs (default: CPU count)
  --prefix DIR        Installation prefix (default: /var/ossec)
  --skip-deps         Skip dependency installation
  --skip-build        Skip Wazuh build (useful for config/test only)
  --setup-quickwit    Download and setup Quickwit server
  --clean             Clean previous build artifacts
  --help              Show help message
```

### Examples

```bash
# Standard development build with debug symbols
./scripts/build_wazuh_with_quickwit_macos.sh --debug

# Build with tests enabled
./scripts/build_wazuh_with_quickwit_macos.sh --debug --test

# Full setup including Quickwit server
./scripts/build_wazuh_with_quickwit_macos.sh --debug --setup-quickwit

# Clean build
./scripts/build_wazuh_with_quickwit_macos.sh --clean --debug

# Custom installation directory
./scripts/build_wazuh_with_quickwit_macos.sh --prefix /opt/wazuh-dev
```

## Testing the Integration

### Unit Tests

If built with `TEST=1`:

```bash
cd src
python3 build.py -t shared_modules/indexer_connector
python3 build.py -t engine/source/wiconnector
```

### Integration Testing

1. Start Quickwit:
   ```bash
   cd quickwit-v0.8.1
   ./quickwit run
   ```

2. Start Wazuh with Quickwit configuration:
   ```bash
   sudo /var/ossec/bin/wazuh-control start
   ```

3. Generate test alerts:
   ```bash
   # Trigger a test rule
   logger "Test alert for Wazuh"
   ```

4. Query Quickwit for alerts:
   ```bash
   curl "http://localhost:7280/api/v1/wazuh-alerts/search?query=*"
   ```

### Python SDK Testing

```python
from wazuh.quickwit.client import QuickwitClient
from wazuh.quickwit.dashboard import QuickwitDashboard

# Initialize client
client = QuickwitClient(hosts=["http://localhost:7280"])

# Test connection
health = client.health_check()
print(f"Quickwit health: {health}")

# Search for alerts
results = client.search(
    index="wazuh-alerts",
    query="*",
    max_hits=10
)
print(f"Found {results['num_hits']} alerts")

# Use dashboard utilities
dashboard = QuickwitDashboard(client)
summary = dashboard.get_alerts_summary(time_range_hours=24)
print(f"Total alerts in last 24h: {summary['total_alerts']}")
```

## Development Workflow

### Iterative Development

```bash
# 1. Make code changes to Quickwit connector
vim src/shared_modules/indexer_connector/src/quickwitConnectorAsync.cpp

# 2. Rebuild just the affected components
cd src
make TARGET=server build -j$(sysctl -n hw.ncpu)

# 3. Run unit tests
python3 build.py -t shared_modules/indexer_connector

# 4. Test integration
sudo /var/ossec/bin/wazuh-control restart
tail -f /var/ossec/logs/ossec.log | grep -i quickwit
```

### Code Quality Checks

```bash
# Run cppcheck
python3 src/build.py --cppcheck shared_modules/indexer_connector

# Run code formatting check
python3 src/build.py --scheck shared_modules/indexer_connector

# Format code
python3 src/build.py --sformat shared_modules/indexer_connector

# Run with address sanitizer
python3 src/build.py --asan shared_modules/indexer_connector

# Full ready-to-review checks
python3 src/build.py -r shared_modules/indexer_connector
```

### Debugging

#### Enable Debug Logging

Edit `ossec.conf`:

```xml
<ossec_config>
  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
```

#### View Logs

```bash
# Main Wazuh log
tail -f /var/ossec/logs/ossec.log

# Filter for Quickwit messages
tail -f /var/ossec/logs/ossec.log | grep -i "quickwit\|indexer"
```

#### Debugging with lldb (macOS)

```bash
# Run Wazuh manager under debugger
sudo lldb /var/ossec/bin/wazuh-analysisd

# Set breakpoints
(lldb) breakpoint set --name QuickwitConnectorAsync::publish
(lldb) run
```

## Troubleshooting

### Build Issues

#### OpenSSL Not Found

```bash
# Ensure OpenSSL is properly linked
export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
export PKG_CONFIG_PATH="$OPENSSL_ROOT_DIR/lib/pkgconfig:$PKG_CONFIG_PATH"
export LDFLAGS="-L$OPENSSL_ROOT_DIR/lib"
export CPPFLAGS="-I$OPENSSL_ROOT_DIR/include"
```

#### RocksDB Linking Issues

```bash
# Install RocksDB via Homebrew
brew install rocksdb

# Or build from source
cd src/external/rocksdb
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(sysctl -n hw.ncpu)
```

#### CMake Configuration Issues

```bash
# Clear CMake cache
rm -rf src/engine/build
rm -rf src/shared_modules/indexer_connector/build

# Reconfigure
cd src
make deps TARGET=server
make TARGET=server build
```

### Runtime Issues

#### Quickwit Connection Failed

1. Verify Quickwit is running:
   ```bash
   curl http://localhost:7280/health
   ```

2. Check Wazuh configuration:
   ```bash
   grep -A 10 "<indexer>" /var/ossec/etc/ossec.conf
   ```

3. Check Wazuh logs:
   ```bash
   tail -n 100 /var/ossec/logs/ossec.log | grep -i error
   ```

#### Index Not Found

Ensure the index exists:

```bash
curl http://localhost:7280/api/v1/indexes/wazuh-alerts
```

If not, create it as described in [Step 4](#step-4-setup-quickwit).

#### Performance Issues

1. Adjust Quickwit commit timeout in index config
2. Increase Quickwit resources
3. Monitor system resources:
   ```bash
   # macOS
   top -o cpu

   # Check disk I/O
   iostat -w 1
   ```

### macOS-Specific Issues

#### SIP (System Integrity Protection)

If you encounter permission issues:

1. Install to a user-writable location:
   ```bash
   ./scripts/build_wazuh_with_quickwit_macos.sh --prefix ~/wazuh-dev
   ```

2. Or temporarily disable SIP (not recommended for production)

#### Flat Namespace Issues

The build uses `DYLD_FORCE_FLAT_NAMESPACE=1` for macOS. If you encounter symbol conflicts:

```bash
# Check for conflicts
nm -g /var/ossec/bin/wazuh-analysisd | grep quickwit

# Rebuild with verbose output
make TARGET=server build V=1
```

## Architecture Details

### Quickwit Connector Components

```
src/shared_modules/indexer_connector/
├── include/
│   └── quickwitConnector.hpp          # Public interface
├── src/
│   ├── quickwitConnectorAsync.cpp     # Async HTTP client
│   └── quickwitConnectorAsyncImpl.hpp # Implementation details
└── CMakeLists.txt

src/engine/source/wiconnector/
├── include/wiconnector/
│   ├── connectorFactory.hpp           # Factory pattern for backend selection
│   └── wquickwitconnector.hpp         # Wazuh engine connector interface
├── src/
│   └── wquickwitconnector.cpp         # Implementation
└── CMakeLists.txt

framework/wazuh/quickwit/
├── __init__.py
├── client.py                          # Python REST API client
└── dashboard.py                       # Dashboard utilities
```

### Build Dependencies

The Quickwit connector depends on:

- **rocksdb**: Key-value storage
- **urlrequest** (HTTP client library): HTTP communication
- **simdjson**: Fast JSON parsing
- **keystore**: Credential management
- **OpenSSL**: HTTPS support

These are linked in `src/shared_modules/indexer_connector/CMakeLists.txt`:

```cmake
target_link_libraries(indexer_connector
    rocksdb
    urlrequest
    gcc_s
    wazuhext
    keystore
    simdjson
)
```

### Configuration Flow

1. **Config Parsing** (`src/config/indexer-config.c`):
   - Reads `<indexer>` section from `ossec.conf`
   - Validates `type` field (opensearch or quickwit)

2. **Factory Creation** (`connectorFactory.hpp`):
   - Instantiates appropriate connector based on type
   - Default: OpenSearch (backward compatible)

3. **Connector Initialization**:
   - Establishes connection pool
   - Validates index existence
   - Prepares for bulk indexing

4. **Event Flow**:
   - Wazuh engine generates events
   - Events formatted as NDJSON
   - Bulk published to Quickwit ingest API
   - Automatic commit based on index settings

## Additional Resources

- [Quickwit Integration Guide](./QUICKWIT_INTEGRATION.md) - Detailed integration documentation
- [Python SDK Documentation](./framework/wazuh/quickwit/README.md) - Python client usage
- [Wazuh Build Documentation](./src/Readme.md) - General build information
- [Quickwit Documentation](https://quickwit.io/docs) - Quickwit official docs
- [Wazuh Documentation](https://documentation.wazuh.com) - Wazuh official docs

## Contributing

When contributing to the Quickwit integration:

1. Follow the [development workflow](#development-workflow)
2. Run all quality checks: `python3 src/build.py -r shared_modules/indexer_connector`
3. Test on both macOS and Linux when possible
4. Update documentation as needed
5. Add unit tests for new functionality

## License

Copyright (C) 2015, Wazuh Inc.

This program is free software; you can redistribute it and/or modify it under the terms of GPLv2.
