# Dockerfile for Wazuh with Quickwit Support
# Copyright (C) 2015, Wazuh Inc.
# Multi-stage build for optimized image size

# Build stage
FROM ubuntu:24.04 AS builder

# Build arguments
ARG WAZUH_VERSION=4.9.0
ARG BUILD_JOBS=2
ARG BUILD_DEBUG=0
ARG BUILD_TARGET=server

# Set environment variables for build
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    BUILD_JOBS=${BUILD_JOBS} \
    BUILD_DEBUG=${BUILD_DEBUG}

# Install ALL build dependencies (comprehensive list)
RUN apt-get update && apt-get install -y \
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
    python3-pip \
    libjemalloc-dev \
    nlohmann-json3-dev \
    libcjson-dev \
    libsystemd-dev \
    libyaml-dev \
    libffi-dev \
    autoconf \
    automake \
    libtool \
    ca-certificates \
    libcurl4-openssl-dev \
    libreadline-dev \
    libpam0g-dev \
    libdb-dev \
    libaudit-dev \
    libgtest-dev \
    libgmock-dev \
    libboost-all-dev \
    uuid-dev \
    libpopt-dev \
    rpm \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy only necessary files for build
COPY src/ /build/src/
COPY etc/ /build/etc/
COPY framework/ /build/framework/
COPY api/ /build/api/
COPY VERSION.json /build/
COPY install.sh /build/
COPY gen_ossec.sh /build/
COPY add_localfiles.sh /build/

# Make scripts executable
RUN chmod +x /build/*.sh

# Build Wazuh with Quickwit support
RUN set -ex && \
    cd /build/src && \
    echo "========================================" && \
    echo "Downloading external dependencies..." && \
    echo "========================================" && \
    make deps TARGET=${BUILD_TARGET} || { \
        echo "ERROR: Failed to download dependencies"; \
        echo "This usually means network issues or missing tools"; \
        exit 1; \
    } && \
    echo "" && \
    echo "========================================" && \
    echo "Building Wazuh (this takes 20-60 min)..." && \
    echo "Using ${BUILD_JOBS} parallel jobs" && \
    echo "========================================" && \
    # Reduce parallel jobs to avoid memory issues
    make TARGET=${BUILD_TARGET} DEBUG=${BUILD_DEBUG} build -j${BUILD_JOBS} || { \
        echo "ERROR: Build failed"; \
        echo "Check if you have enough RAM (need 4GB+)"; \
        echo "Try reducing BUILD_JOBS in .env file"; \
        exit 1; \
    } && \
    echo "" && \
    echo "========================================" && \
    echo "Installing Wazuh..." && \
    echo "========================================" && \
    cd /build && \
    mkdir -p /var/ossec && \
    export USER_LANGUAGE="en" && \
    export USER_NO_STOP="y" && \
    export USER_INSTALL_TYPE="${BUILD_TARGET}" && \
    export USER_DIR="/var/ossec" && \
    export USER_DELETE_DIR="y" && \
    export USER_CLEANINSTALL="y" && \
    export USER_BINARYINSTALL="yes" && \
    export USER_AGENT_SERVER_IP="MANAGER_IP" && \
    export USER_ENABLE_SYSCHECK="y" && \
    export USER_ENABLE_ROOTCHECK="y" && \
    export USER_ENABLE_ACTIVE_RESPONSE="y" && \
    export USER_CA_STORE="n" && \
    ./install.sh || { \
        echo "ERROR: Installation failed"; \
        cat /var/ossec/logs/ossec.log 2>/dev/null || true; \
        exit 1; \
    } && \
    echo "" && \
    echo "========================================" && \
    echo "Installing Python environment..." && \
    echo "========================================" && \
    cd /build/src && \
    make install_python INSTALLDIR=/var/ossec || { \
        echo "ERROR: Python installation failed"; \
        exit 1; \
    } && \
    echo "" && \
    echo "========================================" && \
    echo "Installing Wazuh Framework..." && \
    echo "========================================" && \
    make install_framework INSTALLDIR=/var/ossec WAZUH_GROUP=wazuh || { \
        echo "ERROR: Framework installation failed"; \
        exit 1; \
    } && \
    echo "" && \
    echo "========================================" && \
    echo "Installing Wazuh API..." && \
    echo "========================================" && \
    cd /build/api && \
    make install INSTALLDIR=/var/ossec WAZUH_GROUP=wazuh || { \
        echo "ERROR: API installation failed"; \
        exit 1; \
    } && \
    echo "" && \
    echo "========================================" && \
    echo "Build completed successfully!" && \
    echo "========================================"

# Runtime stage
FROM ubuntu:24.04

# Runtime arguments
ARG WAZUH_VERSION=4.9.0

# Labels
LABEL maintainer="Wazuh Inc." \
      version="${WAZUH_VERSION}" \
      description="Wazuh Manager with Quickwit integration support"

# Set environment variables
ENV WAZUH_HOME=/var/ossec \
    WAZUH_USER=wazuh \
    WAZUH_GROUP=wazuh \
    DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    QUICKWIT_HOST=quickwit-server \
    QUICKWIT_PORT=7280 \
    QUICKWIT_INDEX=wazuh-alerts

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    gnupg \
    libc6 \
    libgcc-s1 \
    libssl3 \
    libsqlite3-0 \
    libarchive13 \
    libpcre2-8-0 \
    zlib1g \
    libbz2-1.0 \
    liblzma5 \
    python3 \
    python3-pip \
    libjemalloc2 \
    libcjson1 \
    libsystemd0 \
    libyaml-0-2 \
    libffi8 \
    procps \
    net-tools \
    iproute2 \
    ca-certificates \
    libcurl4 \
    libpam0g \
    libdb5.3 \
    libaudit1 \
    uuid-runtime \
    libpopt0 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --no-cache-dir requests 2>/dev/null || \
    pip3 install --no-cache-dir --break-system-packages requests

# Copy Wazuh installation from builder
COPY --from=builder /var/ossec /var/ossec

# Copy framework (Python SDK)
COPY --from=builder /build/framework /var/ossec/framework

# Create Wazuh user and groups if they don't exist
# Note: Both ossec and wazuh groups are needed because the build stage
# installs framework/API with WAZUH_GROUP=wazuh
RUN groupadd -r ossec 2>/dev/null || true && \
    groupadd -r wazuh 2>/dev/null || true && \
    useradd -r -g ossec -G wazuh -d /var/ossec -s /sbin/nologin ossec 2>/dev/null || true

RUN useradd -r -g wazuh -G wazuh -d /var/ossec -s /sbin/nologin wazuh 2>/dev/null || true
RUN getent passwd wazuh
RUN getent group wazuh
    

# Create necessary directories
RUN mkdir -p \
    /var/ossec/logs \
    /var/ossec/etc \
    /var/ossec/queue/alerts \
    /var/ossec/queue/rids \
    /var/ossec/queue/fts \
    /var/ossec/queue/syscheck \
    /var/ossec/queue/rootcheck \
    /var/ossec/queue/diff \
    /var/ossec/queue/fim/db \
    /var/ossec/stats \
    /var/ossec/tmp \
    /var/ossec/var/run

# Set proper permissions
# Files are owned by ossec:ossec, but ossec user is also member of wazuh group
RUN chown -R ossec:ossec /var/ossec && \
    chmod -R 750 /var/ossec/logs \
                  /var/ossec/queue \
                  /var/ossec/stats \
                  /var/ossec/tmp \
                  /var/ossec/var && \
    chmod +x /var/ossec/bin/* 2>/dev/null || true && \
    # Ensure API and framework directories have proper group access
    find /var/ossec/api -type d -exec chmod g+rx {} \; 2>/dev/null || true && \
    find /var/ossec/framework -type d -exec chmod g+rx {} \; 2>/dev/null || true

# Copy entrypoint and healthcheck scripts
COPY docker/scripts/entrypoint.sh /usr/local/bin/
COPY docker/scripts/healthcheck.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh

# Expose ports
EXPOSE 55000 1514/tcp 1514/udp 1515 1516

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh

# Set working directory
WORKDIR /var/ossec

# Volume for persistent data
VOLUME ["/var/ossec/logs", "/var/ossec/etc", "/var/ossec/queue", "/var/ossec/stats"]

# Entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
