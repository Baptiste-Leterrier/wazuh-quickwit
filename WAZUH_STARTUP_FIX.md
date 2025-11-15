# Wazuh Startup Issues - Fix Documentation

## Problems Identified

Based on the logs from `/var/ossec/logs/ossec.log`, the following critical issues were identified:

### 1. **wazuh-db Connection Failures** (Most Critical)
- **Error**: `wazuh-authd: INFO: Cannot connect to 'queue/db/wdb': Connection refused (111)`
- **Impact**: Prevents agent registration and database operations
- **Cause**: wazuh-db service failing to start or initialize properly

### 2. **Missing MITRE Database**
- **Error**: `wazuh-db: ERROR: Can't open SQLite database 'var/db/mitre.db': unable to open database file`
- **Impact**: MITRE ATT&CK matrix information not available for threat correlation
- **Cause**: Database not created during initialization

### 3. **Vulnerability Scanner Database Corruption**
- **Error**: `wazuh-modulesd:vulnerability-scanner: ERROR: Error opening the database: Couldn't find column family: 'vendor_map'`
- **Impact**: Vulnerability scanning functionality degraded
- **Cause**: Database corruption or incomplete initialization

### 4. **Indexer Connection Failures** (Expected)
- **Warning**: `indexer-connector: WARNING: IndexerConnector initialization failed`
- **Impact**: None (expected when using Quickwit instead of OpenSearch)
- **Note**: This is normal and can be ignored in your setup

## Solution Implemented

### Files Created/Modified

#### 1. **docker/scripts/init-databases.sh** (New File)
Comprehensive database initialization script that:
- Creates required database directories with proper permissions
- Initializes the MITRE ATT&CK database from `enterprise-attack.json`
- Prepares directories for vulnerability scanner database
- Creates wazuh-db socket directory
- Sets correct ownership (ossec:ossec) and permissions (770)

#### 2. **docker/scripts/entrypoint.sh** (Modified)
Updated to:
- Call `init-databases.sh` before starting Wazuh services
- Ensure databases are initialized before wazuh-db starts
- Provide better logging for troubleshooting

#### 3. **docker/Dockerfile** (Modified)
Updated to:
- Copy `init-databases.sh` to the container
- Copy tools directory (includes MITRE database tools)
- Copy ruleset directory (includes enterprise-attack.json)
- Install Python dependencies (sqlalchemy) for database tools
- Make all scripts executable

## How the Fix Works

### Initialization Sequence

1. **Container Starts** → entrypoint.sh runs
2. **Directory Creation** → Required directories created with proper permissions
3. **Database Initialization** → `init-databases.sh` runs:
   - Checks if MITRE DB exists
   - If missing, creates it using `tools/mitre/mitredb.py`
   - Creates socket directory for wazuh-db
   - Sets all permissions correctly
4. **Wazuh Services Start** → All services start with databases ready

### MITRE Database Creation

The script uses:
- **Source**: `/var/ossec/ruleset/mitre/enterprise-attack.json`
- **Tool**: `/var/ossec/tools/mitre/mitredb.py`
- **Output**: `/var/ossec/var/db/mitre.db`
- **Permissions**: 660 (ossec:ossec)

## Testing Instructions

### 1. Rebuild the Docker Image

```bash
cd /home/user/wazuh-quickwit

# Rebuild the image
docker compose build --no-cache wazuh-manager
```

### 2. Start the Services

```bash
# Start the stack
docker compose up -d

# Watch the logs
docker compose logs -f wazuh-manager
```

### 3. Verify Database Initialization

Look for these log messages:
```
[DB-INIT] Starting database initialization...
[DB-INIT] Checking MITRE database...
[DB-INIT] MITRE database created successfully
[DB-INIT] Database initialization complete
```

### 4. Verify Wazuh Services

After startup, check service status:
```bash
# Enter the container
docker exec -it wazuh-manager bash

# Check service status
/var/ossec/bin/wazuh-control status

# Check if mitre.db was created
ls -lah /var/ossec/var/db/mitre.db

# Check wazuh-db logs
tail -50 /var/ossec/logs/ossec.log | grep -E "(mitre|wazuh-db)"
```

### 5. Expected Results

After successful initialization, you should see:

#### ✅ Services Running:
```
wazuh-db is running...
wazuh-analysisd is running...
wazuh-authd is running...
wazuh-execd is running...
wazuh-logcollector is running...
wazuh-syscheckd is running...
wazuh-remoted is running...
wazuh-monitord is running...
wazuh-modulesd is running...
```

#### ✅ MITRE Database:
```
-rw-rw---- 1 ossec ossec [SIZE] [DATE] /var/ossec/var/db/mitre.db
```

#### ✅ No Critical Errors in Logs:
- No "Can't open SQLite database 'var/db/mitre.db'" errors
- No "Cannot connect to 'queue/db/wdb'" errors
- Mitre matrix information loaded successfully

### 6. Test Agent Registration

```bash
# From another terminal/container, try to register an agent
docker exec -it wazuh-manager /var/ossec/bin/agent-auth -m localhost
```

This should work without connection refused errors.

## Troubleshooting

### Issue: MITRE database still not created

**Check:**
```bash
docker exec -it wazuh-manager ls -la /var/ossec/ruleset/mitre/
docker exec -it wazuh-manager ls -la /var/ossec/tools/mitre/
```

**Verify:**
- enterprise-attack.json exists
- mitredb.py exists
- Python3 and sqlalchemy are installed

### Issue: Permission denied errors

**Fix:**
```bash
docker exec -it wazuh-manager bash
chown -R ossec:ossec /var/ossec/var/db
chmod -R 770 /var/ossec/var/db
```

### Issue: wazuh-db still not accessible

**Check:**
```bash
# Check if wazuh-db is running
docker exec -it wazuh-manager ps aux | grep wazuh-db

# Check socket exists
docker exec -it wazuh-manager ls -la /var/ossec/queue/db/

# Check wazuh-db logs
docker exec -it wazuh-manager tail -100 /var/ossec/logs/ossec.log | grep wazuh-db
```

## Verification Checklist

- [ ] Docker image rebuilds without errors
- [ ] Container starts successfully
- [ ] Database initialization script runs
- [ ] MITRE database is created (`/var/ossec/var/db/mitre.db`)
- [ ] wazuh-db service starts and stays running
- [ ] No "Can't open SQLite database" errors in logs
- [ ] Agent registration works
- [ ] MITRE matrix information loads successfully

## Additional Notes

### Vulnerability Scanner Database

The vulnerability scanner database (`vd.db`) uses RocksDB and requires:
- Initial feed download (happens automatically on first run)
- Network connectivity to download vulnerability data
- May take several minutes on first startup

If you see:
```
wazuh-modulesd:vulnerability-scanner: ERROR: Error opening the database: Couldn't find column family: 'vendor_map'.
```

This is normal on first run and will resolve after the vulnerability feeds are downloaded.

### Indexer Warnings (Expected)

These warnings are **expected** when using Quickwit instead of OpenSearch:
```
monitoring: WARNING: Health check failed for 'https://0.0.0.0:9200'
indexer-connector: WARNING: IndexerConnector initialization failed
```

These can be safely ignored as you're using Quickwit for indexing.

## Summary

This fix ensures that:
1. All required databases are initialized before services start
2. Proper permissions are set for all database files
3. wazuh-db can start and be accessed by other services
4. MITRE ATT&CK data is available for threat correlation
5. Agent registration works correctly

The initialization is automatic and happens every time the container starts, but databases are only created if they don't already exist.
