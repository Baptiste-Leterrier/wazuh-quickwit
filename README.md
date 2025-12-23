
# Wazuh–Quickwit Integration (Proof of Concept)

## Disclaimer

This project is an independent experiment and is **not affiliated with Wazuh Inc. or Quickwit Inc.**

This repository contains an experimental C++ implementation enabling **Wazuh** to natively index security log data directly into **Quickwit**.

Read the full story behind this implementation here:  
*(link placeholder)*

---

## ⚠️ Important Disclaimers

- **Proof of Concept Only**  
  This is strictly a PoC. Do **not** use this in production environments without extensive testing and modification.

- **Experimental Code**  
  Significant portions of this codebase were developed with AI assistance (“vibe coding”) and may not adhere to strict C++ best practices or memory-safety standards required for critical security infrastructure.

- **No GUI Support**  
  This integration replaces the OpenSearch backend. As a result, the standard Wazuh Dashboard (Kibana fork) will not function, since it relies on OpenSearch-specific APIs.

- **Untested at Scale**  
  Tested only in a small lab environment. Performance under high throughput (e.g., 10k+ EPS), network latency, or large cluster configurations is unknown.

- **Data Transformation**  
  To satisfy Quickwit’s stricter schema requirements, some data types (notably arrays and inconsistent field types) are aggressively normalized (e.g., serialized to JSON strings) during ingestion.

---

## Overview

The goal of this project is to explore using **Quickwit** as a high-efficiency, object-storage-native backend for Wazuh logs.

This architecture targets **Write-Once-Read-Many (WORM)** use cases such as long-term compliance archiving or immutable evidence preservation, where the mutability and resource overhead of OpenSearch are unnecessary.

---

## Key Features

- **Native C++ Integration**  
  Modifies the Wazuh `indexer_connector` to speak Quickwit’s NDJSON ingestion protocol directly, removing the need for intermediate proxies.

- **Dynamic Index Creation**  
  Automatically creates missing indices in Quickwit based on incoming log data.

- **Schema Adaptation**  
  Includes defensive logic to normalize Wazuh’s flexible JSON output into Quickwit’s stricter type system.

- **S3-Compatible Storage**  
  Leverages Quickwit’s native ability to store indices directly on S3-compatible object storage.

---

## Architecture

This modification introduces a new backend type in the Wazuh Analysis Engine (`wazuh-analysisd`).

### Flow

1. **Detection**  
   The connector detects `type="quickwit"` in the configuration.

2. **Translation**  
   Wazuh’s internal JSON alerts are converted to NDJSON (Newline Delimited JSON) batches.

3. **Normalization**
   - Timestamps are standardized to RFC3339.
   - Nested arrays (e.g., `process.args`) are serialized to strings to prevent schema conflicts.

4. **Ingestion**  
   Batches are POSTed to the Quickwit `/api/v1/_bulk` endpoint.

---

## Configuration

To enable this integration, modify the `<indexer>` block in your `ossec.conf`.

> **Note:** This requires the modified Wazuh binary built from this repository.

```xml
<ossec_config>
  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>http://quickwit-server:7280</host>
    </hosts>
    <type>quickwit</type>
    <ssl>
      <agent_auth>no</agent_auth>
    </ssl>
  </indexer>
</ossec_config>
````

---

## Known Issues & Limitations

* **Error Handling**
  Retry logic is minimal. In the event of a Quickwit node failure, buffers may overflow or data may be lost more easily than with the standard OpenSearch connector.

* **Mapping Rigidity**
  While dynamic mapping is enabled, radical schema changes may still cause ingestion errors once Quickwit has locked a field’s type.

* **Authentication**
  Basic HTTP authentication support is minimal and largely untested.

---

## Building

This repository follows the standard Wazuh build process. Ensure all Wazuh development dependencies are installed.

---

## License

**Don’t Care**

---

## Disclaimer again

This project is an independent experiment and is **not affiliated with Wazuh Inc. or Quickwit Inc.**
