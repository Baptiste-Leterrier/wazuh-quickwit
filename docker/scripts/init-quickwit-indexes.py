#!/usr/bin/env python3
"""
Quickwit Index Initialization Script
Copyright (C) 2015, Wazuh Inc.

This script creates Quickwit indexes from OpenSearch templates for wazuh-states indexes.
It converts OpenSearch field mappings to Quickwit format and creates the indexes via the Quickwit REST API.
"""

import json
import os
import sys
import time
import requests
from pathlib import Path
from typing import Dict, Any, List


# Color output
class Colors:
    BLUE = '\033[0;34m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    RED = '\033[0;31m'
    NC = '\033[0m'


def log_info(msg: str):
    print(f"{Colors.BLUE}[QW-INIT]{Colors.NC} {msg}")


def log_success(msg: str):
    print(f"{Colors.GREEN}[QW-INIT]{Colors.NC} {msg}")


def log_warning(msg: str):
    print(f"{Colors.YELLOW}[QW-INIT]{Colors.NC} {msg}")


def log_error(msg: str):
    print(f"{Colors.RED}[QW-INIT]{Colors.NC} {msg}")


def opensearch_to_quickwit_type(os_type: str, field_name: str = "") -> str:
    """Convert OpenSearch field type to Quickwit field type."""
    type_mapping = {
        'keyword': 'text',
        'text': 'text',
        'long': 'i64',
        'integer': 'i64',
        'short': 'i64',
        'byte': 'i64',
        'double': 'f64',
        'float': 'f64',
        'boolean': 'bool',
        'date': 'datetime',
        'ip': 'ip',
        'object': 'object',
    }
    return type_mapping.get(os_type, 'text')


def convert_field_mapping(field_name: str, field_config: Dict[str, Any], parent_path: str = "") -> Dict[str, Any]:
    """Convert an OpenSearch field mapping to Quickwit format."""
    full_path = f"{parent_path}.{field_name}" if parent_path else field_name

    # Handle nested properties (object type)
    if 'properties' in field_config:
        sub_mappings = []
        for sub_field_name, sub_field_config in field_config['properties'].items():
            sub_mappings.append(convert_field_mapping(sub_field_name, sub_field_config, full_path))

        return {
            'name': field_name,
            'type': 'object',
            'field_mappings': sub_mappings
        }

    # Get the field type
    os_type = field_config.get('type', 'keyword')
    qw_type = opensearch_to_quickwit_type(os_type, full_path)

    # Build Quickwit field config
    qw_field = {
        'name': field_name,
        'type': qw_type,
    }

    # Add tokenizer for text fields
    if qw_type == 'text':
        # OpenSearch 'keyword' type should use 'raw' tokenizer in Quickwit
        if os_type == 'keyword':
            qw_field['tokenizer'] = 'raw'
        else:
            qw_field['tokenizer'] = 'default'

    # Add fast field for frequently queried fields
    if qw_type in ['text', 'i64', 'f64', 'ip', 'datetime']:
        qw_field['fast'] = True

    # Add indexed flag for searchable fields
    qw_field['indexed'] = True

    # Handle datetime input formats
    if qw_type == 'datetime':
        qw_field['input_formats'] = ['rfc3339', 'unix_timestamp']

    return qw_field


def convert_template_to_quickwit(template_data: Dict[str, Any], index_id: str) -> Dict[str, Any]:
    """Convert an OpenSearch index template to Quickwit index config."""

    # Extract the mappings
    mappings = template_data.get('template', {}).get('mappings', {})
    properties = mappings.get('properties', {})

    # Convert field mappings
    field_mappings = []
    for field_name, field_config in properties.items():
        field_mappings.append(convert_field_mapping(field_name, field_config))

    # Build Quickwit index config
    quickwit_config = {
        'version': '0.8',
        'index_id': index_id,
        'doc_mapping': {
            'field_mappings': field_mappings,
            'mode': 'dynamic',  # Allow fields not explicitly defined
        },
        'indexing_settings': {
            'commit_timeout_secs': 10,
            'resources': {
                'heap_size': '500MB'
            }
        },
        'search_settings': {
            'default_search_fields': []
        }
    }

    # Add timestamp field if it doesn't exist
    # Use a common timestamp field for state indexes
    has_timestamp = any(f['name'] in ['timestamp', '@timestamp'] for f in field_mappings)
    if not has_timestamp:
        # Add a timestamp field for the index
        field_mappings.insert(0, {
            'name': 'timestamp',
            'type': 'datetime',
            'input_formats': ['rfc3339', 'unix_timestamp'],
            'fast': True,
            'indexed': True
        })
        quickwit_config['doc_mapping']['timestamp_field'] = 'timestamp'

    return quickwit_config


def create_quickwit_index(quickwit_url: str, index_config: Dict[str, Any]) -> bool:
    """Create a Quickwit index via the REST API."""
    index_id = index_config['index_id']

    try:
        # Check if index already exists
        check_url = f"{quickwit_url}/api/v1/indexes/{index_id}"
        response = requests.get(check_url, timeout=5)

        if response.status_code == 200:
            log_info(f"Index '{index_id}' already exists, skipping creation")
            return True

        # Create the index
        create_url = f"{quickwit_url}/api/v1/indexes"
        response = requests.post(create_url, json=index_config, timeout=10)

        if response.status_code in [200, 201]:
            log_success(f"Created index '{index_id}'")
            return True
        else:
            log_error(f"Failed to create index '{index_id}': HTTP {response.status_code}")
            log_error(f"Response: {response.text}")
            return False

    except requests.exceptions.RequestException as e:
        log_error(f"Error creating index '{index_id}': {e}")
        return False


def wait_for_quickwit(quickwit_url: str, max_retries: int = 30, retry_interval: int = 2) -> bool:
    """Wait for Quickwit to be ready."""
    log_info(f"Waiting for Quickwit at {quickwit_url}...")

    for attempt in range(max_retries):
        try:
            response = requests.get(f"{quickwit_url}/api/v1/cluster", timeout=2)
            if response.status_code == 200:
                log_success("Quickwit is ready!")
                return True
        except requests.exceptions.RequestException:
            pass

        if attempt < max_retries - 1:
            log_info(f"Quickwit not ready yet, retrying in {retry_interval}s... ({attempt + 1}/{max_retries})")
            time.sleep(retry_interval)

    log_warning(f"Quickwit not responding after {max_retries} attempts")
    return False


def main():
    # Configuration
    quickwit_host = os.environ.get('QUICKWIT_HOST', '172.25.0.2')
    quickwit_port = os.environ.get('QUICKWIT_PORT', '7280')
    quickwit_url = f"http://{quickwit_host}:{quickwit_port}"

    # Get the agent ID suffix from environment or generate one
    # In the logs, the suffix is like '73a4178f5d26' which appears to be a cluster/node ID
    agent_suffix = os.environ.get('WAZUH_AGENT_ID', 'default')

    log_info("=== Quickwit Index Initialization ===")
    log_info(f"Quickwit URL: {quickwit_url}")

    # Wait for Quickwit to be ready
    if not wait_for_quickwit(quickwit_url):
        log_error("Quickwit is not available, skipping index creation")
        return 1

    # Define the templates to process
    template_dir = Path("/var/ossec/wazuh_modules")

    # Inventory templates
    inventory_templates = [
        "inventory_harvester/indexer/template/wazuh-states-inventory-packages.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-processes.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-system.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-hardware.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-interfaces.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-ports.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-protocols.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-groups.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-networks.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-users.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-services.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-hotfixes.json",
        "inventory_harvester/indexer/template/wazuh-states-inventory-browser-extensions.json",
    ]

    # FIM templates
    fim_templates = [
        "inventory_harvester/indexer/template/wazuh-states-fim-files.json",
        "inventory_harvester/indexer/template/wazuh-states-fim-registries.json",
    ]

    # Vulnerability template
    vulnerability_templates = [
        "vulnerability_scanner/indexer/template/index-template.json",
    ]

    all_templates = inventory_templates + fim_templates + vulnerability_templates

    success_count = 0
    failed_count = 0
    skipped_count = 0

    for template_path in all_templates:
        full_path = template_dir / template_path

        if not full_path.exists():
            log_warning(f"Template not found: {full_path}")
            skipped_count += 1
            continue

        log_info(f"Processing template: {template_path}")

        try:
            # Load the template
            with open(full_path, 'r') as f:
                template_data = json.load(f)

            # Extract the index pattern to determine index_id
            index_pattern = template_data.get('index_patterns', ['unknown'])[0]
            # Remove trailing * and wildcards
            index_id = index_pattern.rstrip('*-').rstrip('*')

            # For vulnerability template, use the proper index name
            if 'vulnerability' in str(template_path):
                index_id = 'wazuh-states-vulnerabilities'

            # Append agent suffix to create unique index per agent/cluster
            index_id_with_suffix = f"{index_id}-{agent_suffix}"

            # Convert to Quickwit format
            quickwit_config = convert_template_to_quickwit(template_data, index_id_with_suffix)

            # Create the index
            if create_quickwit_index(quickwit_url, quickwit_config):
                success_count += 1
            else:
                failed_count += 1

        except Exception as e:
            log_error(f"Error processing template {template_path}: {e}")
            import traceback
            traceback.print_exc()
            failed_count += 1

    log_info("=== Index Creation Summary ===")
    log_success(f"Successfully created/verified: {success_count} indexes")
    if skipped_count > 0:
        log_warning(f"Skipped: {skipped_count} templates (not found)")
    if failed_count > 0:
        log_error(f"Failed: {failed_count} indexes")

    # Return success if at least some indexes were created
    return 0 if failed_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
