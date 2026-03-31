#!/usr/bin/env python
# encoding=utf-8
"""
pull_snow_inventory.py - Alert Action for Full ServiceNow AI Inventory Pull

Pulls ALL records from the ServiceNow AI System (alm_ai_system_digital_asset)
and AI Model tables into the existing KV stores (gen_ai_app_asset_map and
gen_ai_model_asset_map).  This ensures the "Inventoried Not Detected" dashboard
panels reflect the complete ServiceNow inventory, not just items that were
first detected in Splunk logs.

Usage:
    Called as an alert action from a scheduled saved search.

Workflow:
    1. Read ServiceNow connection and asset discovery config
    2. Fetch ALL records from the configured AI System table (paginated)
    3. For each record, upsert into gen_ai_app_asset_map KV store
    4. Repeat for the AI Model table / gen_ai_model_asset_map
    5. Log summary counts

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import json
import time

app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
if lib_path not in sys.path:
    sys.path.insert(0, lib_path)

bin_path = os.path.dirname(os.path.abspath(__file__))
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)

from sync_snow_asset import (
    setup_logging,
    get_snow_config,
    get_asset_discovery_config,
    make_snow_request,
    determine_approval_status,
    derive_inventory_status,
)

import splunklib.client as client


logger = setup_logging('pull_snow_inventory')

PAGE_SIZE = 500


def fetch_all_snow_records(config, table_name, match_field, approval_field):
    """Fetch every record from a ServiceNow table using offset pagination.

    Returns a list of dicts (raw ServiceNow records).
    """
    fields = 'sys_id,{},name'.format(match_field)
    if approval_field and approval_field not in (match_field, 'name', 'sys_id'):
        fields += ',{}'.format(approval_field)

    all_records = []
    offset = 0

    while True:
        url = '/api/now/table/{}?sysparm_fields={}&sysparm_limit={}&sysparm_offset={}'.format(
            table_name, fields, PAGE_SIZE, offset)

        result = make_snow_request('GET', url, config=config)
        page = result.get('result', []) if result else []

        if not page:
            break

        all_records.extend(page)
        logger.info("Fetched {} records from {} (offset={}, page_size={})".format(
            len(page), table_name, offset, len(page)))

        if len(page) < PAGE_SIZE:
            break
        offset += PAGE_SIZE

    logger.info("Total records fetched from {}: {}".format(table_name, len(all_records)))
    return all_records


def build_kv_index(session_key, collection_name, key_field):
    """Load all existing KV store records into a dict keyed by the asset name.

    Returns {asset_name_lower: record_dict, ...}
    """
    try:
        service = client.connect(token=session_key, owner='nobody', app='TA-gen_ai_cim')
        collection = service.kvstore[collection_name]
        records = collection.data.query()
        index = {}
        for rec in records:
            name = rec.get(key_field, '').lower().strip()
            if name:
                index[name] = rec
        logger.info("Loaded {} existing KV store records from {}".format(len(index), collection_name))
        return index
    except Exception as e:
        logger.error("Failed to load KV store index ({}): {}".format(collection_name, str(e)))
        return {}


def upsert_kv_record(session_key, collection_name, key_field, asset_name,
                     sys_id, approval_status, username, existing_record=None):
    """Insert or update a single KV store record."""
    try:
        service = client.connect(token=session_key, owner='nobody', app='TA-gen_ai_cim')
        collection = service.kvstore[collection_name]
        now_epoch = int(time.time())
        inventory_status = derive_inventory_status('found', approval_status)

        if existing_record:
            existing_key = existing_record.get('_key')
            old_approval = existing_record.get('approval_status', '')
            old_sys_id = existing_record.get('service_now_sys_id', '')

            if old_approval == approval_status and old_sys_id == sys_id and existing_record.get('sync_status') == 'found':
                return 'unchanged'

            update_data = dict(existing_record)
            update_data.pop('_key', None)
            update_data['service_now_sys_id'] = sys_id
            update_data['sync_status'] = 'found'
            update_data['approval_status'] = approval_status
            update_data['inventory_status'] = inventory_status
            update_data['updated_at'] = now_epoch
            update_data['updated_by'] = username
            collection.data.update(existing_key, json.dumps(update_data))
            return 'updated'
        else:
            record = {
                key_field: asset_name,
                'service_now_sys_id': sys_id,
                'sync_status': 'found',
                'approval_status': approval_status,
                'inventory_status': inventory_status,
                'created_at': now_epoch,
                'updated_at': now_epoch,
                'created_by': username,
            }
            collection.data.insert(json.dumps(record))
            return 'inserted'

    except Exception as e:
        logger.error("KV store upsert failed ({}, {}): {}".format(
            collection_name, asset_name, str(e)))
        return 'error'


def pull_table_inventory(session_key, snow_config, table_name, match_field,
                         approval_field, approved_values_list, collection_name,
                         key_field, label):
    """Pull all records from one ServiceNow table into the corresponding KV store."""
    logger.info("=== Starting {} inventory pull from {} ===".format(label, table_name))

    snow_records = fetch_all_snow_records(snow_config, table_name, match_field, approval_field)
    if not snow_records:
        logger.info("No records returned from {}".format(table_name))
        return {'inserted': 0, 'updated': 0, 'unchanged': 0, 'errors': 0}

    kv_index = build_kv_index(session_key, collection_name, key_field)
    username = snow_config.get('username', 'pull_snow_inventory')
    counters = {'inserted': 0, 'updated': 0, 'unchanged': 0, 'errors': 0}

    for record in snow_records:
        asset_name = (record.get(match_field, '') or record.get('name', '')).strip()
        if not asset_name:
            logger.warning("Skipping ServiceNow record with empty {}: sys_id={}".format(
                match_field, record.get('sys_id', '?')))
            continue

        sys_id = record.get('sys_id', '')
        approval = determine_approval_status(record, approval_field, approved_values_list)
        existing = kv_index.get(asset_name.lower())

        result = upsert_kv_record(
            session_key, collection_name, key_field, asset_name,
            sys_id, approval, username, existing_record=existing)

        counters[result] = counters.get(result, 0) + 1

        if result == 'inserted':
            logger.info("Inserted {} '{}' (sys_id={}, approval={})".format(
                label, asset_name, sys_id, approval))
        elif result == 'updated':
            logger.info("Updated {} '{}' (sys_id={}, approval={})".format(
                label, asset_name, sys_id, approval))

    logger.info("=== {} inventory pull complete: inserted={}, updated={}, unchanged={}, errors={} ===".format(
        label, counters['inserted'], counters['updated'], counters['unchanged'], counters['errors']))
    return counters


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        try:
            payload_str = sys.stdin.read()
            payload = json.loads(payload_str)
        except Exception as e:
            logger.error("Failed to parse alert action payload: {}".format(str(e)))
            sys.exit(1)
    else:
        try:
            payload_str = sys.stdin.read()
            if payload_str:
                payload = json.loads(payload_str)
            else:
                logger.error("No payload provided")
                sys.exit(1)
        except Exception as e:
            logger.error("Failed to parse input: {}".format(str(e)))
            sys.exit(1)

    logger.info("Pull Snow Inventory started - payload keys: {}".format(list(payload.keys())))

    session_key = payload.get('session_key')
    if not session_key:
        logger.error("No session_key in payload")
        sys.exit(1)

    snow_config = get_snow_config(session_key)
    if not snow_config.get('configured'):
        logger.error("ServiceNow not configured: {}".format(snow_config.get('error')))
        sys.exit(1)

    discovery_config = get_asset_discovery_config(session_key)

    total_errors = 0

    # --- AI System table ---
    system_table = discovery_config.get('ai_system_table', 'alm_ai_system_digital_asset')
    if system_table:
        try:
            result = pull_table_inventory(
                session_key, snow_config,
                table_name=system_table,
                match_field=discovery_config.get('ai_system_match_field', 'display_name'),
                approval_field=discovery_config.get('ai_system_approval_field', 'approval'),
                approved_values_list=discovery_config.get('ai_system_approved_values_list', ['approved']),
                collection_name='gen_ai_app_asset_map',
                key_field='gen_ai_app_name',
                label='AI System',
            )
            total_errors += result.get('errors', 0)
        except Exception as e:
            logger.error("AI System inventory pull failed: {}".format(str(e)))
            total_errors += 1
    else:
        logger.warning("AI System table not configured, skipping")

    # --- AI Model table ---
    model_table = discovery_config.get('ai_model_table', '')
    if model_table:
        try:
            result = pull_table_inventory(
                session_key, snow_config,
                table_name=model_table,
                match_field=discovery_config.get('ai_model_match_field', 'display_name'),
                approval_field=discovery_config.get('ai_model_approval_field', 'approval'),
                approved_values_list=discovery_config.get('ai_model_approved_values_list', ['approved']),
                collection_name='gen_ai_model_asset_map',
                key_field='gen_ai_response_model',
                label='AI Model',
            )
            total_errors += result.get('errors', 0)
        except Exception as e:
            logger.error("AI Model inventory pull failed: {}".format(str(e)))
            total_errors += 1
    else:
        logger.warning("AI Model table not configured, skipping")

    logger.info("Pull Snow Inventory complete (total errors={})".format(total_errors))

    if total_errors > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
