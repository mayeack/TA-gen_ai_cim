#!/usr/bin/env python
# encoding=utf-8
"""
sync_snow_asset.py - Alert Action for ServiceNow AI Asset Sync

This script syncs gen_ai.app.name (AI System) and gen_ai.response.model (AI Model)
values to their respective ServiceNow tables. It queries ServiceNow to check if
records exist, stores sys_id mappings in KV stores, and fetches approval status.

Usage:
    Called as an alert action from scheduled saved searches that identify
    gen_ai.app.name or gen_ai.response.model values not yet mapped in KV stores.

Workflow:
    1. Receive asset name from alert action payload (app_name or model_name)
    2. Read asset discovery config (table, match field, approval field, approved values)
    3. Check KV store for existing mapping (defensive check)
    4. Query ServiceNow for matching record and approval status
    5. If found: store sys_id with sync_status="found" and approval_status
    6. If not found: store with sync_status="not_found" (no record creation)

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import json
import time
import ssl
import csv
import gzip

# Add Splunk SDK paths - use lib directory in this app
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
if lib_path not in sys.path:
    sys.path.insert(0, lib_path)

# Handle Python 2/3 compatibility for Splunk versions
try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlencode, quote
except ImportError:
    from urllib2 import Request, urlopen, HTTPError, URLError
    from urllib import urlencode, quote

import splunklib.client as client


def setup_logging():
    """Setup logging for the alert action"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
        filename=os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk'),
                             'var', 'log', 'splunk', 'sync_snow_asset.log'),
        filemode='a'
    )
    return logging.getLogger('sync_snow_asset')


logger = setup_logging()


def get_snow_config(session_key):
    """Retrieve ServiceNow configuration from account configuration.
    
    Reads from ta_gen_ai_cim_account.conf and retrieves passwords
    from Splunk's secure storage/passwords.
    """
    try:
        service = client.connect(
            token=session_key,
            owner='nobody',
            app='TA-gen_ai_cim'
        )
        
        # Get account configuration from ta_gen_ai_cim_account.conf
        account_conf = None
        account_name = None
        
        try:
            accounts = service.confs['ta_gen_ai_cim_account']
            for stanza in accounts:
                # Skip default, asset_discovery config, and internal stanzas
                if stanza.name in ('default', 'asset_discovery') or stanza.name.startswith('_'):
                    continue
                account_conf = stanza
                account_name = stanza.name
                logger.info("Found ServiceNow account: {}".format(account_name))
                break
        except KeyError:
            logger.error("Config file ta_gen_ai_cim_account.conf not found")
        except Exception as e:
            logger.error("Error reading account config: {}".format(str(e)))
        
        if account_conf is None:
            return {
                'configured': False,
                'error': 'No ServiceNow account configured. Go to Configuration page to add an account.'
            }
        
        # Extract configuration
        url = account_conf.content.get('url', '')
        auth_type = account_conf.content.get('auth_type', 'basic')
        username = account_conf.content.get('username', '')
        client_id = account_conf.content.get('client_id', '')
        
        # Extract instance from URL
        instance = url.replace('https://', '').replace('http://', '').replace('.service-now.com', '').strip('/')
        
        # Get passwords from storage/passwords
        password = None
        client_secret = None
        realm = 'ta_gen_ai_cim_account__' + account_name
        
        logger.info("Looking for passwords with realm: {}".format(realm))
        
        storage_passwords = service.storage_passwords
        for credential in storage_passwords:
            cred_realm = credential.content.get('realm', '')
            if cred_realm == realm:
                cred_name = credential.content.get('username', '') or ''
                if ':' in credential.name:
                    parts = credential.name.split(':')
                    if len(parts) > 1:
                        cred_name = parts[1]
                clear_password = credential.content.get('clear_password', '')
                logger.info("Found credential: name={}, realm={}".format(cred_name, cred_realm))
                if cred_name == 'password' or 'password' in credential.name:
                    password = clear_password
                    logger.info("Found password credential")
                elif cred_name == 'client_secret' or 'client_secret' in credential.name:
                    client_secret = clear_password
                    logger.info("Found client_secret credential")
        
        if not password and auth_type == 'basic':
            logger.warning("No password found for account {}".format(account_name))
        
        # Debug: Log the configuration being used
        logger.info("Config - URL: {}, Instance: {}, Username: {}, Auth Type: {}".format(
            url, instance, username, auth_type))
        
        # Validate configuration based on auth type
        if auth_type in ['oauth_auth_code', 'oauth_client_creds']:
            if not all([instance, client_id, client_secret]):
                return {
                    'configured': False,
                    'error': 'OAuth credentials incomplete. Check account configuration.'
                }
            return {
                'configured': True,
                'auth_type': 'oauth',
                'instance': instance,
                'url': url,
                'client_id': client_id,
                'client_secret': client_secret,
                'username': username,
                'password': password,
                'access_token': None,
                'token_expires': 0
            }
        else:
            # Basic authentication
            if not all([instance, username, password]):
                return {
                    'configured': False,
                    'error': 'Basic auth credentials incomplete. Check account configuration.'
                }
            return {
                'configured': True,
                'auth_type': 'basic',
                'instance': instance,
                'url': url,
                'username': username,
                'password': password
            }
            
    except Exception as e:
        return {
            'configured': False,
            'error': 'Failed to retrieve ServiceNow config: {}'.format(str(e))
        }


def get_asset_discovery_config(session_key):
    """Retrieve AI Asset Discovery configuration from account conf.

    Returns a dict with keys for ai_system and ai_model settings.
    Falls back to defaults if fields are not set.
    """
    defaults = {
        'ai_system_table': 'alm_ai_system_digital_asset',
        'ai_system_match_field': 'display_name',
        'ai_system_approval_field': 'approval',
        'ai_system_approved_values': 'approved',
        'ai_model_table': '',
        'ai_model_match_field': 'display_name',
        'ai_model_approval_field': 'approval',
        'ai_model_approved_values': 'approved',
    }
    try:
        service = client.connect(
            token=session_key,
            owner='nobody',
            app='TA-gen_ai_cim'
        )
        accounts = service.confs['ta_gen_ai_cim_account']
        if 'asset_discovery' in accounts:
            content = accounts['asset_discovery'].content
            for key in defaults:
                val = content.get(key, '')
                if val:
                    defaults[key] = val
    except Exception as e:
        logger.warning("Could not read asset discovery config, using defaults: {}".format(str(e)))

    # Parse comma-separated approved values into lists
    defaults['ai_system_approved_values_list'] = [
        v.strip() for v in defaults['ai_system_approved_values'].split(',') if v.strip()
    ]
    defaults['ai_model_approved_values_list'] = [
        v.strip() for v in defaults['ai_model_approved_values'].split(',') if v.strip()
    ]

    logger.info("Asset discovery config: system_table={}, model_table={}".format(
        defaults['ai_system_table'], defaults['ai_model_table']))
    return defaults


def determine_approval_status(snow_record, approval_field, approved_values_list):
    """Determine approval status from a ServiceNow record.

    Args:
        snow_record: dict from ServiceNow API response
        approval_field: field name to check (e.g., 'approval')
        approved_values_list: list of values that mean approved

    Returns:
        'approved', 'unapproved', or 'unknown'
    """
    if not snow_record or not approval_field:
        return 'unknown'

    raw_value = snow_record.get(approval_field, '')
    if not raw_value:
        return 'unknown'

    if raw_value in approved_values_list:
        return 'approved'
    return 'unapproved'


def derive_inventory_status(sync_status, approval_status):
    """Derive a human-readable inventory status from sync and approval states.

    Returns:
        'Inventoried Approved', 'Inventoried Unapproved', or 'Uninventoried Unapproved'
    """
    if sync_status == 'found' and approval_status == 'approved':
        return 'Inventoried Approved'
    if sync_status == 'found':
        return 'Inventoried Unapproved'
    return 'Uninventoried Unapproved'


def get_oauth_token(config):
    """Get OAuth 2.0 access token from ServiceNow"""
    import base64
    
    # Check if we have a valid cached token
    if config.get('access_token') and config.get('token_expires', 0) > time.time():
        return config['access_token']
    
    # Request new token
    token_url = 'https://{}.service-now.com/oauth_token.do'.format(config['instance'])
    
    # Prepare token request data
    token_data = {
        'grant_type': 'password',
        'client_id': config['client_id'],
        'client_secret': config['client_secret'],
        'username': config['username'],
        'password': config['password']
    }
    
    # URL encode the data
    if sys.version_info[0] >= 3:
        body = urlencode(token_data).encode('utf-8')
    else:
        body = urlencode(token_data)
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    
    req = Request(token_url, data=body, headers=headers)
    
    try:
        ssl_context = ssl.create_default_context()
        response = urlopen(req, context=ssl_context, timeout=30)
        response_data = response.read()
        if sys.version_info[0] >= 3:
            response_data = response_data.decode('utf-8')
        
        token_response = json.loads(response_data)
        access_token = token_response.get('access_token')
        expires_in = token_response.get('expires_in', 1800)
        
        # Cache the token
        config['access_token'] = access_token
        config['token_expires'] = time.time() + expires_in - 60  # 60 second buffer
        
        return access_token
        
    except HTTPError as e:
        error_body = e.read()
        if sys.version_info[0] >= 3:
            error_body = error_body.decode('utf-8')
        raise Exception('OAuth token error {}: {}'.format(e.code, error_body))
    except URLError as e:
        raise Exception('OAuth connection error: {}'.format(str(e.reason)))


def make_snow_request(method, url, data=None, config=None):
    """Make HTTP request to ServiceNow REST API"""
    import base64
    
    if not config.get('configured'):
        raise Exception(config.get('error', 'ServiceNow not configured'))
    
    # Construct full URL
    base_url = 'https://{}.service-now.com'.format(config['instance'])
    full_url = base_url + url
    
    # Debug: Log the request details
    logger.info("ServiceNow API Request - Method: {}, URL: {}".format(method, full_url))
    logger.info("ServiceNow API Request - Username: {}".format(config.get('username', 'NOT SET')))
    
    # Prepare request headers
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    # Set authentication based on auth type
    auth_type = config.get('auth_type', 'basic')
    logger.info("ServiceNow API Request - Auth Type: {}".format(auth_type))
    
    if auth_type == 'oauth':
        # OAuth 2.0 Bearer token
        access_token = get_oauth_token(config)
        headers['Authorization'] = 'Bearer {}'.format(access_token)
    else:
        # Basic authentication
        auth_string = '{}:{}'.format(config['username'], config['password'])
        if sys.version_info[0] >= 3:
            auth_bytes = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
        else:
            auth_bytes = base64.b64encode(auth_string)
        headers['Authorization'] = 'Basic {}'.format(auth_bytes)
        # Debug: Log auth header (first 20 chars only for security)
        logger.info("ServiceNow API Request - Auth header set (Basic auth)")
    
    # Prepare data
    body = None
    if data is not None:
        body = json.dumps(data)
        if sys.version_info[0] >= 3:
            body = body.encode('utf-8')
    
    # Create request
    req = Request(full_url, data=body, headers=headers)
    if method.upper() != 'POST' and method.upper() != 'GET':
        req.get_method = lambda: method.upper()
    
    # Make request with SSL context
    try:
        ssl_context = ssl.create_default_context()
        response = urlopen(req, context=ssl_context, timeout=30)
        response_data = response.read()
        if sys.version_info[0] >= 3:
            response_data = response_data.decode('utf-8')
        return json.loads(response_data)
    except HTTPError as e:
        error_body = e.read()
        if sys.version_info[0] >= 3:
            error_body = error_body.decode('utf-8')
        raise Exception('ServiceNow API error {}: {}'.format(e.code, error_body))
    except URLError as e:
        raise Exception('ServiceNow connection error: {}'.format(str(e.reason)))


def get_kv_store_record(session_key, asset_name, collection_name='gen_ai_app_asset_map',
                        key_field='gen_ai_app_name'):
    """Check KV Store for existing mapping.

    Args:
        session_key: Splunk session key
        asset_name: value to look up
        collection_name: KV store collection
        key_field: field name used as the unique key
    """
    try:
        service = client.connect(
            token=session_key,
            owner='nobody',
            app='TA-gen_ai_cim'
        )
        collection = service.kvstore[collection_name]

        query = json.dumps({key_field: asset_name})
        results = collection.data.query(query=query)

        if results and len(results) > 0:
            return results[0]
        return None

    except Exception as e:
        logger.error("KV Store lookup failed ({}): {}".format(collection_name, str(e)))
        return None


def save_kv_store_record(session_key, asset_name, sys_id, sync_status, username,
                         approval_status='unknown',
                         collection_name='gen_ai_app_asset_map',
                         key_field='gen_ai_app_name'):
    """Save mapping to KV Store."""
    try:
        service = client.connect(
            token=session_key,
            owner='nobody',
            app='TA-gen_ai_cim'
        )
        collection = service.kvstore[collection_name]

        now_epoch = int(time.time())
        inventory_status = derive_inventory_status(sync_status, approval_status)
        record = {
            key_field: asset_name,
            'service_now_sys_id': sys_id,
            'sync_status': sync_status,
            'approval_status': approval_status,
            'inventory_status': inventory_status,
            'created_at': now_epoch,
            'updated_at': now_epoch,
            'created_by': username
        }

        collection.data.insert(json.dumps(record))
        logger.info("Saved KV Store record ({}): {}={}, sys_id={}, status={}, approval={}, inventory={}".format(
            collection_name, key_field, asset_name, sys_id, sync_status, approval_status, inventory_status))
        return True

    except Exception as e:
        logger.error("KV Store save failed ({}): {}".format(collection_name, str(e)))
        return False


def update_kv_store_record(session_key, key, sys_id, sync_status, username,
                           approval_status=None,
                           collection_name='gen_ai_app_asset_map',
                           key_field=None, asset_name=None,
                           existing_record=None):
    """Update existing mapping in KV Store.

    collection.data.update() replaces the full record, so all fields that
    should be preserved must be included in the payload.  We start from the
    existing record (if provided) and overlay the changed fields so that
    original creation metadata and the asset key field are never lost.
    """
    try:
        service = client.connect(
            token=session_key,
            owner='nobody',
            app='TA-gen_ai_cim'
        )
        collection = service.kvstore[collection_name]

        now_epoch = int(time.time())

        if existing_record:
            update_data = dict(existing_record)
            update_data.pop('_key', None)
        else:
            update_data = {}

        update_data['service_now_sys_id'] = sys_id
        update_data['sync_status'] = sync_status
        update_data['updated_at'] = now_epoch
        update_data['updated_by'] = username
        if approval_status is not None:
            update_data['approval_status'] = approval_status
        if key_field and asset_name is not None:
            update_data[key_field] = asset_name

        final_approval = approval_status if approval_status is not None else update_data.get('approval_status', 'unknown')
        update_data['inventory_status'] = derive_inventory_status(sync_status, final_approval)

        collection.data.update(key, json.dumps(update_data))
        logger.info("Updated KV Store record ({}): _key={}, sys_id={}, status={}, approval={}, inventory={}".format(
            collection_name, key, sys_id, sync_status, approval_status, update_data['inventory_status']))
        return True

    except Exception as e:
        logger.error("KV Store update failed ({}): {}".format(collection_name, str(e)))
        return False


def query_snow_asset(asset_name, config, table_name='alm_ai_system_digital_asset',
                     match_field='display_name', approval_field=''):
    """Query ServiceNow for an existing record on the specified table.

    Args:
        asset_name: The value to search for
        config: ServiceNow configuration dict
        table_name: ServiceNow table to query
        match_field: Field to match asset_name against
        approval_field: Optional field to include in response for approval checking

    Returns:
        dict with sys_id (and approval field) if found, None otherwise
    """
    fields = 'sys_id,{},name'.format(match_field)
    if approval_field and approval_field not in (match_field, 'name', 'sys_id'):
        fields += ',{}'.format(approval_field)

    encoded_name = quote(asset_name, safe='')
    url_with_query = '/api/now/table/{}?sysparm_query={}={}&sysparm_limit=1&sysparm_fields={}'.format(
        table_name, match_field, encoded_name, fields)

    try:
        result = make_snow_request('GET', url_with_query, config=config)

        if result and 'result' in result and len(result['result']) > 0:
            record = result['result'][0]
            logger.info("Found existing ServiceNow record for '{}' in {}: sys_id={}".format(
                asset_name, table_name, record.get('sys_id')))
            return record

        logger.info("Exact match not found for '{}' in {}, trying fallback...".format(
            asset_name, table_name))
        return query_snow_asset_fallback(asset_name, config, table_name, match_field,
                                         approval_field)

    except Exception as e:
        logger.warning("Query-based search failed for '{}' in {}: {}, trying fallback...".format(
            asset_name, table_name, str(e)))
        return query_snow_asset_fallback(asset_name, config, table_name, match_field,
                                         approval_field)


def query_snow_asset_fallback(asset_name, config, table_name='alm_ai_system_digital_asset',
                              match_field='display_name', approval_field=''):
    """Fallback: Fetch all records and filter locally when query permissions are restricted.

    Args:
        asset_name: The value to search for
        config: ServiceNow configuration dict
        table_name: ServiceNow table to query
        match_field: Field to match asset_name against
        approval_field: Optional field to include in response for approval checking

    Returns:
        dict with sys_id (and approval field) if found, None otherwise
    """
    fields = 'sys_id,{},name'.format(match_field)
    if approval_field and approval_field not in (match_field, 'name', 'sys_id'):
        fields += ',{}'.format(approval_field)

    url = '/api/now/table/{}?sysparm_fields={}&sysparm_limit=1000'.format(table_name, fields)

    try:
        result = make_snow_request('GET', url, config=config)

        if result and 'result' in result:
            records = result['result']
            logger.info("ServiceNow returned {} records from {}".format(len(records), table_name))

            for i, record in enumerate(records[:5]):
                logger.info("  Record {}: {}='{}', name='{}', sys_id={}".format(
                    i, match_field, record.get(match_field, ''),
                    record.get('name', ''), record.get('sys_id', '')))

            asset_name_lower = asset_name.lower().strip()
            for record in records:
                record_match = record.get(match_field, '').lower().strip()
                record_name = record.get('name', '').lower().strip()

                if record_match == asset_name_lower or record_name == asset_name_lower:
                    logger.info("Found ServiceNow record for '{}' (fallback) in {}: sys_id={}".format(
                        asset_name, table_name, record.get('sys_id')))
                    return record

        logger.info("No ServiceNow record found for '{}' in {} (checked {} records)".format(
            asset_name, table_name,
            len(records) if result and 'result' in result else 0))
        return None

    except Exception as e:
        logger.error("Error in fallback query for '{}' in {}: {}".format(
            asset_name, table_name, str(e)))
        raise


def _process_asset(asset_name, session_key, snow_config, asset_config):
    """Generic asset processor for both AI Systems and AI Models.

    Args:
        asset_name: The asset value to process
        session_key: Splunk session key
        snow_config: ServiceNow connection config
        asset_config: dict with keys: table_name, match_field, approval_field,
                      approved_values_list, collection_name, key_field, asset_label

    Returns:
        dict with result status and details
    """
    table_name = asset_config['table_name']
    match_field = asset_config['match_field']
    approval_field = asset_config['approval_field']
    approved_values_list = asset_config['approved_values_list']
    collection_name = asset_config['collection_name']
    key_field = asset_config['key_field']
    label = asset_config.get('asset_label', 'asset')

    result = {
        'asset_name': asset_name,
        'status': 'error',
        'sys_id': None,
        'sync_status': None,
        'approval_status': None,
        'message': ''
    }

    try:
        existing = get_kv_store_record(session_key, asset_name,
                                       collection_name=collection_name,
                                       key_field=key_field)
        username = snow_config.get('username', 'system')

        if existing:
            existing_sys_id = existing.get('service_now_sys_id', '')
            existing_status = existing.get('sync_status', '')
            existing_key = existing.get('_key')

            if existing_sys_id and existing_status == 'found':
                logger.info("Re-verifying {} '{}' in ServiceNow (sys_id={})".format(
                    label, asset_name, existing_sys_id))

                snow_record = query_snow_asset(
                    asset_name, snow_config, table_name=table_name,
                    match_field=match_field, approval_field=approval_field)

                if snow_record:
                    approval = determine_approval_status(
                        snow_record, approval_field, approved_values_list)
                    update_kv_store_record(
                        session_key, existing_key, snow_record.get('sys_id'),
                        'found', username, approval_status=approval,
                        collection_name=collection_name,
                        key_field=key_field, asset_name=asset_name,
                        existing_record=existing)
                    result['status'] = 'success'
                    result['sys_id'] = snow_record.get('sys_id')
                    result['sync_status'] = 'found'
                    result['approval_status'] = approval
                    result['message'] = '{} still exists in ServiceNow'.format(label)
                else:
                    logger.warning("{} '{}' no longer found, marking as lost".format(
                        label, asset_name))
                    update_success = update_kv_store_record(
                        session_key, existing_key, '', 'lost', username,
                        approval_status='unknown', collection_name=collection_name,
                        key_field=key_field, asset_name=asset_name,
                        existing_record=existing)
                    if update_success:
                        result['status'] = 'success'
                        result['sys_id'] = ''
                        result['sync_status'] = 'lost'
                        result['approval_status'] = 'unknown'
                        result['message'] = '{} no longer in ServiceNow, marked as lost'.format(label)
                    else:
                        result['message'] = 'Failed to update KV store with lost status'

                return result
            else:
                result['status'] = 'skipped'
                result['sys_id'] = existing_sys_id
                result['sync_status'] = existing_status
                result['approval_status'] = existing.get('approval_status', 'unknown')
                result['message'] = 'Already in KV store with status: {}'.format(existing_status)
                logger.info("Skipping {} '{}': status={}".format(label, asset_name, existing_status))
                return result

        snow_record = query_snow_asset(
            asset_name, snow_config, table_name=table_name,
            match_field=match_field, approval_field=approval_field)

        if snow_record:
            sys_id = snow_record.get('sys_id')
            sync_status = 'found'
            approval = determine_approval_status(
                snow_record, approval_field, approved_values_list)
            logger.info("Found {} '{}' in ServiceNow: sys_id={}, approval={}".format(
                label, asset_name, sys_id, approval))
        else:
            logger.info("{} '{}' not found in ServiceNow".format(label, asset_name))
            sys_id = ''
            sync_status = 'not_found'
            approval = 'unknown'

        save_success = save_kv_store_record(
            session_key, asset_name, sys_id, sync_status, username,
            approval_status=approval, collection_name=collection_name,
            key_field=key_field)

        if save_success:
            result['status'] = 'success'
            result['sys_id'] = sys_id
            result['sync_status'] = sync_status
            result['approval_status'] = approval
            result['message'] = '{} {} in ServiceNow'.format(
                label, 'found and mapped' if sync_status == 'found' else 'not found')
        else:
            result['message'] = 'Failed to save to KV store'

        return result

    except Exception as e:
        result['message'] = str(e)
        logger.error("Error processing {} '{}': {}".format(label, asset_name, str(e)))
        return result


def process_app_name(app_name, session_key, snow_config, discovery_config=None):
    """Process a single gen_ai.app.name: query ServiceNow and save to KV store."""
    if discovery_config is None:
        discovery_config = {}
    asset_config = {
        'table_name': discovery_config.get('ai_system_table', 'alm_ai_system_digital_asset'),
        'match_field': discovery_config.get('ai_system_match_field', 'display_name'),
        'approval_field': discovery_config.get('ai_system_approval_field', 'approval'),
        'approved_values_list': discovery_config.get('ai_system_approved_values_list', ['approved']),
        'collection_name': 'gen_ai_app_asset_map',
        'key_field': 'gen_ai_app_name',
        'asset_label': 'AI System',
    }
    return _process_asset(app_name, session_key, snow_config, asset_config)


def process_model_name(model_name, session_key, snow_config, discovery_config=None):
    """Process a single gen_ai.response.model: query ServiceNow and save to KV store."""
    if discovery_config is None:
        discovery_config = {}
    asset_config = {
        'table_name': discovery_config.get('ai_model_table', ''),
        'match_field': discovery_config.get('ai_model_match_field', 'display_name'),
        'approval_field': discovery_config.get('ai_model_approval_field', 'approval'),
        'approved_values_list': discovery_config.get('ai_model_approved_values_list', ['approved']),
        'collection_name': 'gen_ai_model_asset_map',
        'key_field': 'gen_ai_response_model',
        'asset_label': 'AI Model',
    }
    if not asset_config['table_name']:
        logger.warning("AI Model table not configured, skipping model sync for '{}'".format(model_name))
        return {
            'asset_name': model_name,
            'status': 'skipped',
            'sys_id': None,
            'sync_status': None,
            'approval_status': None,
            'message': 'AI Model table not configured'
        }
    return _process_asset(model_name, session_key, snow_config, asset_config)


def main():
    """Main entry point for the alert action."""
    
    # Read alert action payload from stdin
    # Splunk sends JSON payload for alert actions
    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        # Read payload from stdin
        try:
            payload_str = sys.stdin.read()
            payload = json.loads(payload_str)
        except Exception as e:
            logger.error("Failed to parse alert action payload: {}".format(str(e)))
            sys.exit(1)
    else:
        # For testing, accept JSON from stdin directly
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
    
    # Debug: Log payload keys to understand structure
    logger.info("Payload keys: {}".format(list(payload.keys())))
    
    # Extract session key
    session_key = payload.get('session_key')
    if not session_key:
        logger.error("No session_key in payload")
        sys.exit(1)
    
    # Get ServiceNow configuration
    snow_config = get_snow_config(session_key)
    if not snow_config.get('configured'):
        logger.error("ServiceNow not configured: {}".format(snow_config.get('error')))
        sys.exit(1)

    # Load asset discovery configuration
    discovery_config = get_asset_discovery_config(session_key)

    # Process results from the search
    results_file = payload.get('results_file')
    results = payload.get('result', {})

    logger.info("results_file: {}".format(results_file))
    logger.info("result keys: {}".format(list(results.keys()) if results else 'None'))
    if results:
        logger.info("result contents: {}".format(results))

    processed_count = 0
    success_count = 0
    error_count = 0
    processed_assets = set()

    def _extract_app_name(row):
        return (row.get('gen_ai.app.name') or row.get('app_name') or
                row.get('gen_ai_app_name') or row.get('"gen_ai.app.name"'))

    def _extract_model_name(row):
        return (row.get('gen_ai.response.model') or row.get('response_model') or
                row.get('gen_ai_response_model') or row.get('"gen_ai.response.model"'))

    def _process_row(row):
        nonlocal processed_count, success_count, error_count
        app_name = _extract_app_name(row)
        model_name = _extract_model_name(row)

        if app_name and ('app', app_name) not in processed_assets:
            res = process_app_name(app_name, session_key, snow_config, discovery_config)
            processed_assets.add(('app', app_name))
            processed_count += 1
            if res['status'] in ('success', 'skipped'):
                success_count += 1
            else:
                error_count += 1
        elif app_name:
            logger.info("Skipping duplicate app_name '{}' (already processed)".format(app_name))

        if model_name and ('model', model_name) not in processed_assets:
            res = process_model_name(model_name, session_key, snow_config, discovery_config)
            processed_assets.add(('model', model_name))
            processed_count += 1
            if res['status'] in ('success', 'skipped'):
                success_count += 1
            else:
                error_count += 1
        elif model_name:
            logger.info("Skipping duplicate model_name '{}' (already processed)".format(model_name))

    # Handle single result (from payload.result)
    if results:
        logger.info("Result keys: {}".format(list(results.keys())))
        _process_row(results)

    # Handle multiple results from results_file (CSV or gzip)
    if results_file:
        logger.info("Checking results_file: {}".format(results_file))
        if os.path.exists(results_file):
            logger.info("Results file exists, reading...")
            try:
                if results_file.endswith('.gz'):
                    f = gzip.open(results_file, 'rt')
                else:
                    f = open(results_file, 'r')

                reader = csv.DictReader(f)
                logger.info("CSV fieldnames: {}".format(reader.fieldnames))

                for row in reader:
                    logger.info("Row keys: {}".format(list(row.keys())))
                    _process_row(row)

                f.close()

            except Exception as e:
                logger.error("Error reading results file: {}".format(str(e)))
                import traceback
                logger.error("Traceback: {}".format(traceback.format_exc()))
        else:
            logger.warning("Results file does not exist: {}".format(results_file))
    else:
        logger.info("No results_file provided in payload")
    
    logger.info("Sync complete: processed={}, success={}, errors={}".format(
        processed_count, success_count, error_count))
    
    # Exit with appropriate code
    if error_count > 0 and success_count == 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
