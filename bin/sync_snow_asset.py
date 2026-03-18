#!/usr/bin/env python
# encoding=utf-8
"""
sync_snow_asset.py - Alert Action for ServiceNow AI System Digital Asset Sync

This script syncs gen_ai.app.name values to ServiceNow's alm_ai_system_digital_asset
table. It queries ServiceNow to check if a record exists for the app name and stores
the sys_id mapping in the KV store.

Usage:
    Called as an alert action from a scheduled saved search that identifies
    gen_ai.app.name values not yet mapped in the KV store.

Workflow:
    1. Receive app_name from alert action payload
    2. Check KV store for existing mapping (defensive check)
    3. Query ServiceNow alm_ai_system_digital_asset for matching record
    4. If found: store sys_id with sync_status="found"
    5. If not found: store with sync_status="not_found" (no record creation)

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
                # Skip default and internal stanzas
                if stanza.name == 'default' or stanza.name.startswith('_'):
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


def get_kv_store_record(session_key, app_name):
    """Check KV Store for existing mapping"""
    try:
        service = client.connect(
            token=session_key,
            owner='nobody',
            app='TA-gen_ai_cim'
        )
        collection = service.kvstore['gen_ai_app_asset_map']
        
        # Query by gen_ai_app_name
        query = json.dumps({'gen_ai_app_name': app_name})
        results = collection.data.query(query=query)
        
        if results and len(results) > 0:
            return results[0]
        return None
        
    except Exception as e:
        logger.error("KV Store lookup failed: {}".format(str(e)))
        return None


def save_kv_store_record(session_key, app_name, sys_id, sync_status, username):
    """Save mapping to KV Store"""
    try:
        service = client.connect(
            token=session_key,
            owner='nobody',
            app='TA-gen_ai_cim'
        )
        collection = service.kvstore['gen_ai_app_asset_map']
        
        now_epoch = int(time.time())
        record = {
            'gen_ai_app_name': app_name,
            'service_now_sys_id': sys_id,
            'sync_status': sync_status,
            'created_at': now_epoch,
            'updated_at': now_epoch,
            'created_by': username
        }
        
        collection.data.insert(json.dumps(record))
        logger.info("Saved KV Store record: app_name={}, sys_id={}, status={}".format(
            app_name, sys_id, sync_status))
        return True
        
    except Exception as e:
        logger.error("KV Store save failed: {}".format(str(e)))
        return False


def update_kv_store_record(session_key, key, sys_id, sync_status, username):
    """Update existing mapping in KV Store"""
    try:
        service = client.connect(
            token=session_key,
            owner='nobody',
            app='TA-gen_ai_cim'
        )
        collection = service.kvstore['gen_ai_app_asset_map']
        
        now_epoch = int(time.time())
        update_data = {
            'service_now_sys_id': sys_id,
            'sync_status': sync_status,
            'updated_at': now_epoch,
            'updated_by': username
        }
        
        collection.data.update(key, json.dumps(update_data))
        logger.info("Updated KV Store record: _key={}, sys_id={}, status={}".format(
            key, sys_id, sync_status))
        return True
        
    except Exception as e:
        logger.error("KV Store update failed: {}".format(str(e)))
        return False


def query_snow_asset(app_name, config):
    """Query ServiceNow for existing alm_ai_system_digital_asset record.
    
    Args:
        app_name: The gen_ai.app.name to search for
        config: ServiceNow configuration dict
        
    Returns:
        dict with sys_id if found, None otherwise
    """
    # First, try exact match query (faster but case-sensitive)
    encoded_name = quote(app_name, safe='')
    url_with_query = '/api/now/table/alm_ai_system_digital_asset?sysparm_query=display_name={}&sysparm_limit=1&sysparm_fields=sys_id,display_name'.format(encoded_name)
    
    try:
        result = make_snow_request('GET', url_with_query, config=config)
        
        if result and 'result' in result and len(result['result']) > 0:
            record = result['result'][0]
            logger.info("Found existing ServiceNow asset for '{}': sys_id={}".format(
                app_name, record.get('sys_id')))
            return record
        
        # Exact match not found - try case-insensitive fallback
        logger.info("Exact match not found for '{}', trying case-insensitive search...".format(app_name))
        return query_snow_asset_fallback(app_name, config)
        
    except Exception as e:
        # If query fails (403 or other error), fall back to fetching all and filtering locally
        logger.warning("Query-based search failed for '{}': {}, trying fetch-all approach...".format(app_name, str(e)))
        return query_snow_asset_fallback(app_name, config)


def query_snow_asset_fallback(app_name, config):
    """Fallback: Fetch all assets and filter locally when query permissions are restricted.
    
    Args:
        app_name: The gen_ai.app.name to search for
        config: ServiceNow configuration dict
        
    Returns:
        dict with sys_id if found, None otherwise
    """
    # Fetch records without query filter, only get sys_id and display_name fields
    url = '/api/now/table/alm_ai_system_digital_asset?sysparm_fields=sys_id,display_name,name&sysparm_limit=1000'
    
    try:
        result = make_snow_request('GET', url, config=config)
        
        if result and 'result' in result:
            records = result['result']
            logger.info("ServiceNow returned {} records from alm_ai_system_digital_asset".format(len(records)))
            
            # Log first few records for debugging
            for i, record in enumerate(records[:5]):
                logger.info("  Record {}: display_name='{}', name='{}', sys_id={}".format(
                    i, record.get('display_name', ''), record.get('name', ''), record.get('sys_id', '')))
            
            # Search locally for matching display_name (case-insensitive)
            app_name_lower = app_name.lower().strip()
            for record in records:
                record_display_name = record.get('display_name', '').lower().strip()
                record_name = record.get('name', '').lower().strip()
                
                # Match on either display_name or name field
                if record_display_name == app_name_lower or record_name == app_name_lower:
                    logger.info("Found existing ServiceNow asset for '{}' (fallback): sys_id={}, display_name='{}', name='{}'".format(
                        app_name, record.get('sys_id'), record.get('display_name', ''), record.get('name', '')))
                    return record
        
        logger.info("No existing ServiceNow asset found for '{}' (fallback search, checked {} records)".format(
            app_name, len(records) if result and 'result' in result else 0))
        return None
        
    except Exception as e:
        logger.error("Error in fallback query for '{}': {}".format(app_name, str(e)))
        raise


def process_app_name(app_name, session_key, snow_config):
    """Process a single app_name: query ServiceNow and save mapping to KV store.
    
    This function queries ServiceNow for existing records. The result is saved 
    to the KV store with the appropriate sync_status.
    
    Workflow:
        1. Check KV store for existing mapping
        2. Query ServiceNow alm_ai_system_digital_asset for matching record
        3. If found: store sys_id with sync_status="found"
        4. If not found: store with sync_status="not_found" (no record creation)
        5. If previously found but now missing: update sync_status="lost"
    
    Args:
        app_name: The gen_ai.app.name to process
        session_key: Splunk session key
        snow_config: ServiceNow configuration dict
        
    Returns:
        dict with result status and details
    """
    result = {
        'app_name': app_name,
        'status': 'error',
        'sys_id': None,
        'sync_status': None,
        'message': ''
    }
    
    try:
        # Check if already in KV store
        existing = get_kv_store_record(session_key, app_name)
        username = snow_config.get('username', 'system')
        
        if existing:
            existing_sys_id = existing.get('service_now_sys_id', '')
            existing_status = existing.get('sync_status', '')
            existing_key = existing.get('_key')
            
            # If previously found with a sys_id, re-verify it still exists
            if existing_sys_id and existing_status == 'found':
                logger.info("Re-verifying '{}' in ServiceNow (existing sys_id={})".format(
                    app_name, existing_sys_id))
                
                snow_record = query_snow_asset(app_name, snow_config)
                
                if snow_record:
                    # Still exists in ServiceNow
                    result['status'] = 'success'
                    result['sys_id'] = snow_record.get('sys_id')
                    result['sync_status'] = 'found'
                    result['message'] = 'Asset still exists in ServiceNow'
                    logger.info("'{}' still exists in ServiceNow".format(app_name))
                else:
                    # No longer exists in ServiceNow - mark as lost
                    logger.warning("'{}' no longer found in ServiceNow, marking as lost".format(app_name))
                    update_success = update_kv_store_record(
                        session_key, existing_key, '', 'lost', username)
                    
                    if update_success:
                        result['status'] = 'success'
                        result['sys_id'] = ''
                        result['sync_status'] = 'lost'
                        result['message'] = 'Asset no longer exists in ServiceNow, marked as lost'
                    else:
                        result['status'] = 'error'
                        result['message'] = 'Failed to update KV store with lost status'
                
                return result
            else:
                # Already in KV store with not_found or lost status, skip
                result['status'] = 'skipped'
                result['sys_id'] = existing_sys_id
                result['sync_status'] = existing_status
                result['message'] = 'Already mapped in KV store with status: {}'.format(existing_status)
                logger.info("Skipping '{}': already in KV store with status={}".format(
                    app_name, existing_status))
                return result
        
        # New record - Query ServiceNow for existing record
        snow_record = query_snow_asset(app_name, snow_config)
        
        if snow_record:
            # Found existing record in ServiceNow
            sys_id = snow_record.get('sys_id')
            sync_status = 'found'
            logger.info("Found '{}' in ServiceNow with sys_id={}".format(app_name, sys_id))
        else:
            # Not found in ServiceNow - mark as not_found (no record creation)
            logger.info("'{}' not found in ServiceNow, marking as not_found".format(app_name))
            sys_id = ''  # No sys_id since record doesn't exist
            sync_status = 'not_found'
        
        # Save to KV store
        save_success = save_kv_store_record(session_key, app_name, sys_id, sync_status, username)
        
        if save_success:
            result['status'] = 'success'
            result['sys_id'] = sys_id
            result['sync_status'] = sync_status
            if sync_status == 'found':
                result['message'] = 'Asset found in ServiceNow and mapped'
            else:
                result['message'] = 'Asset not found in ServiceNow, marked for alert'
        else:
            result['status'] = 'error'
            result['message'] = 'Failed to save to KV store'
        
        return result
        
    except Exception as e:
        result['message'] = str(e)
        logger.error("Error processing '{}': {}".format(app_name, str(e)))
        return result


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
    
    # Process results from the search
    results_file = payload.get('results_file')
    results = payload.get('result', {})
    
    # Debug: Log what we received
    logger.info("results_file: {}".format(results_file))
    logger.info("result keys: {}".format(list(results.keys()) if results else 'None'))
    if results:
        logger.info("result contents: {}".format(results))
    
    processed_count = 0
    success_count = 0
    error_count = 0
    
    # Handle single result (from payload.result)
    if results:
        # Log all keys for debugging
        logger.info("Result keys: {}".format(list(results.keys())))
        # Try multiple possible field names (with and without quotes, dots, underscores)
        app_name = (results.get('gen_ai.app.name') or 
                    results.get('app_name') or 
                    results.get('gen_ai_app_name') or
                    results.get('"gen_ai.app.name"'))
        logger.info("Single result app_name: {}".format(app_name))
        if app_name:
            result = process_app_name(app_name, session_key, snow_config)
            processed_count += 1
            if result['status'] in ['success', 'skipped']:
                success_count += 1
            else:
                error_count += 1
    
    # Handle multiple results from results_file (CSV or gzip)
    if results_file:
        logger.info("Checking results_file: {}".format(results_file))
        if os.path.exists(results_file):
            logger.info("Results file exists, reading...")
            try:
                # Check if gzipped
                if results_file.endswith('.gz'):
                    f = gzip.open(results_file, 'rt')
                else:
                    f = open(results_file, 'r')
                
                reader = csv.DictReader(f)
                # Log the CSV field names
                logger.info("CSV fieldnames: {}".format(reader.fieldnames))
                
                for row in reader:
                    # Log all keys for debugging
                    logger.info("Row keys: {}".format(list(row.keys())))
                    # Try multiple possible field names (with and without quotes, dots, underscores)
                    app_name = (row.get('gen_ai.app.name') or 
                                row.get('app_name') or 
                                row.get('gen_ai_app_name') or
                                row.get('"gen_ai.app.name"'))
                    logger.info("Processing row: app_name={}".format(app_name))
                    if app_name:
                        result = process_app_name(app_name, session_key, snow_config)
                        processed_count += 1
                        if result['status'] in ['success', 'skipped']:
                            success_count += 1
                        else:
                            error_count += 1
                
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
