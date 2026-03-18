#!/usr/bin/env python
# encoding=utf-8
"""
create_snow_case.py - Alert Action for ServiceNow AI Case Creation

This script is executed as an alert action to create ServiceNow AI Cases.
It provides a Splunk Cloud-compatible alternative to the custom search command.

Usage (Alert Action):
    Configured via alert_actions.conf - not called directly

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import json
import time

# Handle Python 2/3 compatibility
try:
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except ImportError:
    from urllib2 import Request, urlopen, HTTPError, URLError

# Add Splunk SDK paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

import splunklib.client as client


APP_NAME = 'TA-gen_ai_cim'
KV_COLLECTION = 'gen_ai_snow_case_map'
SNOW_TABLE = 'sn_ai_case_mgmt_ai_case'


def get_snow_config(session_key):
    """Retrieve ServiceNow configuration from passwords.conf storage"""
    try:
        service = client.connect(
            token=session_key,
            owner='nobody',
            app=APP_NAME
        )
        
        storage_passwords = service.storage_passwords
        
        snow_instance = None
        snow_username = None
        snow_password = None
        
        for credential in storage_passwords:
            if 'ta_gen_ai_cim_snow' in credential.name:
                clear_password = credential.content.get('clear_password', '')
                realm = credential.content.get('realm', '')
                username = credential.content.get('username', '')
                
                if realm == 'servicenow_instance':
                    snow_instance = clear_password
                elif realm == 'servicenow_credentials':
                    snow_username = username
                    snow_password = clear_password
        
        if not all([snow_instance, snow_username, snow_password]):
            return None, "ServiceNow credentials not configured"
            
        return {
            'instance': snow_instance,
            'username': snow_username,
            'password': snow_password
        }, None
        
    except Exception as e:
        return None, str(e)


def check_existing_case(service, event_id):
    """Check KV Store for existing case mapping"""
    try:
        collection = service.kvstore[KV_COLLECTION]
        query = json.dumps({'event_id': event_id})
        results = collection.data.query(query=query)
        
        if results and len(results) > 0:
            return results[0]
        return None
    except Exception:
        return None


def save_case_mapping(service, event_id, sys_id, sn_instance, username):
    """Save case mapping to KV Store"""
    try:
        collection = service.kvstore[KV_COLLECTION]
        now_epoch = int(time.time())
        
        record = {
            'event_id': event_id,
            'sys_id': sys_id,
            'sn_instance': sn_instance,
            'created_at': now_epoch,
            'updated_at': now_epoch,
            'created_by': username
        }
        
        collection.data.insert(json.dumps(record))
        return True
    except Exception:
        return False


def create_snow_case(config, event_id, description=None):
    """Create a new AI Case in ServiceNow"""
    import base64
    import ssl
    import datetime
    
    # Build case data
    case_data = {
        'short_description': 'Splunk Event for {}'.format(event_id),
        'type': 'AI Case',
        'u_date_of_discovery': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'),
        'description': description or 'AI Case automatically created from Splunk GenAI governance alert. Event ID: {}'.format(event_id),
        'u_source': 'Splunk TA-gen_ai_cim Alert Action'
    }
    
    # Build URL
    url = 'https://{}.service-now.com/api/now/table/{}'.format(
        config['instance'], SNOW_TABLE
    )
    
    # Prepare auth
    auth_string = '{}:{}'.format(config['username'], config['password'])
    if sys.version_info[0] >= 3:
        auth_bytes = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
    else:
        auth_bytes = base64.b64encode(auth_string)
    
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': 'Basic {}'.format(auth_bytes)
    }
    
    body = json.dumps(case_data)
    if sys.version_info[0] >= 3:
        body = body.encode('utf-8')
    
    req = Request(url, data=body, headers=headers)
    
    try:
        ssl_context = ssl.create_default_context()
        response = urlopen(req, context=ssl_context, timeout=30)
        response_data = response.read()
        if sys.version_info[0] >= 3:
            response_data = response_data.decode('utf-8')
        return json.loads(response_data), None
    except HTTPError as e:
        error_body = e.read()
        if sys.version_info[0] >= 3:
            error_body = error_body.decode('utf-8')
        return None, 'ServiceNow API error {}: {}'.format(e.code, error_body)
    except URLError as e:
        return None, 'ServiceNow connection error: {}'.format(str(e.reason))
    except Exception as e:
        return None, str(e)


def main():
    """Main entry point for alert action"""
    
    # Read payload from stdin
    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        # Alert action format
        payload = json.loads(sys.stdin.read())
    else:
        # Try to read from stdin anyway
        try:
            payload = json.loads(sys.stdin.read())
        except Exception:
            print("Error: No input payload provided", file=sys.stderr)
            sys.exit(1)
    
    # Extract configuration
    config = payload.get('configuration', {})
    event_id = config.get('event_id')
    case_description = config.get('case_description', '')
    session_key = payload.get('session_key')
    
    # Also try to get event_id from result if not in config
    if not event_id:
        result = payload.get('result', {})
        event_id = result.get('gen_ai.event.id') or result.get('event_id')
    
    if not event_id:
        print(json.dumps({
            'success': False,
            'message': 'No event_id provided'
        }))
        sys.exit(1)
    
    if not session_key:
        print(json.dumps({
            'success': False,
            'message': 'No session key available'
        }))
        sys.exit(1)
    
    # Get ServiceNow configuration
    snow_config, error = get_snow_config(session_key)
    if error:
        print(json.dumps({
            'success': False,
            'message': 'ServiceNow configuration error: {}'.format(error)
        }))
        sys.exit(1)
    
    # Connect to Splunk
    try:
        service = client.connect(
            token=session_key,
            owner='nobody',
            app=APP_NAME
        )
    except Exception as e:
        print(json.dumps({
            'success': False,
            'message': 'Splunk connection error: {}'.format(str(e))
        }))
        sys.exit(1)
    
    # Check for existing case
    existing = check_existing_case(service, event_id)
    if existing:
        case_url = 'https://{}.service-now.com/{}.do?sys_id={}'.format(
            existing.get('sn_instance', snow_config['instance']),
            SNOW_TABLE,
            existing.get('sys_id')
        )
        print(json.dumps({
            'success': True,
            'status': 'existing',
            'message': 'Existing case found for event_id={}'.format(event_id),
            'case_url': case_url,
            'sys_id': existing.get('sys_id')
        }))
        sys.exit(0)
    
    # Create new case
    result, error = create_snow_case(snow_config, event_id, case_description)
    
    if error:
        print(json.dumps({
            'success': False,
            'message': 'Failed to create case: {}'.format(error)
        }))
        sys.exit(1)
    
    if result and 'result' in result:
        sys_id = result['result'].get('sys_id')
        
        # Save mapping to KV Store
        save_case_mapping(
            service,
            event_id,
            sys_id,
            snow_config['instance'],
            snow_config['username']
        )
        
        case_url = 'https://{}.service-now.com/{}.do?sys_id={}'.format(
            snow_config['instance'],
            SNOW_TABLE,
            sys_id
        )
        
        print(json.dumps({
            'success': True,
            'status': 'created',
            'message': 'New case created for event_id={}'.format(event_id),
            'case_url': case_url,
            'sys_id': sys_id
        }))
        sys.exit(0)
    else:
        print(json.dumps({
            'success': False,
            'message': 'ServiceNow returned empty response'
        }))
        sys.exit(1)


if __name__ == '__main__':
    main()
