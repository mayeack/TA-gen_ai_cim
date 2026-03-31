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

# Add lib/ and bin/ paths
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
if lib_path not in sys.path:
    sys.path.insert(0, lib_path)

bin_path = os.path.dirname(os.path.abspath(__file__))
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)

from sync_snow_asset import (
    setup_logging,
    get_snow_config as _get_account_config,
    make_snow_request,
)

import splunklib.client as client


APP_NAME = 'TA-gen_ai_cim'
KV_COLLECTION = 'gen_ai_snow_case_map'
SNOW_TABLE = 'sn_ai_case_mgmt_ai_case'

logger = setup_logging('create_snow_case')


def get_snow_config(session_key):
    """Retrieve ServiceNow configuration using the account-based mechanism."""
    config = _get_account_config(session_key)
    if not config.get('configured'):
        return None, config.get('error', 'ServiceNow credentials not configured')
    return config, None


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
    """Create a new AI Case in ServiceNow using the shared make_snow_request."""
    import datetime

    case_data = {
        'short_description': 'Splunk Event for {}'.format(event_id),
        'type': 'AI Case',
        'u_date_of_discovery': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'),
        'description': description or 'AI Case automatically created from Splunk GenAI governance alert. Event ID: {}'.format(event_id),
        'u_source': 'Splunk TA-gen_ai_cim Alert Action'
    }

    url = '/api/now/table/{}'.format(SNOW_TABLE)

    try:
        result = make_snow_request('POST', url, data=case_data, config=config)
        return result, None
    except Exception as e:
        return None, str(e)


def main():
    """Main entry point for alert action"""

    if len(sys.argv) > 1 and sys.argv[1] == '--execute':
        payload = json.loads(sys.stdin.read())
    else:
        try:
            payload = json.loads(sys.stdin.read())
        except Exception:
            logger.error("No input payload provided")
            print("Error: No input payload provided", file=sys.stderr)
            sys.exit(1)

    logger.info("create_snow_case started - payload keys: {}".format(list(payload.keys())))

    config = payload.get('configuration', {})
    event_id = config.get('event_id')
    case_description = config.get('case_description', '')
    session_key = payload.get('session_key')

    if not event_id:
        result = payload.get('result', {})
        event_id = (result.get('gen_ai.request.id') or result.get('gen_ai.event.id')
                    or result.get('event_id') or result.get('request_id'))

    if not event_id:
        logger.error("No event_id/request_id in payload")
        print(json.dumps({'success': False, 'message': 'No event_id provided'}))
        sys.exit(1)

    if not session_key:
        logger.error("No session_key in payload")
        print(json.dumps({'success': False, 'message': 'No session key available'}))
        sys.exit(1)

    snow_config, error = get_snow_config(session_key)
    if error:
        logger.error("ServiceNow config error: {}".format(error))
        print(json.dumps({'success': False, 'message': 'ServiceNow configuration error: {}'.format(error)}))
        sys.exit(1)

    logger.info("ServiceNow configured - instance: {}".format(snow_config.get('instance')))

    try:
        service = client.connect(token=session_key, owner='nobody', app=APP_NAME)
    except Exception as e:
        logger.error("Splunk connection error: {}".format(str(e)))
        print(json.dumps({'success': False, 'message': 'Splunk connection error: {}'.format(str(e))}))
        sys.exit(1)

    existing = check_existing_case(service, event_id)
    if existing:
        case_url = 'https://{}.service-now.com/{}.do?sys_id={}'.format(
            existing.get('sn_instance', snow_config['instance']),
            SNOW_TABLE, existing.get('sys_id'))
        logger.info("Existing case found for event_id={}: {}".format(event_id, existing.get('sys_id')))
        print(json.dumps({
            'success': True, 'status': 'existing',
            'message': 'Existing case found for event_id={}'.format(event_id),
            'case_url': case_url, 'sys_id': existing.get('sys_id')}))
        sys.exit(0)

    result, error = create_snow_case(snow_config, event_id, case_description)

    if error:
        logger.error("Failed to create case for event_id={}: {}".format(event_id, error))
        print(json.dumps({'success': False, 'message': 'Failed to create case: {}'.format(error)}))
        sys.exit(1)

    if result and 'result' in result:
        sys_id = result['result'].get('sys_id')
        save_case_mapping(service, event_id, sys_id, snow_config['instance'], snow_config.get('username', 'system'))
        case_url = 'https://{}.service-now.com/{}.do?sys_id={}'.format(
            snow_config['instance'], SNOW_TABLE, sys_id)
        logger.info("Case created for event_id={}: sys_id={}".format(event_id, sys_id))
        print(json.dumps({
            'success': True, 'status': 'created',
            'message': 'New case created for event_id={}'.format(event_id),
            'case_url': case_url, 'sys_id': sys_id}))
        sys.exit(0)
    else:
        logger.error("ServiceNow returned empty response for event_id={}".format(event_id))
        print(json.dumps({'success': False, 'message': 'ServiceNow returned empty response'}))
        sys.exit(1)


if __name__ == '__main__':
    main()
