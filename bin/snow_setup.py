#!/usr/bin/env python
# encoding=utf-8
"""
snow_setup.py - ServiceNow Credential Setup Utility

This script configures ServiceNow REST API credentials for the TA-gen_ai_cim
Technology Add-on using Splunk's secure credential storage.

Usage (CLI):
    $SPLUNK_HOME/bin/splunk cmd python bin/snow_setup.py --instance <instance> --username <user> --password <pass>

Usage (Interactive):
    $SPLUNK_HOME/bin/splunk cmd python bin/snow_setup.py --interactive

Environment Variables (alternative):
    SNOW_INSTANCE - ServiceNow instance name
    SNOW_USERNAME - ServiceNow username  
    SNOW_PASSWORD - ServiceNow password

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

from __future__ import absolute_import, division, print_function

import os
import sys
import argparse
import getpass

# Add Splunk library path
SPLUNK_HOME = os.environ.get('SPLUNK_HOME', '/opt/splunk')
sys.path.insert(0, os.path.join(SPLUNK_HOME, 'lib', 'python3.9', 'site-packages'))
sys.path.insert(0, os.path.join(SPLUNK_HOME, 'lib', 'python3.7', 'site-packages'))

try:
    import splunk.entity as entity
    import splunk.auth as auth
    SPLUNK_AVAILABLE = True
except ImportError:
    SPLUNK_AVAILABLE = False


APP_NAME = 'TA-gen_ai_cim'
REALM_INSTANCE = 'servicenow_instance'
REALM_CREDENTIALS = 'servicenow_credentials'


def get_session_key():
    """Get a session key for Splunk REST API access"""
    if not SPLUNK_AVAILABLE:
        raise RuntimeError("Splunk SDK not available. Run this script using: $SPLUNK_HOME/bin/splunk cmd python")
    
    # Try to get session from environment or stdin
    session_key = os.environ.get('SPLUNK_SESSION_KEY')
    if session_key:
        return session_key
    
    # Prompt for credentials
    print("\nSplunk Authentication Required")
    print("-" * 40)
    username = input("Splunk Username: ")
    password = getpass.getpass("Splunk Password: ")
    
    try:
        session_key = auth.getSessionKey(username, password)
        return session_key
    except Exception as e:
        raise RuntimeError("Authentication failed: {}".format(str(e)))


def store_credential(session_key, name, password, realm):
    """Store a credential in Splunk's password storage"""
    try:
        # Check if credential already exists
        try:
            existing = entity.getEntity(
                '/storage/passwords',
                '{}:{}:'.format(realm, name),
                sessionKey=session_key,
                owner='nobody',
                namespace=APP_NAME
            )
            # Update existing credential
            entity.setEntity(
                '/storage/passwords',
                '{}:{}:'.format(realm, name),
                {'password': password},
                sessionKey=session_key,
                owner='nobody',
                namespace=APP_NAME
            )
            return "updated"
        except Exception:
            pass
        
        # Create new credential
        new_credential = entity.Entity(
            '/storage/passwords',
            '_new',
            namespace=APP_NAME,
            owner='nobody'
        )
        new_credential['name'] = name
        new_credential['password'] = password
        new_credential['realm'] = realm
        
        entity.setEntity(new_credential, sessionKey=session_key)
        return "created"
        
    except Exception as e:
        raise RuntimeError("Failed to store credential: {}".format(str(e)))


def store_config(session_key, instance):
    """Store non-sensitive configuration"""
    try:
        # Try to update the ta_gen_ai_cim_servicenow.conf
        conf_endpoint = '/configs/conf-ta_gen_ai_cim_servicenow/settings'
        
        try:
            # Check if stanza exists
            existing = entity.getEntity(
                conf_endpoint,
                '',
                sessionKey=session_key,
                owner='nobody',
                namespace=APP_NAME
            )
        except Exception:
            # Create the stanza if it doesn't exist
            pass
        
        # Update the configuration
        entity.setEntity(
            conf_endpoint,
            '',
            {'instance': instance},
            sessionKey=session_key,
            owner='nobody',
            namespace=APP_NAME
        )
        return True
        
    except Exception as e:
        # Non-critical - config can be stored in password storage instead
        print("Warning: Could not update config file: {}".format(str(e)))
        return False


def test_connection(instance, username, password):
    """Test ServiceNow connection"""
    try:
        # Python 3
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError, URLError
    except ImportError:
        # Python 2
        from urllib2 import Request, urlopen, HTTPError, URLError
    
    import base64
    import ssl
    import json
    
    # Build test URL - query sys_user table (always exists)
    url = 'https://{}.service-now.com/api/now/table/sys_user?sysparm_limit=1'.format(instance)
    
    # Prepare auth header
    auth_string = '{}:{}'.format(username, password)
    if sys.version_info[0] >= 3:
        auth_bytes = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
    else:
        auth_bytes = base64.b64encode(auth_string)
    
    headers = {
        'Authorization': 'Basic {}'.format(auth_bytes),
        'Accept': 'application/json'
    }
    
    req = Request(url, headers=headers)
    
    try:
        ssl_context = ssl.create_default_context()
        response = urlopen(req, context=ssl_context, timeout=15)
        response_data = response.read()
        return True, "Connection successful!"
    except HTTPError as e:
        if e.code == 401:
            return False, "Authentication failed - check username/password"
        elif e.code == 403:
            return False, "Access forbidden - check user permissions"
        else:
            return False, "HTTP error {}: {}".format(e.code, str(e))
    except URLError as e:
        return False, "Connection failed: {}".format(str(e.reason))
    except Exception as e:
        return False, "Error: {}".format(str(e))


def main():
    parser = argparse.ArgumentParser(
        description='Configure ServiceNow credentials for TA-gen_ai_cim',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Interactive mode
    python snow_setup.py --interactive
    
    # Command line mode
    python snow_setup.py --instance ciscoaidfsir --username svc_splunk --password 'secret123'
    
    # Using environment variables
    export SNOW_INSTANCE=ciscoaidfsir
    export SNOW_USERNAME=svc_splunk
    export SNOW_PASSWORD=secret123
    python snow_setup.py
    
Note: This script must be run using Splunk's Python interpreter:
    $SPLUNK_HOME/bin/splunk cmd python bin/snow_setup.py [options]
        """
    )
    
    parser.add_argument('--instance', '-i', help='ServiceNow instance name (e.g., ciscoaidfsir)')
    parser.add_argument('--username', '-u', help='ServiceNow username')
    parser.add_argument('--password', '-p', help='ServiceNow password')
    parser.add_argument('--interactive', '-I', action='store_true', help='Interactive mode')
    parser.add_argument('--test', '-t', action='store_true', help='Test connection after setup')
    parser.add_argument('--test-only', '-T', action='store_true', help='Only test connection (no setup)')
    
    args = parser.parse_args()
    
    # Get credentials from args, environment, or interactive input
    instance = args.instance or os.environ.get('SNOW_INSTANCE')
    username = args.username or os.environ.get('SNOW_USERNAME')
    password = args.password or os.environ.get('SNOW_PASSWORD')
    
    if args.interactive or (not all([instance, username, password]) and not args.test_only):
        print("\n" + "=" * 60)
        print("ServiceNow Configuration for TA-gen_ai_cim")
        print("=" * 60)
        
        if not instance:
            instance = input("\nServiceNow Instance Name (e.g., ciscoaidfsir): ").strip()
        else:
            print("\nServiceNow Instance: {}".format(instance))
            
        if not username:
            username = input("ServiceNow Username: ").strip()
        else:
            print("ServiceNow Username: {}".format(username))
            
        if not password:
            password = getpass.getpass("ServiceNow Password: ")
    
    # Validate inputs
    if not all([instance, username, password]):
        print("\nError: Instance, username, and password are required.")
        print("Use --interactive or provide via arguments/environment variables.")
        sys.exit(1)
    
    # Test only mode
    if args.test_only:
        print("\nTesting ServiceNow connection...")
        success, message = test_connection(instance, username, password)
        if success:
            print("✓ {}".format(message))
            sys.exit(0)
        else:
            print("✗ {}".format(message))
            sys.exit(1)
    
    # Test connection first if requested
    if args.test or args.interactive:
        print("\nTesting ServiceNow connection...")
        success, message = test_connection(instance, username, password)
        if success:
            print("✓ {}".format(message))
        else:
            print("✗ {}".format(message))
            if args.interactive:
                proceed = input("\nConnection test failed. Continue anyway? (y/N): ").strip().lower()
                if proceed != 'y':
                    print("Setup cancelled.")
                    sys.exit(1)
            else:
                sys.exit(1)
    
    # Get Splunk session key
    print("\nAuthenticating with Splunk...")
    try:
        session_key = get_session_key()
        print("✓ Splunk authentication successful")
    except Exception as e:
        print("✗ {}".format(str(e)))
        sys.exit(1)
    
    # Store credentials
    print("\nStoring credentials in Splunk secure storage...")
    
    try:
        # Store instance name
        result = store_credential(session_key, 'ta_gen_ai_cim_snow', instance, REALM_INSTANCE)
        print("✓ Instance configuration {}".format(result))
        
        # Store username/password
        result = store_credential(session_key, username, password, REALM_CREDENTIALS)
        print("✓ Credentials {}".format(result))
        
        # Store config file (optional)
        store_config(session_key, instance)
        
    except Exception as e:
        print("✗ Error: {}".format(str(e)))
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    print("""
ServiceNow integration is now configured.

To test the integration:
    | makeresults | eval gen_ai.request.id="test_123" | aicase mode=lookup

To create a case:
    index=gen_ai_log earliest=-1h | head 1 | aicase

The "Open Case in ServiceNow" option is now available in the
Event Context menu (right-click) for events with gen_ai.request.id.
""")


if __name__ == '__main__':
    main()
