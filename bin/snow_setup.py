#!/usr/bin/env python
# encoding=utf-8
"""
snow_setup.py - ServiceNow Credential Setup Utility

Configures a ServiceNow account for the TA-gen_ai_cim Technology Add-on by
driving the same REST endpoint as the Configuration page
(ta_gen_ai_cim_account, handled by ta_gen_ai_cim_account_handler.py).
The handler writes the account stanza to ta_gen_ai_cim_account.conf and the
password to Splunk secure storage under realm
ta_gen_ai_cim_account__<account_name> — the realm every runtime consumer
(aicase, sync_snow_asset, create_snow_case, pull_snow_inventory) reads.

Usage (CLI):
    $SPLUNK_HOME/bin/splunk cmd python3 bin/snow_setup.py --instance <instance> --username <user> --password <pass>

Usage (Interactive):
    $SPLUNK_HOME/bin/splunk cmd python3 bin/snow_setup.py --interactive

Environment Variables (alternative):
    SNOW_INSTANCE - ServiceNow instance name
    SNOW_USERNAME - ServiceNow username
    SNOW_PASSWORD - ServiceNow password
    SPLUNK_SESSION_KEY - Splunk session key (skips the Splunk login prompt)

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import os
import sys
import argparse
import getpass

# Use the app's vendored Splunk SDK
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
if lib_path not in sys.path:
    sys.path.insert(0, lib_path)

import splunklib.binding as binding

APP_NAME = 'TA-gen_ai_cim'
ACCOUNT_ENDPOINT = '/servicesNS/nobody/{}/ta_gen_ai_cim_account'.format(APP_NAME)


def connect_splunk(host, port):
    """Build an authenticated splunklib binding context to splunkd."""
    session_key = os.environ.get('SPLUNK_SESSION_KEY')
    if session_key:
        return binding.connect(host=host, port=port, scheme='https',
                               token=session_key, autologin=False)

    print("\nSplunk Authentication Required")
    print("-" * 40)
    username = input("Splunk Username: ")
    password = getpass.getpass("Splunk Password: ")

    try:
        return binding.connect(host=host, port=port, scheme='https',
                               username=username, password=password)
    except Exception as e:
        raise RuntimeError("Authentication failed: {}".format(str(e)))


def account_exists(ctx, account_name):
    """Check whether the account stanza already exists."""
    try:
        ctx.get('{}/{}'.format(ACCOUNT_ENDPOINT, account_name))
        return True
    except binding.HTTPError as e:
        if e.status == 404:
            return False
        raise


def store_account(ctx, account_name, instance, username, password):
    """Create or update the ServiceNow account via the app's REST handler."""
    url = 'https://{}.service-now.com'.format(instance)
    fields = {
        'url': url,
        'auth_type': 'basic',
        'username': username,
        'password': password,
    }

    if account_exists(ctx, account_name):
        ctx.post('{}/{}'.format(ACCOUNT_ENDPOINT, account_name), **fields)
        return "updated"
    ctx.post(ACCOUNT_ENDPOINT, name=account_name, **fields)
    return "created"


def test_connection(instance, username, password):
    """Test ServiceNow connection"""
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
    import base64
    import ssl

    # Build test URL - query sys_user table (always exists)
    url = 'https://{}.service-now.com/api/now/table/sys_user?sysparm_limit=1'.format(instance)

    # Prepare auth header
    auth_string = '{}:{}'.format(username, password)
    auth_bytes = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')

    headers = {
        'Authorization': 'Basic {}'.format(auth_bytes),
        'Accept': 'application/json'
    }

    req = Request(url, headers=headers)

    try:
        ssl_context = ssl.create_default_context()
        urlopen(req, context=ssl_context, timeout=15)
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
    python3 snow_setup.py --interactive

    # Command line mode
    python3 snow_setup.py --instance your-instance --username svc_splunk --password 'YOUR_PASSWORD'

    # Using environment variables
    export SNOW_INSTANCE=your-instance
    export SNOW_USERNAME=svc_splunk
    export SNOW_PASSWORD=YOUR_PASSWORD
    python3 snow_setup.py

Note: This script must be run using Splunk's Python interpreter:
    $SPLUNK_HOME/bin/splunk cmd python3 bin/snow_setup.py [options]
        """
    )

    parser.add_argument('--instance', '-i', help='ServiceNow instance name (e.g., your-instance)')
    parser.add_argument('--username', '-u', help='ServiceNow username')
    parser.add_argument('--password', '-p', help='ServiceNow password')
    parser.add_argument('--account-name', '-a', default='servicenow',
                        help='Splunk account stanza name (default: servicenow)')
    parser.add_argument('--splunkd-host', default='localhost', help='splunkd host (default: localhost)')
    parser.add_argument('--splunkd-port', type=int, default=8089, help='splunkd management port (default: 8089)')
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
            instance = input("\nServiceNow Instance Name (e.g., your-instance): ").strip()
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

    # Authenticate with Splunk
    print("\nAuthenticating with Splunk...")
    try:
        ctx = connect_splunk(args.splunkd_host, args.splunkd_port)
        print("✓ Splunk authentication successful")
    except Exception as e:
        print("✗ {}".format(str(e)))
        sys.exit(1)

    # Store the account via the app's REST handler (same path as the UI)
    print("\nStoring account via TA-gen_ai_cim configuration endpoint...")
    try:
        result = store_account(ctx, args.account_name, instance, username, password)
        print("✓ Account '{}' {}".format(args.account_name, result))
    except Exception as e:
        print("✗ Error: {}".format(str(e)))
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    print("""
ServiceNow integration is now configured.

To test the integration:
    | makeresults | eval gen_ai.event.id="test_123" | aicase mode=lookup

To create a case:
    index=gen_ai_log earliest=-1h | head 1 | aicase

The "Open Case in ServiceNow" option is now available in the
Event Context menu (right-click) for events with gen_ai.event.id.
""")


if __name__ == '__main__':
    main()
