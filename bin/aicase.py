#!/usr/bin/env python
# encoding=utf-8
"""
aicase.py - Custom Search Command for ServiceNow AI Case Management Integration

This command creates or retrieves ServiceNow AI Case Management records
linked to GenAI events via gen_ai.event.id. When creating a new case,
it fetches full event details and generates an AI-powered summary focused
on anomalies and notable findings using the Splunk AI Toolkit.

Usage:
    | aicase [event_id=<value>] [mode=create|lookup|open] [include_summary=true|false]
    
Parameters:
    event_id        - Optional. Override the gen_ai.event.id from the event
    mode            - Optional. create (default), lookup (check only), open (return URL only)
    include_summary - Optional. Generate AI summary of anomalies (default: true)

Output Fields:
    snow_case_url       - URL to the ServiceNow AI Case record
    snow_case_sys_id    - ServiceNow sys_id of the case
    snow_case_number    - ServiceNow case number (if returned)
    snow_case_status    - Status: created, existing, error
    snow_case_message   - Human-readable status message

AI Summary Features:
    When include_summary=true (default), the case description includes an AI-generated
    summary using Splunk AI Toolkit's | ai command. The summary analyzes the event for:
    - PII detections and types
    - Safety violations
    - Policy blocks
    - Prompt/response anomalies (TF-IDF)
    - Risk level indicators
    - Guardrail triggers
    
    Prerequisites:
    - Splunk AI Toolkit app must be installed
    - AI Toolkit must have an LLM connection configured via Connection Management
    
    If AI Toolkit is unavailable, falls back to a structured summary without AI.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import json
import time
import ssl

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

# Splunk SDK imports
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import splunklib.client as client


@Configuration()
class AICaseCommand(StreamingCommand):
    """
    Custom streaming command to create or lookup ServiceNow AI Case records.
    
    ##Syntax
    
    | aicase [event_id=<value>] [mode=create|lookup|open] [include_summary=true|false]
    
    ##Description
    
    Creates a new ServiceNow AI Case in table sn_ai_case_mgmt_ai_case if no
    mapping exists for the gen_ai.event.id, or returns the existing case URL.
    When creating a case, fetches full event details and generates an AI summary
    focused on anomalies, PII detections, and other notable findings.
    
    ##Examples
    
    Create/open case for events with AI summary:
    | search index=gen_ai_log | aicase
    
    Create case with explicit event_id:
    | makeresults | eval gen_ai.event.id="abc123" | aicase event_id=abc123
    
    Create case without AI summary:
    | search index=gen_ai_log | aicase include_summary=false
    
    Lookup only (no creation):
    | search index=gen_ai_log | aicase mode=lookup
    """
    
    event_id = Option(
        doc='''
        **Syntax:** **event_id=***<string>*
        **Description:** Override the gen_ai.event.id field value''',
        require=False,
        default=None
    )
    
    mode = Option(
        doc='''
        **Syntax:** **mode=***<create|lookup|open>*
        **Description:** Operation mode. create (default), lookup (check only), open (URL only)''',
        require=False,
        default='create',
        validate=validators.Set('create', 'lookup', 'open')
    )
    
    include_summary = Option(
        doc='''
        **Syntax:** **include_summary=***<true|false>*
        **Description:** Generate AI summary of event anomalies and notable findings (default: true)''',
        require=False,
        default=True,
        validate=validators.Boolean()
    )
    
    def __init__(self):
        super(AICaseCommand, self).__init__()
        self._snow_config = None
        self._kv_store = None
        self._service = None
        
    def _get_service(self):
        """Get Splunk service connection"""
        if self._service is None:
            self._service = client.connect(
                token=self.metadata.searchinfo.session_key,
                owner='nobody',
                app='TA-gen_ai_cim'
            )
        return self._service
    
    def _get_snow_config(self):
        """Retrieve ServiceNow configuration from account configuration"""
        if self._snow_config is not None:
            return self._snow_config
            
        try:
            service = self._get_service()
            
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
                    self.logger.info("Found ServiceNow account: {}".format(account_name))
                    break
            except KeyError:
                self.logger.error("Config file ta_gen_ai_cim_account.conf not found")
            except Exception as e:
                self.logger.error("Error reading account config: {}".format(str(e)))
            
            if account_conf is None:
                self._snow_config = {
                    'configured': False,
                    'error': 'No ServiceNow account configured. Go to Configuration page to add an account.'
                }
                return self._snow_config
            
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
            
            self.logger.info("Looking for passwords with realm: {}".format(realm))
            
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
                    self.logger.info("Found credential: name={}, realm={}".format(cred_name, cred_realm))
                    if cred_name == 'password' or 'password' in credential.name:
                        password = clear_password
                        self.logger.info("Found password credential")
                    elif cred_name == 'client_secret' or 'client_secret' in credential.name:
                        client_secret = clear_password
                        self.logger.info("Found client_secret credential")
            
            if not password and auth_type == 'basic':
                self.logger.warning("No password found for account {}".format(account_name))
            
            # Validate configuration based on auth type
            if auth_type in ['oauth_auth_code', 'oauth_client_creds']:
                if not all([instance, client_id, client_secret]):
                    self._snow_config = {
                        'configured': False,
                        'error': 'OAuth credentials incomplete. Check account configuration.'
                    }
                else:
                    self._snow_config = {
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
                    self._snow_config = {
                        'configured': False,
                        'error': 'Basic auth credentials incomplete. Check account configuration.'
                    }
                else:
                    self._snow_config = {
                        'configured': True,
                        'auth_type': 'basic',
                        'instance': instance,
                        'url': url,
                        'username': username,
                        'password': password
                    }
                
        except Exception as e:
            self._snow_config = {
                'configured': False,
                'error': 'Failed to retrieve ServiceNow config: {}'.format(str(e))
            }
            
        return self._snow_config
    
    def _get_oauth_token(self, config):
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
    
    def _get_kv_store_record(self, event_id):
        """Check KV Store for existing mapping"""
        try:
            service = self._get_service()
            collection = service.kvstore['gen_ai_snow_case_map']
            
            # Query by event_id
            query = json.dumps({'event_id': event_id})
            results = collection.data.query(query=query)
            
            if results and len(results) > 0:
                return results[0]
            return None
            
        except Exception as e:
            self.logger.error("KV Store lookup failed: {}".format(str(e)))
            return None
    
    def _save_kv_store_record(self, event_id, sys_id, sn_instance, username):
        """Save mapping to KV Store"""
        try:
            service = self._get_service()
            collection = service.kvstore['gen_ai_snow_case_map']
            
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
            
        except Exception as e:
            self.logger.error("KV Store save failed: {}".format(str(e)))
            return False
    
    def _make_snow_request(self, method, url, data=None, config=None):
        """Make HTTP request to ServiceNow REST API"""
        import base64
        
        if config is None:
            config = self._get_snow_config()
            
        if not config.get('configured'):
            raise Exception(config.get('error', 'ServiceNow not configured'))
        
        # Construct full URL
        base_url = 'https://{}.service-now.com'.format(config['instance'])
        full_url = base_url + url
        
        # Prepare request headers
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Set authentication based on auth type
        auth_type = config.get('auth_type', 'basic')
        
        if auth_type == 'oauth':
            # OAuth 2.0 Bearer token
            access_token = self._get_oauth_token(config)
            headers['Authorization'] = 'Bearer {}'.format(access_token)
        else:
            # Basic authentication
            auth_string = '{}:{}'.format(config['username'], config['password'])
            if sys.version_info[0] >= 3:
                auth_bytes = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
            else:
                auth_bytes = base64.b64encode(auth_string)
            headers['Authorization'] = 'Basic {}'.format(auth_bytes)
        
        # Prepare data
        body = None
        if data is not None:
            body = json.dumps(data)
            if sys.version_info[0] >= 3:
                body = body.encode('utf-8')
        
        # Create request
        req = Request(full_url, data=body, headers=headers)
        if method.upper() != 'POST' and body is not None:
            req.get_method = lambda: method.upper()
        
        # Make request with SSL context
        try:
            # Create SSL context that handles certificates properly
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
    
    def _get_today_date(self):
        """Get today's date in ServiceNow format (YYYY-MM-DD)"""
        import datetime
        return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')
    
    def _get_splunk_event_url(self, event_id):
        """Build a URL to view the event in Splunk"""
        # Get Splunk web URL from server info if available, otherwise use placeholder
        try:
            service = self._get_service()
            server_info = service.info
            # Default to localhost - in production this would be configured
            splunk_host = 'localhost:8000/'
        except Exception:
            splunk_host = 'localhost:8000/'
        
        # Build search URL to find the event
        # Format: search index=gen_ai_log gen_ai.event.id=<value>
        search_query = 'search index=gen_ai_log gen_ai.event.id={}'.format(event_id)
        encoded_query = quote(search_query, safe='')
        
        return 'http://{}en-US/app/search/search?q={}'.format(splunk_host, encoded_query)
    
    def _fetch_event_details(self, event_id):
        """Fetch full event details from Splunk for the given event_id.
        
        Returns a dictionary with all gen_ai.* fields from the event.
        
        Note: Multiple events may share the same gen_ai.event.id (e.g., the main
        conversation event plus PII/TF-IDF scoring events). This method aggregates
        fields from all related events using stats to ensure we capture both the
        prompt/response content and detection scores.
        """
        try:
            service = self._get_service()
            
            # Aggregate fields from all events with this event_id
            # This ensures we get prompt/response from main event AND scores from scoring events
            search_query = '''search index=gen_ai_log gen_ai.event.id="{}" 
                | stats 
                    latest(gen_ai.input.messages) as gen_ai.input.messages,
                    latest(gen_ai.output.messages) as gen_ai.output.messages,
                    latest(gen_ai.prompt) as gen_ai.prompt,
                    latest(gen_ai.response) as gen_ai.response,
                    latest(input_messages) as input_messages,
                    latest(output_messages) as output_messages,
                    latest(gen_ai.app.name) as gen_ai.app.name,
                    latest(gen_ai.service.name) as gen_ai.service.name,
                    latest(service.name) as service.name,
                    latest(gen_ai.request.model) as gen_ai.request.model,
                    latest(gen_ai.pii.detected) as gen_ai.pii.detected,
                    latest(gen_ai.pii.types) as gen_ai.pii.types,
                    latest(gen_ai.pii.ml_detected) as gen_ai.pii.ml_detected,
                    latest(gen_ai.pii.confidence) as gen_ai.pii.confidence,
                    latest(gen_ai.pii.risk_score) as gen_ai.pii.risk_score,
                    latest(gen_ai.safety.violated) as gen_ai.safety.violated,
                    latest(gen_ai.safety.category) as gen_ai.safety.category,
                    latest(gen_ai.policy.blocked) as gen_ai.policy.blocked,
                    latest(gen_ai.policy.name) as gen_ai.policy.name,
                    latest(gen_ai.prompt.is_anomaly) as gen_ai.prompt.is_anomaly,
                    latest(gen_ai.prompt.anomaly_score) as gen_ai.prompt.anomaly_score,
                    latest(gen_ai.response.is_anomaly) as gen_ai.response.is_anomaly,
                    latest(gen_ai.response.anomaly_score) as gen_ai.response.anomaly_score,
                    latest(gen_ai.tfidf.risk_level) as gen_ai.tfidf.risk_level,
                    latest(gen_ai.guardrail.triggered) as gen_ai.guardrail.triggered,
                    latest(gen_ai.guardrail.name) as gen_ai.guardrail.name,
                    latest(_time) as _time
                by gen_ai.event.id'''.format(event_id)
            
            # Run a oneshot search
            kwargs_oneshot = {
                'earliest_time': '-7d',
                'latest_time': 'now',
                'output_mode': 'json',
                'count': 1
            }
            
            search_results = service.jobs.oneshot(search_query, **kwargs_oneshot)
            
            # Parse JSON results
            if sys.version_info[0] >= 3:
                results_data = search_results.read().decode('utf-8')
            else:
                results_data = search_results.read()
            
            results_json = json.loads(results_data)
            
            if results_json.get('results') and len(results_json['results']) > 0:
                event = results_json['results'][0]
                self.logger.info("Fetched aggregated event details for event_id={}".format(event_id))
                return event
            else:
                self.logger.warning("No event found for event_id={}".format(event_id))
                return {}
                
        except Exception as e:
            self.logger.error("Failed to fetch event details: {}".format(str(e)))
            return {}
    
    def _escape_spl_string(self, text):
        """Escape a string for safe use in SPL eval statements.
        
        Handles quotes, backslashes, and special characters that could
        break SPL parsing.
        """
        if text is None:
            return ''
        text = str(text)
        # Escape backslashes first, then quotes
        text = text.replace('\\', '\\\\')
        text = text.replace('"', '\\"')
        # Replace newlines with spaces to avoid SPL parsing issues
        text = text.replace('\n', ' ').replace('\r', ' ')
        # Replace tabs with spaces
        text = text.replace('\t', ' ')
        return text
    
    def _build_event_context(self, event_details, event_id):
        """Build a structured text context from event details for summarization.
        
        Returns a formatted string containing event metadata, detected issues,
        user prompt, and AI response suitable for AI summarization.
        """
        # Build context from event details focusing on anomaly-related fields
        anomaly_fields = []
        
        # Check for PII detection
        pii_detected = event_details.get('gen_ai.pii.detected', 'false')
        if str(pii_detected).lower() == 'true':
            pii_types = event_details.get('gen_ai.pii.types', 'unknown types')
            anomaly_fields.append("PII DETECTED: {}".format(pii_types))
        
        # Check for safety violations
        safety_violated = event_details.get('gen_ai.safety.violated', 'false')
        if str(safety_violated).lower() == 'true':
            safety_category = event_details.get('gen_ai.safety.category', 'unspecified')
            anomaly_fields.append("SAFETY VIOLATION: {}".format(safety_category))
        
        # Check for policy blocks
        policy_blocked = event_details.get('gen_ai.policy.blocked', 'false')
        if str(policy_blocked).lower() == 'true':
            policy_name = event_details.get('gen_ai.policy.name', 'unspecified policy')
            anomaly_fields.append("POLICY BLOCKED: {}".format(policy_name))
        
        # Check for prompt anomalies (TF-IDF)
        prompt_anomaly = event_details.get('gen_ai.prompt.is_anomaly', 'false')
        if str(prompt_anomaly).lower() == 'true':
            prompt_score = event_details.get('gen_ai.prompt.anomaly_score', 'N/A')
            anomaly_fields.append("PROMPT ANOMALY DETECTED (score: {})".format(prompt_score))
        
        # Check for response anomalies (TF-IDF)
        response_anomaly = event_details.get('gen_ai.response.is_anomaly', 'false')
        if str(response_anomaly).lower() == 'true':
            response_score = event_details.get('gen_ai.response.anomaly_score', 'N/A')
            anomaly_fields.append("RESPONSE ANOMALY DETECTED (score: {})".format(response_score))
        
        # Check TF-IDF risk level
        risk_level = event_details.get('gen_ai.tfidf.risk_level', '')
        if risk_level and risk_level.upper() in ['HIGH', 'CRITICAL']:
            anomaly_fields.append("HIGH RISK LEVEL: {}".format(risk_level))
        
        # Check for guardrail triggers
        guardrail_triggered = event_details.get('gen_ai.guardrail.triggered', 'false')
        if str(guardrail_triggered).lower() == 'true':
            guardrail_name = event_details.get('gen_ai.guardrail.name', 'unspecified')
            anomaly_fields.append("GUARDRAIL TRIGGERED: {}".format(guardrail_name))
        
        # Extract metadata
        service_name = event_details.get('gen_ai.app.name', event_details.get('gen_ai.service.name', 'Unknown'))
        model_name = event_details.get('gen_ai.request.model', 'Unknown')
        
        # Extract user prompt and system response from event
        user_prompt = event_details.get('gen_ai.input.messages', 
                      event_details.get('gen_ai.prompt', 
                      event_details.get('input_messages', '')))
        system_response = event_details.get('gen_ai.output.messages',
                          event_details.get('gen_ai.response',
                          event_details.get('output_messages', '')))
        
        # Truncate long content for the summary request (keep first 1000 chars)
        if user_prompt and len(str(user_prompt)) > 1000:
            user_prompt = str(user_prompt)[:1000] + '...[truncated]'
        if system_response and len(str(system_response)) > 1000:
            system_response = str(system_response)[:1000] + '...[truncated]'
        
        # Build the context text
        context_parts = [
            "GenAI Event Details:",
            "- Event ID: {}".format(event_id),
            "- Service: {}".format(service_name),
            "- Model: {}".format(model_name),
            "- Timestamp: {}".format(event_details.get('_time', 'Unknown')),
            "",
            "Detected Issues:",
            '\n'.join(anomaly_fields) if anomaly_fields else 'No anomalies detected',
            "",
            "User Prompt:",
            str(user_prompt) if user_prompt else 'Not available',
            "",
            "AI Response:",
            str(system_response) if system_response else 'Not available'
        ]
        
        return '\n'.join(context_parts), anomaly_fields
    
    def _run_ai_toolkit_summary(self, event_context, event_id):
        """Run AI Toolkit's | ai command to generate a summary.
        
        Uses Splunk's AI Toolkit app to summarize the event context via
        a SPL subsearch with the | ai command.
        
        Args:
            event_context: Formatted text containing event details
            event_id: The gen_ai.event.id for logging
            
        Returns:
            str: AI-generated summary or None if AI Toolkit fails
        """
        try:
            service = self._get_service()
            
            # Build the AI summarization prompt with the event data embedded directly
            # IMPORTANT: Frame as security/compliance log review to avoid LLM safety guardrails
            # when reviewing medical, financial, or other sensitive content
            prompt_prefix = (
                "CONTEXT: You are a security/compliance analyst reviewing GenAI application "
                "telemetry logs in Splunk for a ServiceNow case. This is audit work, not a "
                "request for advice. "
                "TASK: Analyze this LOG ENTRY and provide: "
                "1. A concise 2-3 sentence summary highlighting key anomalies and concerns "
                "(focus on actionable insights for security/compliance team). "
                "2. A brief 1-sentence summary of what the end user asked (Prompt Summary). "
                "3. A brief 1-sentence summary of the AI system response (Response Summary). "
                "Note any PII, PHI, or policy concerns found in the log data. "
                "Format your response EXACTLY as: [Summary] then Prompt Summary: [text] then Response Summary: [text] "
                "LOG DATA: "
            )
            # Build the full prompt and escape ONCE for SPL embedding
            full_prompt = prompt_prefix + event_context
            full_prompt_escaped = self._escape_spl_string(full_prompt)
            
            # Build SPL query using AI Toolkit's | ai command
            # Embed the full prompt directly in the SPL
            search_query = '| makeresults | ai prompt="' + full_prompt_escaped + '" | table ai_result_1'
            
            self.logger.info("Running AI Toolkit summarization for event_id={}".format(event_id))
            self.logger.info("AI Toolkit search query (first 200 chars): {}".format(search_query[:200]))
            
            # Run search job with longer timeout for LLM API calls
            # Use normal job instead of oneshot for better control
            kwargs_search = {
                'earliest_time': '-1m',
                'latest_time': 'now',
                'exec_mode': 'blocking',  # Wait for completion
                'timeout': 120  # 2 minute timeout for LLM calls
            }
            
            job = service.jobs.create(search_query, **kwargs_search)
            
            # Wait for job to complete (blocking mode should handle this, but be explicit)
            while not job.is_done():
                time.sleep(0.5)
            
            # Get results
            results_stream = job.results(output_mode='json', count=10)
            if sys.version_info[0] >= 3:
                results_data = results_stream.read().decode('utf-8')
            else:
                results_data = results_stream.read()
            
            # Clean up job
            job.cancel()
            
            self.logger.info("AI Toolkit search completed, parsing results")
            results_json = json.loads(results_data)
            
            # Log the raw results for debugging
            self.logger.info("AI Toolkit raw results (first 500 chars): {}".format(results_data[:500] if len(results_data) > 500 else results_data))
            
            if results_json.get('results') and len(results_json['results']) > 0:
                # The | ai command outputs to ai_result_1 field
                result_row = results_json['results'][0]
                self.logger.info("AI Toolkit result keys: {}".format(list(result_row.keys())))
                response = result_row.get('ai_result_1', '')
                if response:
                    self.logger.info("AI Toolkit summary generated successfully for event_id={}".format(event_id))
                    return response.strip()
                else:
                    # Check if there's an error message in the results
                    error_field = result_row.get('_error', result_row.get('error', ''))
                    if error_field:
                        self.logger.warning("AI Toolkit returned error: {}".format(error_field))
                    # Log all keys and values for debugging
                    self.logger.warning("AI Toolkit result row contents: {}".format(result_row))
            else:
                self.logger.warning("AI Toolkit returned no results. Full response: {}".format(results_data))
            
            self.logger.warning("AI Toolkit returned empty response for event_id={}".format(event_id))
            return None
            
        except Exception as e:
            error_msg = str(e)
            # Log full exception details for debugging
            self.logger.error("AI Toolkit exception type: {}".format(type(e).__name__))
            self.logger.error("AI Toolkit exception message: {}".format(error_msg))
            # Check for common AI Toolkit errors
            if 'Unknown search command' in error_msg or "'ai'" in error_msg:
                self.logger.warning("AI Toolkit not installed or | ai command unavailable: {}".format(error_msg))
            elif 'connection' in error_msg.lower():
                self.logger.warning("AI Toolkit connection not configured: {}".format(error_msg))
            elif 'permission' in error_msg.lower() or 'capability' in error_msg.lower():
                self.logger.warning("AI Toolkit permission denied - user may need apply_ai_commander_command capability: {}".format(error_msg))
            else:
                self.logger.error("AI Toolkit summarization failed: {}".format(error_msg))
            return None
    
    def _generate_ai_summary(self, event_details, event_id):
        """Generate a concise AI summary focused on anomalies and notable findings.
        
        Uses Splunk AI Toolkit's | ai command to analyze event details and produce
        a summary highlighting any anomalies, PII detections, safety violations,
        or other concerning indicators.
        
        Falls back to a structured summary if AI Toolkit is unavailable.
        """
        if not event_details:
            return "Unable to generate summary: No event details available."
        
        try:
            # Build the event context for summarization
            event_context, anomaly_fields = self._build_event_context(event_details, event_id)
            
            # Try AI Toolkit summarization first
            ai_summary = self._run_ai_toolkit_summary(event_context, event_id)
            
            if ai_summary:
                self.logger.info("Generated AI summary using Splunk AI Toolkit")
                return ai_summary
            
            # Fallback to structured summary if AI Toolkit fails
            self.logger.warning("AI Toolkit unavailable, using fallback summary")
            return self._generate_fallback_summary(event_details, anomaly_fields)
            
        except Exception as e:
            self.logger.error("Failed to generate AI summary: {}".format(str(e)))
            return "Summary generation failed: {}".format(str(e))
    
    def _generate_fallback_summary(self, event_details, anomaly_fields=None):
        """Generate a structured summary without AI when API is unavailable"""
        service_name = event_details.get('gen_ai.app.name', event_details.get('gen_ai.service.name', 'Unknown'))
        model_name = event_details.get('gen_ai.request.model', 'Unknown')
        
        if anomaly_fields is None:
            # Build anomaly fields if not provided
            anomaly_fields = []
            if str(event_details.get('gen_ai.pii.detected', 'false')).lower() == 'true':
                anomaly_fields.append("PII detected")
            if str(event_details.get('gen_ai.safety.violated', 'false')).lower() == 'true':
                anomaly_fields.append("Safety violation")
            if str(event_details.get('gen_ai.policy.blocked', 'false')).lower() == 'true':
                anomaly_fields.append("Policy blocked")
            if str(event_details.get('gen_ai.prompt.is_anomaly', 'false')).lower() == 'true':
                anomaly_fields.append("Prompt anomaly")
            if str(event_details.get('gen_ai.response.is_anomaly', 'false')).lower() == 'true':
                anomaly_fields.append("Response anomaly")
        
        # Build the main summary
        if anomaly_fields:
            main_summary = "This GenAI event from {} ({}) has the following concerns: {}. Recommend review by security/compliance team.".format(
                service_name,
                model_name,
                '; '.join(anomaly_fields)
            )
        else:
            main_summary = "This GenAI event from {} ({}) completed without detected anomalies. Created for tracking purposes.".format(
                service_name,
                model_name
            )
        
        # Add prompt/response indicators
        user_prompt = event_details.get('gen_ai.input.messages', 
                      event_details.get('gen_ai.prompt', ''))
        system_response = event_details.get('gen_ai.output.messages',
                          event_details.get('gen_ai.response', ''))
        
        prompt_summary = "Prompt Summary: User interaction recorded (AI summary unavailable)"
        response_summary = "Response Summary: AI response recorded (AI summary unavailable)"
        
        if user_prompt:
            # Truncate for display
            prompt_preview = str(user_prompt)[:100] + '...' if len(str(user_prompt)) > 100 else str(user_prompt)
            prompt_summary = "Prompt Summary: {}".format(prompt_preview)
        
        if system_response:
            response_preview = str(system_response)[:100] + '...' if len(str(system_response)) > 100 else str(system_response)
            response_summary = "Response Summary: {}".format(response_preview)
        
        return "{}\n\n{}\n{}".format(main_summary, prompt_summary, response_summary)
    
    def _create_snow_case(self, event_id, config, service_name=None, event_details=None, ai_summary=None):
        """Create a new AI Case in ServiceNow with AI-generated summary.
        
        Args:
            event_id: The gen_ai.event.id
            config: ServiceNow configuration
            service_name: Optional service name
            event_details: Optional dict of full event details
            ai_summary: Optional AI-generated summary text
        """
        # Build Splunk event link
        splunk_url = self._get_splunk_event_url(event_id)
        
        # Extract event details for the description
        if event_details:
            service_name = service_name or event_details.get('gen_ai.app.name') or event_details.get('gen_ai.service.name') or 'Unknown'
            model_name = event_details.get('gen_ai.request.model', 'Unknown')
            timestamp = event_details.get('_time', 'Unknown')
        else:
            model_name = 'Unknown'
            timestamp = 'Unknown'
        
        # Build case name with service name if available
        if service_name and service_name != 'Unknown':
            case_name = 'Splunk Event for gen_ai.event.id: {} from {}'.format(event_id, service_name)
        else:
            case_name = 'Splunk Event for gen_ai.event.id: {}'.format(event_id)
        
        # Build the case description with new format
        description_parts = []
        
        # AI Summary section
        description_parts.append('=== AI SUMMARY ===')
        if ai_summary:
            description_parts.append(ai_summary)
        else:
            description_parts.append('No summary available.')
        description_parts.append('')
        
        # Event Details section
        description_parts.append('=== EVENT DETAILS ===')
        description_parts.append('Event ID: {}'.format(event_id))
        description_parts.append('Service: {}'.format(service_name or 'Unknown'))
        description_parts.append('Model: {}'.format(model_name))
        description_parts.append('Timestamp: {}'.format(timestamp))
        description_parts.append('')
        
        # Splunk Link section
        description_parts.append('=== SPLUNK LINK ===')
        description_parts.append('View Original Event in Splunk:')
        description_parts.append(splunk_url)
        
        description = '\n'.join(description_parts)
        
        case_data = {
            'short_description': case_name,
            'type': 'AI Case',
            'description': description,
            'u_source': 'Splunk TA-gen_ai_cim'
        }
        
        # POST to ServiceNow Table API
        url = '/api/now/table/sn_ai_case_mgmt_ai_case'
        
        result = self._make_snow_request('POST', url, data=case_data, config=config)
        
        if result and 'result' in result:
            return result['result']
        return result
    
    def _get_case_url(self, sys_id, instance):
        """Build the ServiceNow case URL using AI Control Tower format"""
        return 'https://{}.service-now.com/now/ai-control-tower/record/sn_ai_case_mgmt_ai_case/{}'.format(
            instance, sys_id
        )
    
    def stream(self, records):
        """Process each record through the command"""
        
        # Get ServiceNow config once
        snow_config = self._get_snow_config()
        
        for record in records:
            # Get event_id from parameter override or event field
            evt_id = self.event_id
            if evt_id is None:
                # Try multiple field name formats
                evt_id = record.get('gen_ai.event.id') or \
                         record.get('gen_ai_event_id') or \
                         record.get('event_id')
            
            # Initialize output fields
            record['snow_case_url'] = ''
            record['snow_case_sys_id'] = ''
            record['snow_case_number'] = ''
            record['snow_case_status'] = ''
            record['snow_case_message'] = ''
            
            if not evt_id:
                record['snow_case_status'] = 'error'
                record['snow_case_message'] = 'No gen_ai.event.id found in event'
                yield record
                continue
            
            # Check if ServiceNow is configured
            if not snow_config.get('configured'):
                record['snow_case_status'] = 'error'
                record['snow_case_message'] = snow_config.get('error', 'ServiceNow not configured')
                yield record
                continue
            
            try:
                # Check KV Store for existing mapping
                existing = self._get_kv_store_record(evt_id)
                
                if existing:
                    # Case already exists
                    sys_id = existing.get('sys_id')
                    instance = existing.get('sn_instance', snow_config['instance'])
                    
                    record['snow_case_url'] = self._get_case_url(sys_id, instance)
                    record['snow_case_sys_id'] = sys_id
                    record['snow_case_status'] = 'existing'
                    record['snow_case_message'] = 'Existing case found for event_id={}'.format(evt_id)
                    
                elif self.mode == 'lookup':
                    # Lookup only mode - no case found
                    record['snow_case_status'] = 'not_found'
                    record['snow_case_message'] = 'No existing case for event_id={}'.format(evt_id)
                    
                else:
                    # Create new case
                    # Get service name from record
                    service_name = record.get('gen_ai.service.name') or \
                                   record.get('gen_ai.app.name') or \
                                   record.get('service_name') or \
                                   record.get('service.name')
                    
                    # Fetch full event details and generate AI summary
                    event_details = self._fetch_event_details(evt_id)
                    
                    ai_summary = None
                    if self.include_summary:
                        ai_summary = self._generate_ai_summary(event_details, evt_id)
                        self.logger.info("Generated AI summary for event_id={}".format(evt_id))
                    
                    case_result = self._create_snow_case(
                        evt_id, 
                        snow_config, 
                        service_name=service_name,
                        event_details=event_details,
                        ai_summary=ai_summary
                    )
                    
                    if case_result:
                        sys_id = case_result.get('sys_id')
                        case_number = case_result.get('number', case_result.get('short_description', ''))
                        
                        # Save mapping to KV Store
                        self._save_kv_store_record(
                            evt_id,
                            sys_id,
                            snow_config['instance'],
                            snow_config['username']
                        )
                        
                        record['snow_case_url'] = self._get_case_url(sys_id, snow_config['instance'])
                        record['snow_case_sys_id'] = sys_id
                        record['snow_case_number'] = case_number
                        record['snow_case_status'] = 'created'
                        record['snow_case_message'] = 'New case created for event_id={}'.format(evt_id)
                    else:
                        record['snow_case_status'] = 'error'
                        record['snow_case_message'] = 'ServiceNow returned empty response'
                        
            except Exception as e:
                record['snow_case_status'] = 'error'
                record['snow_case_message'] = str(e)
                self.logger.error("aicase command error: {}".format(str(e)))
            
            yield record


# Entry point
if __name__ == '__main__':
    dispatch(AICaseCommand, sys.argv, sys.stdin, sys.stdout, __name__)
