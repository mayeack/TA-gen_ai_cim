#!/usr/bin/env python
# encoding=utf-8
"""
genaiscore.py - Custom Search Command for GenAI Scoring Pipelines

Streaming command that reads a pipeline configuration from
ta_gen_ai_cim_genai_scoring.conf, sends each event to the default LLM
configured in Splunk AI Toolkit's Connection Management, parses the
structured JSON response, and enriches events with scoring fields.

The LLM is called directly via HTTP rather than through a sub-search,
which avoids SPL string-escaping issues with event data.

Usage:
    | genaiscore pipeline=pipeline_1

Parameters:
    pipeline - Required. The pipeline stanza name (pipeline_1 through pipeline_10)

Output Fields (where <name> is the pipeline name from config):
    gen_ai.<name>.risk_score       - Float 0.0-1.0, risk probability
    gen_ai.<name>.genai_detected   - "true"/"false", detection flag
    gen_ai.<name>.confidence       - very_high, high, medium, low, very_low
    gen_ai.<name>.explanation      - LLM reasoning text
    gen_ai.<name>.types            - Multi-value list of detected sub-types
    genai_scoring_status           - "success" or "error"
    genai_scoring_pipeline         - Pipeline name for downstream filtering
    genai_scoring_error            - Error message if status is "error"

Prerequisites:
    - Splunk AI Toolkit (ML Toolkit) must be installed
    - AI Toolkit must have an LLM connection configured via Connection Management
    - A default model must be selected in Connection Management
    - User must have apply_ai_commander_command capability

Supported LLM Providers:
    OpenAI, Azure OpenAI, Groq, Ollama, Anthropic, Gemini

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import os
import sys
import json
import re
import ssl
import logging
import time

app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

debug_log_path = os.path.join(app_root, 'genaiscore_debug.log')
debug_logger = logging.getLogger('genaiscore_debug')
debug_logger.setLevel(logging.DEBUG)
_fh = logging.FileHandler(debug_log_path)
_fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
debug_logger.addHandler(_fh)
try:
    os.chmod(debug_log_path, 0o666)
except OSError:
    pass

lib_path = os.path.join(app_root, 'lib')
if lib_path not in sys.path:
    sys.path.insert(0, lib_path)

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import splunklib.client as client

MLTK_APP = 'Splunk_ML_Toolkit'
KV_COLLECTION = 'mltk_ai_commander_collection'
SECRET_REALM = 'mltk_llm_tokens'


@Configuration()
class GenAIScoreCommand(StreamingCommand):
    """
    Streaming command that scores GenAI events using an LLM via AI Toolkit.

    ##Syntax

    | genaiscore pipeline=<pipeline_stanza>

    ##Description

    Reads scoring pipeline configuration (system prompt, pipeline-specific prompt,
    pipeline name) and sends each event to the default LLM. Parses the JSON
    response and maps it to gen_ai.<name>.* fields.

    ##Examples

    Score events using pipeline 1:
    | search index=gen_ai_log | genaiscore pipeline=pipeline_1
    """

    pipeline = Option(
        doc='''
        **Syntax:** **pipeline=***<pipeline_stanza>*
        **Description:** Pipeline stanza name from ta_gen_ai_cim_genai_scoring.conf (pipeline_1 through pipeline_10)''',
        require=True
    )

    def __init__(self):
        super(GenAIScoreCommand, self).__init__()
        self._service = None
        self._mltk_service = None
        self._pipeline_config = None
        self._system_prompt = None
        self._llm_config = None
        self._api_key = None

    def _get_service(self):
        if self._service is None:
            self._service = client.connect(
                token=self.metadata.searchinfo.session_key,
                owner='nobody',
                app='TA-gen_ai_cim'
            )
        return self._service

    def _get_mltk_service(self):
        """Get a Splunk service connected to the ML Toolkit app."""
        if self._mltk_service is None:
            self._mltk_service = client.connect(
                token=self.metadata.searchinfo.session_key,
                owner='nobody',
                app=MLTK_APP
            )
        return self._mltk_service

    def _load_pipeline_config(self):
        """Load pipeline and global settings from ta_gen_ai_cim_genai_scoring.conf."""
        if self._pipeline_config is not None:
            return

        try:
            service = self._get_service()
            scoring_conf = service.confs['ta_gen_ai_cim_genai_scoring']

            for stanza in scoring_conf:
                if stanza.name == 'settings':
                    self._system_prompt = stanza.content.get('system_prompt', '')
                elif stanza.name == self.pipeline:
                    self._pipeline_config = {
                        'enabled': stanza.content.get('enabled', '0'),
                        'name': stanza.content.get('pipeline_name', ''),
                        'prompt': stanza.content.get('prompt', '')
                    }

            if self._pipeline_config is None:
                raise ValueError("Pipeline stanza '{}' not found".format(self.pipeline))

            if not self._pipeline_config.get('name'):
                raise ValueError("Pipeline '{}' has no name configured".format(self.pipeline))

            if not self._pipeline_config.get('prompt'):
                raise ValueError("Pipeline '{}' has no prompt configured".format(self.pipeline))

            if self._system_prompt is None:
                self._system_prompt = ''

        except Exception as e:
            self.logger.error("Failed to load pipeline config: {}".format(str(e)))
            raise

    def _decode_model_key(self, encoded_name):
        """Decode hex-encoded model key from KV store."""
        try:
            return bytes.fromhex(encoded_name).decode('utf-8')
        except (ValueError, UnicodeDecodeError):
            return encoded_name.replace('__DOT__', '.')

    @staticmethod
    def _ensure_dict(val):
        """Ensure a value is a dict, parsing JSON strings if needed."""
        if isinstance(val, dict):
            return val
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass
        return None

    @staticmethod
    def _is_truthy(val):
        """Check if a value is truthy, handling booleans, strings, etc."""
        if val is True:
            return True
        if isinstance(val, str):
            return val.lower() in ('true', '1', 'yes')
        return bool(val)

    _FIELD_ALIASES = {
        'set_as_default': ['set_as_default', 'Set as default', 'Set as Default'],
        'endpoint': ['endpoint', 'Endpoint'],
        'access_token': ['access_token', 'Access Token'],
        'request_timeout': ['request_timeout', 'Request Timeout'],
        'max_tokens': ['max_tokens', 'Max Tokens'],
        'response_variability': ['response_variability', 'Response Variability'],
        'maximum_result_rows': ['maximum_result_rows', 'Maximum Result Rows'],
        'is_model_saved': ['is_model_saved'],
        'is_saved': ['is_saved'],
        'connection_name': ['connection_name', 'Connection Name'],
        'azure_openai_version': ['azure_openai_version', 'Azure OpenAI Version',
                                 'API Version', 'api_version'],
    }

    def _get_field(self, obj, canonical_key, default=None):
        """Get a field from an AI Toolkit config object.

        Handles both programmatic keys (set_as_default) and display-label
        keys (Set as default) that vary by AI TK version.  If the value
        is a {label, value, type} wrapper, extracts the inner value.
        """
        candidates = self._FIELD_ALIASES.get(canonical_key, [canonical_key])
        for key in candidates:
            raw = obj.get(key)
            if raw is None:
                continue
            raw_dict = self._ensure_dict(raw)
            if raw_dict is not None and 'value' in raw_dict:
                return raw_dict['value']
            if not isinstance(raw, dict):
                return raw
            return raw
        return default

    def _get_llm_config(self):
        """Read LLM configuration from AI Toolkit's KV store.

        Finds the default provider and model, reads endpoint URL and model
        settings.  Result is cached for the lifetime of the command.
        """
        if self._llm_config is not None:
            return self._llm_config

        service = self._get_mltk_service()

        try:
            kv = service.kvstore[KV_COLLECTION]
            records = kv.data.query()
        except Exception as e:
            raise ValueError(
                "Cannot read AI Toolkit config from KV store '{}': {}".format(
                    KV_COLLECTION, str(e)))

        if not records:
            raise ValueError(
                "No AI Toolkit LLM configuration found. "
                "Please configure a connection in AI Toolkit Connection Management.")

        config = records[0] if isinstance(records, list) else records

        debug_logger.info(
            "KV store record keys: %s",
            [k for k in config.keys()])

        skip_keys = {'_key', '_user', 'connection_type', 'metadata'}

        for provider_name, provider_raw in config.items():
            if provider_name in skip_keys:
                continue

            provider_data = self._ensure_dict(provider_raw)
            if provider_data is None:
                continue

            models_raw = provider_data.get('models')
            models = self._ensure_dict(models_raw)
            if models is None:
                debug_logger.debug(
                    "Provider '%s': no models dict (type=%s)",
                    provider_name, type(models_raw).__name__)
                continue

            debug_logger.info(
                "Provider '%s': %d model(s) found",
                provider_name, len(models))

            for encoded_model, model_raw in models.items():
                model_data = self._ensure_dict(model_raw)
                if model_data is None:
                    continue

                model_name = self._decode_model_key(encoded_model)

                default_val = self._get_field(model_data, 'set_as_default', False)

                debug_logger.info(
                    "  Model '%s' (key=%s): set_as_default=%s (type=%s)",
                    model_name, encoded_model[:16],
                    default_val, type(default_val).__name__)

                if self._is_truthy(default_val):
                    endpoint = self._get_field(provider_data, 'endpoint', '')
                    max_tokens_raw = self._get_field(model_data, 'max_tokens', 1000)
                    temp_raw = self._get_field(model_data, 'response_variability', 0.1)
                    timeout_raw = self._get_field(provider_data, 'request_timeout', 120)

                    self._llm_config = {
                        'provider': provider_name,
                        'model': model_name,
                        'endpoint': endpoint,
                        'max_tokens': int(max_tokens_raw),
                        'temperature': float(temp_raw),
                        'timeout': float(timeout_raw),
                        'provider_data': provider_data,
                    }

                    debug_logger.info(
                        "Default LLM found: provider=%s model=%s endpoint=%s",
                        provider_name, model_name,
                        endpoint[:60] if endpoint else 'none')

                    return self._llm_config

        diag_parts = []
        diag_parts.append("records={}".format(
            len(records) if isinstance(records, list) else 1))
        diag_parts.append("top_keys={}".format(
            [k for k in config.keys()]))
        sample_shown = False
        for pn, pv in config.items():
            if pn in skip_keys:
                continue
            pd = self._ensure_dict(pv)
            if pd is None:
                diag_parts.append("{}=not_dict({})".format(pn, type(pv).__name__))
                continue
            pd_keys = list(pd.keys())
            diag_parts.append("{}_keys={}".format(pn, pd_keys))
            md = self._ensure_dict(pd.get('models'))
            if md is None:
                diag_parts.append("{}=no_models".format(pn))
                continue
            for mk, mv in list(md.items())[:3]:
                mvd = self._ensure_dict(mv)
                if mvd is None:
                    diag_parts.append("{}/{}=not_dict".format(pn, mk[:12]))
                    continue
                mn = self._decode_model_key(mk)
                if not sample_shown:
                    diag_parts.append("SAMPLE {}/{} model_keys={}".format(
                        pn, mn, list(mvd.keys())))
                    sample_shown = True
                df = mvd.get('set_as_default')
                diag_parts.append("{}/{}:default={}({})".format(
                    pn, mn, df, type(df).__name__))

        diag = "; ".join(diag_parts) if diag_parts else "no_providers_found"

        debug_logger.error(
            "No default model found. Diag: %s", diag)

        raise ValueError(
            "No default LLM model configured. Diag: [{}]. "
            "Please set a default model in AI Toolkit Connection Management.".format(
                diag))

    def _get_api_key(self, provider_name):
        """Read API key from Splunk storage passwords."""
        if self._api_key is not None:
            return self._api_key

        service = self._get_mltk_service()

        try:
            for sp in service.storage_passwords:
                if sp.realm == SECRET_REALM and sp.username == provider_name:
                    self._api_key = sp.clear_password
                    return self._api_key
        except Exception as e:
            debug_logger.error("Storage password lookup failed: %s", str(e))
            raise ValueError(
                "Cannot read API key for '{}': {}".format(provider_name, str(e)))

        raise ValueError(
            "No API key found for provider '{}'. "
            "Please save the connection in AI Toolkit Connection Management.".format(
                provider_name))

    def _send_llm_request(self, provider, model, endpoint, api_key, prompt,
                          system_prompt="You are a helpful assistant",
                          max_tokens=1000, temperature=0.1, timeout=120):
        """Make a direct HTTP call to the LLM provider and return the text response."""
        import urllib.request
        import urllib.error

        provider_upper = provider.strip().replace(' ', '')
        provider_lower = provider_upper.lower()

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]

        headers = {'Content-Type': 'application/json'}

        if provider_lower in ('openai', 'groq', 'ollama'):
            url = (endpoint or '').rstrip('/')
            if url.endswith('/chat/completions'):
                pass
            elif provider_lower == 'ollama':
                url = url.rstrip('/') + '/v1/chat/completions'
            else:
                url = url.rstrip('/') + '/chat/completions'
            headers['Authorization'] = 'Bearer {}'.format(api_key)
            body = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }

        elif provider_lower == 'azureopenai':
            url = (endpoint or '').rstrip('/')
            if not url.endswith('/chat/completions'):
                url += '/chat/completions'
            azure_version = self._get_field(
                self._llm_config.get('provider_data', {}),
                'azure_openai_version', '2024-02-01')
            url += '?api-version={}'.format(azure_version)
            headers['api-key'] = api_key
            body = {
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }

        elif provider_lower == 'anthropic':
            url = (endpoint or 'https://api.anthropic.com').rstrip('/')
            if not url.endswith('/messages'):
                url += '/v1/messages'
            headers['x-api-key'] = api_key
            headers['anthropic-version'] = '2023-06-01'
            body = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
                "system": system_prompt,
                "temperature": temperature,
            }

        elif provider_lower == 'gemini':
            base = (endpoint or '').rstrip('/')
            url = '{}/{}:generateContent?key={}'.format(base, model, api_key)
            body = {
                "contents": [
                    {"role": "user", "parts": [{"text": prompt}]}
                ],
                "systemInstruction": {
                    "parts": [{"text": system_prompt}]
                },
                "generationConfig": {
                    "temperature": temperature,
                    "maxOutputTokens": max_tokens,
                },
            }

        else:
            url = (endpoint or '').rstrip('/')
            if not url.endswith('/chat/completions'):
                url += '/chat/completions'
            headers['Authorization'] = 'Bearer {}'.format(api_key)
            body = {
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }

        if not url or url == '/chat/completions':
            raise ValueError(
                "No endpoint URL configured for provider '{}'".format(provider))

        payload = json.dumps(body).encode('utf-8')

        req = urllib.request.Request(url, data=payload, method='POST')
        for k, v in headers.items():
            req.add_header(k, v)

        ctx = ssl.create_default_context()
        if provider_lower == 'ollama' and (
                'localhost' in url or '127.0.0.1' in url):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        debug_logger.info(
            "LLM HTTP request: provider=%s model=%s url=%s body_len=%d",
            provider, model, url[:80], len(payload))

        try:
            resp = urllib.request.urlopen(req, context=ctx, timeout=int(timeout))
            result = json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8', errors='replace')[:500]
            raise ValueError("LLM API HTTP {}: {}".format(e.code, error_body))

        if provider_lower == 'anthropic':
            content = result.get('content', [])
            if content and content[0].get('text'):
                return content[0]['text']
            raise ValueError("Empty response from Anthropic API")

        if provider_lower == 'gemini':
            candidates = result.get('candidates', [])
            if candidates:
                parts = candidates[0].get('content', {}).get('parts', [])
                if parts and parts[0].get('text'):
                    return parts[0]['text']
            raise ValueError("Empty response from Gemini API")

        choices = result.get('choices', [])
        if choices and choices[0].get('message', {}).get('content'):
            return choices[0]['message']['content']

        raise ValueError(
            "Empty LLM response: keys={}".format(list(result.keys())))

    def _call_ai_toolkit(self, system_prompt, prompt_text, event_id):
        """Call the default LLM configured in AI Toolkit Connection Management.

        Returns tuple: (response_text, error_detail)
        On success: (response_text, None)
        On failure: (None, error_description)
        """
        try:
            config = self._get_llm_config()

            provider = config['provider']
            if provider.lower() == 'ollama':
                api_key = 'ollama'
            else:
                api_key = self._get_api_key(provider)

            debug_logger.info(
                "LLM call start: event_id=%s provider=%s model=%s prompt_len=%d",
                event_id, provider, config['model'], len(prompt_text))

            response = self._send_llm_request(
                provider=provider,
                model=config['model'],
                endpoint=config['endpoint'],
                api_key=api_key,
                prompt=prompt_text,
                system_prompt=system_prompt,
                max_tokens=config.get('max_tokens', 1000),
                temperature=config.get('temperature', 0.1),
                timeout=config.get('timeout', 120),
            )

            debug_logger.info(
                "LLM response OK: event_id=%s len=%d first300=%s",
                event_id, len(response), response[:300])

            return (response.strip(), None)

        except Exception as e:
            import traceback
            detail = "LLM call failed: {}".format(str(e)[:500])
            debug_logger.error(detail)
            debug_logger.error(traceback.format_exc())
            return (None, detail)

    @staticmethod
    def _extract_json_object(text):
        """Extract the first top-level JSON object from *text* using brace
        counting so that nested objects and arrays are handled correctly."""
        start = text.find('{')
        if start == -1:
            return None
        depth = 0
        in_string = False
        escape = False
        for i in range(start, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == '\\' and in_string:
                escape = True
                continue
            if ch == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        return None

    def _parse_llm_response(self, response_text):
        """Parse the LLM JSON response into a scoring dict.

        Attempts to extract JSON from the response, handling cases where
        the LLM wraps its JSON in markdown code fences or extra text.
        """
        if not response_text:
            return None

        text = response_text.strip()
        fence_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
        if fence_match:
            text = fence_match.group(1)

        parsed = None
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            pass

        if parsed is None:
            json_str = self._extract_json_object(text)
            if json_str:
                try:
                    parsed = json.loads(json_str)
                except (json.JSONDecodeError, ValueError):
                    pass

        if parsed is None:
            patched = text.rstrip()
            if patched.startswith('{') and not patched.endswith('}'):
                patched += '}'
                try:
                    parsed = json.loads(patched)
                    self.logger.info("Parsed LLM response after appending missing '}'")
                except (json.JSONDecodeError, ValueError) as e:
                    self.logger.warning("Failed to parse LLM JSON even after patching: {}".format(str(e)))

        if parsed is None:
            self.logger.warning("No valid JSON object found in LLM response")
            return None

        if not isinstance(parsed, dict):
            self.logger.warning("LLM response parsed but is not a JSON object")
            return None

        required_fields = ['risk_score', 'genai_detected', 'confidence', 'explanation', 'types']
        for field in required_fields:
            if field not in parsed:
                self.logger.warning("Missing required field '{}' in LLM response".format(field))
                return None

        try:
            risk_score = float(parsed['risk_score'])
            risk_score = max(0.0, min(1.0, risk_score))
        except (ValueError, TypeError):
            self.logger.warning("Invalid risk_score value: {}".format(parsed['risk_score']))
            return None

        genai_detected = str(parsed['genai_detected']).lower() in ('true', '1', 'yes')

        confidence = str(parsed['confidence']).lower().strip()
        valid_confidence = ('very_high', 'high', 'medium', 'low', 'very_low')
        if confidence not in valid_confidence:
            confidence = 'medium'

        explanation = str(parsed.get('explanation', ''))

        types_raw = parsed.get('types', [])
        if isinstance(types_raw, list):
            types_list = [str(t) for t in types_raw]
        else:
            types_list = [str(types_raw)] if types_raw else []

        return {
            'risk_score': round(risk_score, 4),
            'genai_detected': 'true' if genai_detected else 'false',
            'confidence': confidence,
            'explanation': explanation,
            'types': types_list
        }

    _OUTPUT_MSG_FIELDS = (
        'output_messages',
        'gen_ai.output.messages_raw',
    )

    def _build_event_json(self, record):
        """Build a JSON payload containing only the output messages for LLM scoring.

        Splunk can deliver ``output_messages`` in several shapes depending on
        ``KV_MODE`` and the streaming-command SDK transport:

        1. **String** -- raw JSON array straight from ``_raw``.
        2. **List** -- multi-value field where each element is a JSON object
           string (Splunk auto-expanded the array).
        3. **Sub-field** -- ``output_messages{}.content`` with just the text
           values extracted by Splunk's JSON path expansion.
        4. **EVAL scalar** -- ``gen_ai.output.messages``, always a single
           space-joined string computed at search time.

        The method walks these in priority order and returns the first
        non-empty result wrapped as ``{"output_messages": ...}``.
        """
        for field in self._OUTPUT_MSG_FIELDS:
            value = record.get(field)
            if value is None:
                continue
            if isinstance(value, list):
                items = []
                for item in value:
                    s = str(item).strip()
                    if not s or s.lower() == 'none':
                        continue
                    try:
                        items.append(json.loads(s))
                    except (json.JSONDecodeError, ValueError):
                        items.append(s)
                if items:
                    return json.dumps(
                        {"output_messages": items}, indent=2, ensure_ascii=False)
                continue
            s = str(value).strip()
            if not s or s.lower() == 'none':
                continue
            if s.startswith(('[', '{')):
                try:
                    parsed = json.loads(s)
                    return json.dumps(
                        {"output_messages": parsed}, indent=2, ensure_ascii=False)
                except (json.JSONDecodeError, ValueError):
                    pass
            return json.dumps(
                {"output_messages": s}, indent=2, ensure_ascii=False)

        content = record.get('output_messages{}.content')
        if content is not None:
            if isinstance(content, list):
                texts = [str(c).strip() for c in content
                         if c is not None and str(c).strip()
                         and str(c).strip().lower() != 'none']
            else:
                t = str(content).strip()
                texts = [t] if t and t.lower() != 'none' else []
            if texts:
                return json.dumps(
                    {"output_messages": " ".join(texts)}, indent=2, ensure_ascii=False)

        value = record.get('gen_ai.output.messages')
        if value is not None:
            s = str(value).strip()
            if s and s.lower() != 'none':
                return json.dumps(
                    {"output_messages": s}, indent=2, ensure_ascii=False)

        return json.dumps(
            {"output_messages": ""}, indent=2, ensure_ascii=False)

    _CONTEXT_FIELDS = (
        'client.address',
        'gen_ai.app.name',
        'gen_ai.event.id',
        'gen_ai.request.id',
        'gen_ai.request.model',
        'gen_ai.session.id',
        'service.name',
        'timestamp',
        'trace_id',
    )

    @staticmethod
    def _resolve_scalar(val):
        """Extract the first meaningful scalar from a possibly multi-value field.

        Splunk streaming commands may pass multi-value fields as Python lists.
        JSON nulls surface as the string ``'none'`` after Splunk's JSON
        extraction.  This helper walks through list elements and returns the
        first non-empty, non-null string, or *None* if nothing useful is found.
        """
        if val is None:
            return None
        if isinstance(val, list):
            for item in val:
                resolved = GenAIScoreCommand._resolve_scalar(item)
                if resolved is not None:
                    return resolved
            return None
        s = str(val).strip()
        if not s or s.lower() == 'none':
            return None
        return s

    @staticmethod
    def _build_output_raw(record, scoring_fields, pipeline_name):
        """Build a slim _raw JSON for the collected scoring event.

        Only includes the required context fields from the original event,
        the dynamic scoring fields, and pipeline metadata.  The full event
        is sent to the LLM separately via _build_event_json.
        """
        output = {}

        for field in GenAIScoreCommand._CONTEXT_FIELDS:
            val = GenAIScoreCommand._resolve_scalar(record.get(field))
            if val is not None:
                output[field] = val

        if 'timestamp' not in output:
            _time = record.get('_time')
            if _time is not None:
                try:
                    output['timestamp'] = time.strftime(
                        '%Y-%m-%dT%H:%M:%S', time.localtime(float(_time)))
                except (ValueError, TypeError, OSError):
                    pass

        output['source'] = '{}_genai_scoring'.format(pipeline_name)

        for key, val in scoring_fields.items():
            if key in ('genai_scoring_status', 'genai_scoring_error'):
                continue
            output[key] = val

        record['_raw'] = json.dumps(output, ensure_ascii=False)

    def stream(self, records):
        """Process each record through the GenAI scoring pipeline."""
        try:
            self._load_pipeline_config()
        except Exception as e:
            for record in records:
                record['genai_scoring_status'] = 'error'
                record['genai_scoring_error'] = 'Config load failed: {}'.format(str(e))
                record['genai_scoring_pipeline'] = ''
                yield record
            return

        pipeline_name = self._pipeline_config['name']
        pipeline_prompt = self._pipeline_config['prompt']

        self.logger.info("Starting GenAI scoring pipeline='{}' name='{}'".format(
            self.pipeline, pipeline_name))

        event_count = 0
        success_count = 0

        for record in records:
            event_count += 1
            event_id = record.get('gen_ai.event.id', record.get('gen_ai_event_id', 'unknown'))

            event_json = self._build_event_json(record)

            debug_logger.info(
                "Event JSON built: event_id=%s len=%d first500=%s",
                event_id, len(event_json), event_json[:500])

            user_prompt = "SCORING TASK: {}\n\nEVENT DATA:\n{}".format(
                pipeline_prompt,
                event_json
            )

            llm_response, call_error = self._call_ai_toolkit(
                self._system_prompt, user_prompt, event_id)

            if llm_response:
                scoring = self._parse_llm_response(llm_response)
            else:
                scoring = None

            scoring_fields = {}

            if scoring:
                prefix = 'gen_ai.{}'.format(pipeline_name)
                scoring_fields['{}.risk_score'.format(prefix)] = str(scoring['risk_score'])
                scoring_fields['{}.genai_detected'.format(prefix)] = scoring['genai_detected']
                scoring_fields['{}.confidence'.format(prefix)] = scoring['confidence']
                scoring_fields['{}.explanation'.format(prefix)] = scoring['explanation']
                scoring_fields['{}.types'.format(prefix)] = scoring['types'] if scoring['types'] else []
                scoring_fields['genai_scoring_status'] = 'success'
                scoring_fields['genai_scoring_pipeline'] = pipeline_name
                scoring_fields['genai_scoring_error'] = ''
                success_count += 1
            else:
                scoring_fields['genai_scoring_status'] = 'error'
                scoring_fields['genai_scoring_pipeline'] = pipeline_name
                if call_error:
                    scoring_fields['genai_scoring_error'] = call_error
                elif llm_response:
                    scoring_fields['genai_scoring_error'] = 'JSON parse failed; raw={}'.format(
                        str(llm_response)[:200])
                else:
                    scoring_fields['genai_scoring_error'] = 'LLM returned empty response'

            record.update(scoring_fields)
            self._build_output_raw(record, scoring_fields, pipeline_name)

            yield record

        self.logger.info("GenAI scoring complete: pipeline='{}' processed={} success={}".format(
            pipeline_name, event_count, success_count))


dispatch(GenAIScoreCommand, sys.argv, sys.stdin, sys.stdout, __name__)
