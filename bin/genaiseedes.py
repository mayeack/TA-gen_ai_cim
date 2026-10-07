# encoding=utf-8
"""
genaiseedes.py - `| genaiseedes` generating command: seed Splunk Enterprise
Security (Mission Control) with the AI Incident Response Plan, the
"ai security incident" investigation type bound to it, the AI Findings queue,
and - through the ES/SOAR pairing - the simulated "MedAdvice Identity Provider"
asset plus the response plan's SOAR task actions.

Run by the shipped search "GenAI - ES - Seed Response Plan and SOAR Binding"
(enabled, run_on_startup, hourly) so a fresh install converges on its own; it
can also be run ad hoc: `| genaiseedes install_simulator=true`.

Every step is idempotent and touches only TA-owned records (see
genai_es_seed.py). No event data is read and nothing content-bearing is logged.

Options (defaults come from ta_gen_ai_cim_es.conf [es_integration]):
  seed_response_plan   seed plan/type/queue                          (default true)
  bind_soar_actions    reach the paired SOAR through the ES proxy    (default true)
  install_simulator    install the simulator app if a `soar` account (default false)
                       exists in ta_gen_ai_cim_account.conf
  enable_triage_agent  turn on ES AI triage for the primary detection (default false)
  route_findings_to_queue  route AI Governance findings to the AI Findings
                       queue instead of the Analyst Queue                 (default false)
  dry_run              print writes without making them              (default false)

Output: one event per step - step, status (OK|SKIP|FAIL), detail.

Copyright 2026 Splunk Inc.
Licensed under Apache License 2.0
"""

import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from urllib.parse import urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lib'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators  # noqa: E402
import splunklib.client as client  # noqa: E402

import genai_es_seed as seed  # noqa: E402

LOG_NAME = 'genaiseedes'
SOAR_ACCOUNT = 'soar'
SOAR_REALM = 'ta_gen_ai_cim_account__' + SOAR_ACCOUNT


def _setup_logging():
    logger = logging.getLogger(LOG_NAME)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    log_dir = os.path.join(os.environ.get('SPLUNK_HOME', '.'), 'var', 'log', 'splunk')
    try:
        handler = RotatingFileHandler(os.path.join(log_dir, LOG_NAME + '.log'),
                                      maxBytes=2 * 1024 * 1024, backupCount=3)
    except OSError:
        handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(handler)
    return logger


# Module level, never self.logger: SearchCommand.logger is a read-only property
# in splunklib, so assigning it raised AttributeError on every run and the
# shipped seeding search never wrote anything (fixed in 1.7.1).
LOGGER = _setup_logging()


def _truthy(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


@Configuration()
class GenaiSeedEsCommand(GeneratingCommand):
    seed_response_plan = Option(require=False, validate=validators.Boolean())
    bind_soar_actions = Option(require=False, validate=validators.Boolean())
    install_simulator = Option(require=False, validate=validators.Boolean())
    enable_triage_agent = Option(require=False, validate=validators.Boolean())
    route_findings_to_queue = Option(require=False, validate=validators.Boolean())
    dry_run = Option(require=False, validate=validators.Boolean(), default=False)

    # Not _service: SearchCommand.__init__ sets self._service = None (the cache
    # behind its own .service property), which shadowed a method of that name
    # and made every run fail with "'NoneType' object is not callable".
    def _connect(self):
        info = self._metadata.searchinfo
        parts = urlsplit(info.splunkd_uri)
        return client.connect(scheme=parts.scheme, host=parts.hostname, port=parts.port,
                              token=info.session_key, owner='nobody', app=seed.APP_NAME)

    def _settings(self, service):
        settings = {}
        try:
            for stanza in service.confs['ta_gen_ai_cim_es']:
                if stanza.name == 'es_integration':
                    settings = dict(stanza.content)
        except Exception as exc:  # conf missing on a partial install
            LOGGER.warning('ta_gen_ai_cim_es.conf unreadable: %s', exc)
        return settings

    def _soar_account(self, service):
        """Optional `soar` account in ta_gen_ai_cim_account.conf (url, optional
        username, auth_type token|basic, verify_ssl) whose secret lives in
        storage/passwords under the account realm. Returns SoarDirect or None."""
        try:
            account = None
            for stanza in service.confs['ta_gen_ai_cim_account']:
                if stanza.name == SOAR_ACCOUNT:
                    account = dict(stanza.content)
            if not account or not account.get('url'):
                return None
            secret = None
            for cred in service.storage_passwords:
                if cred.content.get('realm') == SOAR_REALM:
                    secret = cred.clear_password
            if not secret:
                LOGGER.warning('soar account has no stored secret')
                return None
            verify = _truthy(account.get('verify_ssl'), True)
            if (account.get('auth_type') or 'token').lower() == 'basic':
                return seed.SoarDirect(account['url'], username=account.get('username'),
                                       password=secret, dry_run=bool(self.dry_run), verify=verify)
            return seed.SoarDirect(account['url'], token=secret, dry_run=bool(self.dry_run),
                                   verify=verify)
        except Exception as exc:
            LOGGER.warning('soar account unreadable: %s', exc)
            return None

    def generate(self):
        info = self._metadata.searchinfo
        service = self._connect()
        settings = self._settings(service)

        def opt(name, default):
            value = getattr(self, name)
            if value is None:
                return _truthy(settings.get(name), default)
            return bool(value)

        do_plan = opt('seed_response_plan', True)
        do_bind = opt('bind_soar_actions', True)
        do_install = opt('install_simulator', False)
        do_triage = opt('enable_triage_agent', False)
        do_route = opt('route_findings_to_queue', False)
        dry_run = bool(self.dry_run)

        splunkd = seed.Splunkd(info.splunkd_uri, session_key=info.session_key,
                               verify=False, dry_run=dry_run)
        rep = seed.Reporter()
        soar = None
        if do_bind:
            direct = self._soar_account(service) if do_install else None
            if direct and direct.paired():
                soar = direct
            else:
                if direct:
                    rep.skip('soar account', 'configured but unreachable; using the ES pairing proxy')
                soar = seed.SoarViaEsProxy(splunkd)
        else:
            rep.skip('SOAR', 'bind_soar_actions is off')

        if do_plan:
            seed.seed(splunkd, rep, soar=soar, install_simulator=do_install,
                      enable_triage=do_triage, route_queue=do_route)
        else:
            rep.skip('response plan', 'seed_response_plan is off')
            if do_triage:
                seed.step_triage_agent(splunkd, rep)

        LOGGER.info('genaiseedes finished: %d rows, %d failures%s',
                    len(rep.rows), rep.failures(), ' (dry run)' if dry_run else '')
        now = time.time()
        for status, step, detail in rep.rows:
            yield {'_time': now, 'step': step, 'status': status, 'detail': detail,
                   'dry_run': dry_run}


dispatch(GenaiSeedEsCommand, sys.argv, sys.stdin, sys.stdout, __name__)
