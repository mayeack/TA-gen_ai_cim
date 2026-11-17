# encoding=utf-8
"""
Offline checks for the TA-gen_ai_cim 1.9.0 integration work around the Cisco
Duo feed: who may read the TA's credentials (metadata/default.meta
[passwords], contract decision 6), the version and manifest (decision 9),
the Splunk Web exposure of the account handler, and packaging (decision 8):
package.sh ships README/*.conf.spec and nothing else from README/, and
check_package.sh fails a package that leaks a README/ doc, drops the input's
spec or entry point, or ships an input instance in default/. Also R-INP-002:
every ES identity or asset source in the package has its lookup file there,
and check_package.sh fails one that does not, disabled or not.

The packaging tests build from a scratch copy of the tree in a temp dir (the
repo is never written) and need bash and tar. Runs on Python 3.9 and 3.13:

    python3 -m unittest discover -s tools/tests -p 'test_duo_package.py' -v
"""

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
from test_lab5_conf import read_conf  # noqa: E402

APP = 'TA-gen_ai_cim'
CHECK_PACKAGE = os.path.join(REPO, '.claude', 'skills', 'splunk-ta-development', 'check_package.sh')
ADMIN_ONLY = 'read : [ admin, sc_admin ], write : [ admin, sc_admin ]'
SCHEME = 'ta_gen_ai_cim_duo'
LOOKUP_GEN = 'GenAI - Identity - Duo Identity Lookup Gen'
# Alert actions that read the account conf and the account's credentials with
# the alert's session (bin/sync_snow_asset.py get_snow_config).
CREDENTIAL_ACTIONS = ('sync_snow_asset', 'pull_snow_inventory', 'create_snow_aicase')
SNOW_SEARCHES = {'GenAI - ServiceNow Asset Sync', 'GenAI - ServiceNow Asset Re-Verify',
                 'GenAI - ServiceNow Model Sync', 'GenAI - ServiceNow Model Re-Verify',
                 'GenAI - ServiceNow Full Inventory Pull'}


def read_text(*parts):
    with io.open(os.path.join(REPO, *parts), encoding='utf-8') as handle:
        return handle.read()


def read_stanzas(text):
    """{stanza: {key: value}} for a .meta or .conf text; comments skipped."""
    stanzas, current = {}, None
    for line in text.split('\n'):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        m = re.match(r'^\[(.*)\]\s*$', line)
        if m:
            current = stanzas.setdefault(m.group(1), {})
        elif '=' in line and current is not None:
            key, value = line.split('=', 1)
            current[key.strip()] = value.strip()
    return stanzas


def meta_name(search):
    """The URL-encoded object name metadata/default.meta uses for a search."""
    return 'savedsearches/' + quote(search, safe='')


###############################################################################
# Decision 6: credentials are admin-only, and every reader runs as a role that passes
###############################################################################

class CredentialAclTests(unittest.TestCase):

    def setUp(self):
        self.meta = read_stanzas(read_text('metadata', 'default.meta'))

    def test_passwords_are_admin_only_and_stay_in_the_app(self):
        self.assertEqual(self.meta['passwords'], {'access': ADMIN_ONLY, 'export': 'none'})
        # No narrower stanza re-opens one realm.
        self.assertEqual([s for s in self.meta if s.startswith('passwords/')], [])

    def test_duo_checkpoint_collection_is_admin_only(self):
        self.assertEqual(self.meta['collections/ta_gen_ai_cim_duo_checkpoint'],
                         {'access': ADMIN_ONLY, 'export': 'none'})

    def test_custom_conf_acls_are_named_after_the_conf(self):
        """A conf's metadata object is [<conf name>] (splunkd itself writes
        [ta_gen_ai_cim_genai_scoring/pipeline_1] into local.meta). The 1.x
        stanzas [conf/...] and [configs/conf-...] were never applied, so the
        account conf - since 1.9.0 also every Duo integration key and API
        hostname - inherited [] (read : [ * ], export = system)."""
        for conf in ('ta_gen_ai_cim_account', 'ta_gen_ai_cim_es', 'ta_gen_ai_cim_genai_scoring'):
            self.assertEqual(self.meta.get(conf), {'access': ADMIN_ONLY, 'export': 'none'}, conf)
            self.assertIn('reload.{} = simple'.format(conf), read_text('default', 'app.conf'))
        self.assertEqual([s for s in self.meta if s.startswith(('conf/', 'configs/'))], [])
        self.assertEqual([s for s in self.meta if s.startswith('ta_gen_ai_cim_account/')], [])

    def test_account_conf_readers_connect_in_the_app_context(self):
        """export = none hides the account conf outside TA-gen_ai_cim, so every
        bin/ module that reads it binds its service (or its REST path) to the app."""
        readers = []
        for name in sorted(os.listdir(os.path.join(REPO, 'bin'))):
            if not name.endswith('.py'):
                continue
            text = read_text('bin', name)
            reads = re.search(r"confs\[(?:'ta_gen_ai_cim_account'|ACCOUNT_CONF)\]", text) or (
                "CONF_NAME = 'ta_gen_ai_cim_account'" in text
                and re.search(r"""['"]/servicesNS/[^'"]*configs/conf-""", text))
            if not reads:
                continue
            readers.append(name)
            for call in re.finditer(r'client\.(?:connect|Service)\(([^)]+)\)', text):
                self.assertRegex(call.group(1),
                                 r"\bapp\s*=\s*(?:APP_NAME|APP|'TA-gen_ai_cim'|seed\.APP_NAME)(?![\w.])",
                                 (name, call.group(0)[:120]))
            for url in re.findall(r"""['"](/services(?:NS)?/[^'"]*configs/conf-[^'"]*)""", text):
                self.assertTrue(url.startswith('/servicesNS/nobody/'), (name, url))
        self.assertEqual(readers, ['genaiseedes.py', 'sync_snow_asset.py', 'ta_gen_ai_cim_account_handler.py',
                                   'ta_gen_ai_cim_duo_input.py'])

    def test_every_search_that_runs_a_credential_action_is_owned_by_admin(self):
        searches = read_conf('savedsearches.conf')
        readers = {name for name, keys in searches.items()
                   if any(keys.get('action.' + action) == '1' for action in CREDENTIAL_ACTIONS)}
        self.assertEqual(readers, SNOW_SEARCHES)
        for name in sorted(readers):
            self.assertEqual(self.meta.get(meta_name(name), {}).get('owner'), 'admin', name)

    def test_seeding_and_lookup_gen_are_owned_by_admin(self):
        for name in ('GenAI - ES - Seed Response Plan and SOAR Binding', LOOKUP_GEN):
            self.assertEqual(self.meta.get(meta_name(name), {}).get('owner'), 'admin', name)

    def test_credential_readers_connect_in_the_app_context(self):
        """export = none hides the credentials outside TA-gen_ai_cim, so every
        bin/ module that touches the TA's realm (ta_gen_ai_cim_account__*) in
        storage/passwords must bind its service to the app. (genaiscore reads
        the AI Toolkit's own secrets in that app's context, not this realm.)"""
        readers = []
        for name in sorted(os.listdir(os.path.join(REPO, 'bin'))):
            if not name.endswith('.py'):
                continue
            text = read_text('bin', name)
            if 'ta_gen_ai_cim_account__' not in text:
                continue
            if 'storage_passwords' not in text and 'storage/passwords' not in text:
                continue
            readers.append(name)
            # Calls with arguments only: a ``client.connect()`` in a docstring is not a call site.
            for call in re.finditer(r'client\.(?:connect|Service)\(([^)]+)\)', text):
                self.assertRegex(call.group(1),
                                 r"\bapp\s*=\s*(?:APP_NAME|APP|'TA-gen_ai_cim'|seed\.APP_NAME)(?![\w.])",
                                 (name, call.group(0)[:120]))
            for url in re.findall(r"""['"](/services(?:NS)?/[^'"]*storage/passwords)""", text):
                self.assertTrue(url.startswith('/servicesNS/nobody/'), (name, url))
        self.assertEqual(readers, ['genaiseedes.py', 'sync_snow_asset.py', 'ta_gen_ai_cim_account_handler.py',
                                   'ta_gen_ai_cim_duo_input.py'])


###############################################################################
# Decision 9: one version everywhere, the forwarder workload
###############################################################################

class VersionTests(unittest.TestCase):

    def test_one_semantic_version_everywhere(self):
        app = read_conf('app.conf')
        manifest = json.loads(read_text('app.manifest'))
        readme = re.search(r'(?m)^Version:\s*(\S+)', read_text('README.md')).group(1)
        versions = {app['id']['version'], app['launcher']['version'], manifest['info']['id']['version'], readme}
        self.assertEqual(len(versions), 1, versions)
        self.assertRegex(versions.pop(), r'^\d+\.\d+\.\d+$')
        self.assertRegex(app['install']['build'], r'^\d+$')

    def test_changelog_leads_with_the_current_version(self):
        version = read_conf('app.conf')['id']['version']
        first = re.search(r'(?m)^### v(\d+\.\d+\.\d+)', read_text('README.md')).group(1)
        self.assertEqual(first, version)

    def test_manifest_targets_search_heads_and_forwarders(self):
        manifest = json.loads(read_text('app.manifest'))
        self.assertEqual(manifest['targetWorkloads'], ['_search_heads', '_forwarders'])
        self.assertIn('_search_head_clustering', manifest['supportedDeployments'])


###############################################################################
# The account handler is reachable from Splunk Web, and snow_setup.py calls it
###############################################################################

def compile_expose(pattern):
    """Splunk Web's own compilation (splunk/appserver/mrsparkle/controllers/
    proxy.py precompile_whitelist)."""
    parts = []
    for element in pattern.split('/'):
        if element == '**':
            parts.append('.*')
        elif element.endswith('*'):
            parts.append(re.escape(element[:-1]) + '[^/]*')
        else:
            parts.append(re.escape(element))
    return re.compile('(^|^services/|^servicesNS/[^/]+/[^/]+/)' + '/'.join(parts) + '$')


class WebExposureTests(unittest.TestCase):

    def setUp(self):
        self.allow = []
        for stanza, keys in read_conf('web.conf').items():
            if stanza.startswith('expose:') and keys.get('disabled', '0') not in ('1', 'true'):
                methods = [m.strip().upper() for m in keys.get('methods', 'GET').split(',') if m.strip()]
                self.allow.append((compile_expose(keys['pattern']), methods))
        restmap = read_conf('restmap.conf')['admin:ta_gen_ai_cim_account']
        self.handler = 'servicesNS/nobody/{}{}/{}'.format(APP, restmap['match'], restmap['members'])

    def allowed(self, uri, method):
        return any(rx.match(uri) and method in methods for rx, methods in self.allow)

    def test_handler_collection_and_entities_are_exposed(self):
        self.assertTrue(self.allowed(self.handler, 'GET'))
        self.assertTrue(self.allowed(self.handler, 'POST'))
        for method in ('GET', 'POST', 'DELETE'):
            self.assertTrue(self.allowed(self.handler + '/duo', method), method)
        self.assertFalse(self.allowed(self.handler, 'DELETE'))
        self.assertFalse(self.allowed(self.handler + '/duo/extra', 'GET'))

    def test_config_page_calls_the_exposed_handler(self):
        js = read_text('appserver', 'static', 'config_config.js')
        m = re.search(r"HANDLER_ENDPOINT = localePrefix \+ '/splunkd/__raw/servicesNS/nobody/' \+ APP_NAME \+ "
                      r"'(/[^']+)'", js)
        self.assertIsNotNone(m, 'config_config.js no longer defines HANDLER_ENDPOINT as expected')
        self.assertEqual('servicesNS/nobody/' + APP + m.group(1), self.handler)

    def test_no_expose_pattern_is_dead(self):
        """Every expose stanza must match the handler or one of its entities."""
        for rx, _methods in self.allow:
            self.assertTrue(rx.match(self.handler) or rx.match(self.handler + '/duo'), rx.pattern)

    def test_snow_setup_uses_the_handler_path(self):
        text = read_text('bin', 'snow_setup.py')
        m = re.search(r"^ACCOUNT_ENDPOINT = '([^']+)'\.format\(APP_NAME\)$", text, re.M)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1).format(APP).lstrip('/'), self.handler)


###############################################################################
# Decision 8: packaging and check_package.sh
###############################################################################

def _tool(name):
    return shutil.which(name) is not None


def tar_dir(workspace, app_dir_name, out_name):
    """Tar workspace/app_dir_name the way package.sh does (no macOS xattrs)."""
    flags = []
    probe = subprocess.run(['tar', '--no-xattrs', '--version'], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    if probe.returncode == 0:
        flags = ['--no-xattrs']
    out = os.path.join(workspace, out_name)
    env = dict(os.environ, COPYFILE_DISABLE='1')
    subprocess.check_call(['tar'] + flags + ['-czf', out, app_dir_name + '/'], cwd=workspace, env=env)
    return out


def run_check(pkg, root):
    proc = subprocess.run(['bash', CHECK_PACKAGE, pkg, root], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True, timeout=120)
    return proc.returncode, proc.stdout


def write(path, text):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    with io.open(path, 'w', encoding='utf-8') as handle:
        handle.write(text)


@unittest.skipUnless(_tool('bash') and _tool('tar'), 'needs bash and tar')
class PackageBuildTests(unittest.TestCase):
    """Build the real package from a scratch copy, with placeholders for what
    must never ship, then run check_package.sh on it."""

    SKIP_TOP = {'.git', 'local', '.claude', '.cursor'}

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='ta_pkg_')
        app = os.path.join(cls.tmp, APP)

        def ignore(directory, names):
            rel = os.path.relpath(directory, REPO)
            skip = {n for n in names if n == '__pycache__' or n.endswith('.pyc')}
            if rel == '.':
                skip |= cls.SKIP_TOP & set(names)
                skip |= {n for n in names if n.endswith('.tgz')}
            if rel == 'metadata':
                skip |= {'local.meta'} & set(names)
            if rel == 'lookups':
                skip |= {'llm_pii_mixed_responses_200k.csv', 'ta_gen_ai_cim_duo_identities.csv'} & set(names)
            return skip

        shutil.copytree(REPO, app, ignore=ignore)
        # Placeholders for everything that must never ship, plus a new README/
        # doc and a nested spec to prove the README/ excludes are by name.
        for rel, text in (('local/inputs.conf', '# placeholder\n'), ('metadata/local.meta', '# placeholder\n'),
                          ('.git/HEAD', 'ref: refs/heads/x\n'), ('.claude/settings.local.json', '{}\n'),
                          ('.cursor/mcp.json', '{}\n'), ('lookups/llm_pii_mixed_responses_200k.csv', 'x\n'),
                          ('lookups/ta_gen_ai_cim_duo_identities.csv', 'identity\nx\n'),
                          ('bin/__pycache__/x.cpython-39.pyc', ''), ('README/NEW_NOTES.md', '# notes\n'),
                          ('README/nested/other.conf.spec', '# nested\n'), ('README/Docs [draft].md', '# x\n'),
                          ('default/.DS_Store', '')):
            write(os.path.join(app, rel), text)
        version = read_conf('app.conf')['id']['version']
        # package.sh writes next to the TA folder it runs from; the live
        # workspace's tarball (if any) must be untouched by this build.
        cls.live_pkg = os.path.join(os.path.dirname(REPO), '{}-{}.tgz'.format(APP, version))
        cls.live_before = os.path.getmtime(cls.live_pkg) if os.path.exists(cls.live_pkg) else None
        proc = subprocess.run(['bash', os.path.join(app, 'package.sh')], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, universal_newlines=True, timeout=300)
        cls.build_log = proc.stdout
        cls.build_rc = proc.returncode
        cls.pkg = os.path.join(cls.tmp, '{}-{}.tgz'.format(APP, version))
        cls.app = app
        cls.members = []
        if os.path.exists(cls.pkg):
            with tarfile.open(cls.pkg) as tgz:
                cls.members = [m.name + ('/' if m.isdir() else '') for m in tgz.getmembers()]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_build_succeeds_outside_the_repo(self):
        self.assertEqual(self.build_rc, 0, self.build_log[-2000:])
        self.assertTrue(os.path.exists(self.pkg), self.build_log[-2000:])
        live_after = os.path.getmtime(self.live_pkg) if os.path.exists(self.live_pkg) else None
        self.assertEqual(live_after, self.live_before, 'package.sh wrote into the live workspace')

    def test_soar_tarballs_and_lab5_connector_stay_out(self):
        self.assertEqual([m for m in self.members if m.startswith(APP + '/soar_apps/') and m.endswith('.tgz')], [])
        self.assertEqual([m for m in self.members if m.startswith(APP + '/soar_apps/pseudoco_identity')], [])
        self.assertIn(APP + '/soar_apps/medadvice_idp/', self.members)

    def test_readme_ships_only_its_top_level_specs(self):
        readme = sorted(m for m in self.members if m.startswith(APP + '/README/'))
        self.assertEqual(readme, [APP + '/README/', APP + '/README/alert_actions.conf.spec',
                                  APP + '/README/inputs.conf.spec'])
        self.assertIn(APP + '/README.md', self.members)
        self.assertIn(APP + '/bin/README', self.members)

    def test_duo_input_ships_complete(self):
        for rel in ('bin/ta_gen_ai_cim_duo.py', 'bin/ta_gen_ai_cim_duo_input.py', 'bin/ta_gen_ai_cim_duo_api.py',
                    'default/inputs.conf', 'default/collections.conf'):
            self.assertIn(APP + '/' + rel, self.members, rel)

    def test_never_ships_site_or_dev_content(self):
        bad = re.compile(r'(^|/)(local/|metadata/local\.meta|\.git|\.claude|\.cursor|CLAUDE\.md|__pycache__|\._|'
                         r'\.DS_Store|\.env|tools/|elements/|planning/|package\.sh$)')
        self.assertEqual([m for m in self.members if bad.search(m)], [])
        for rel in ('lookups/ta_gen_ai_cim_duo_identities.csv', 'lookups/llm_pii_mixed_responses_200k.csv'):
            self.assertNotIn(APP + '/' + rel, self.members, rel)

    def packaged(self, rel):
        with tarfile.open(self.pkg) as tgz:
            return tgz.extractfile('{}/{}'.format(APP, rel)).read().decode('utf-8')

    def test_every_identity_source_in_the_package_has_its_lookup_file(self):
        """R-INP-002 on the real build. ES checks the lookup file of every
        identity_manager source, a disabled one included, so each packaged source
        has its CSV in the package; the Duo source, whose CSV is generated at
        runtime (the placeholder above must not ship), is a commented example."""
        inputs_text = self.packaged('default/inputs.conf')
        inputs, transforms = read_stanzas(inputs_text), read_stanzas(self.packaged('default/transforms.conf'))
        sources = sorted(stanza for stanza in inputs if stanza.startswith('identity_manager://'))
        self.assertEqual(sources, ['identity_manager://medadvice_assets', 'identity_manager://medadvice_identities',
                                   'identity_manager://pseudoco_identity_personas'])
        for stanza in sources:
            url = inputs[stanza].get('url', '')
            self.assertTrue(url.startswith('lookup://'), (stanza, url))
            filename = transforms.get(url[len('lookup://'):], {}).get('filename')
            self.assertTrue(filename, stanza)
            self.assertIn('{}/lookups/{}'.format(APP, filename), self.members, stanza)
        self.assertEqual(transforms['ta_gen_ai_cim_duo_identities']['filename'], 'ta_gen_ai_cim_duo_identities.csv')
        self.assertNotIn(APP + '/lookups/ta_gen_ai_cim_duo_identities.csv', self.members)
        self.assertIn('\n#   [identity_manager://ta_gen_ai_cim_duo_identities]\n', inputs_text)

    def test_check_package_passes_the_real_build(self):
        rc, out = run_check(self.pkg, self.app)
        self.assertEqual(rc, 0, out)
        for line in ('PASS  R-PKG-003  no dev-only trees; README/ holds only *.conf.spec',
                     'PASS  R-INP-001  scheme ta_gen_ai_cim_duo: entry point bin/ta_gen_ai_cim_duo.py',
                     'PASS  R-INP-001  scheme ta_gen_ai_cim_duo: no input instance in default/inputs.conf',
                     'PASS  R-INP-002  [identity_manager://medadvice_assets]: lookups/medadvice_assets.csv ships',
                     'PASS  R-INP-002  [identity_manager://medadvice_identities]: '
                     'lookups/medadvice_identities.csv ships',
                     'PASS  R-INP-002  [identity_manager://pseudoco_identity_personas]: '
                     'lookups/pseudoco_identity_personas.csv ships'):
            self.assertIn(line, out)
        self.assertNotIn('FAIL', out)
        self.assertNotIn('ta_gen_ai_cim_duo_identities', out)


@unittest.skipUnless(_tool('bash') and _tool('tar'), 'needs bash and tar')
class CheckPackageRuleTests(unittest.TestCase):
    """check_package.sh against a minimal synthetic app, one defect at a time."""

    NAME = 'TA-x'
    VERSION = '9.9.9'
    SPEC = '[s_x://<name>]\nfoo = <string>\n'
    # The scheme's default stanza, and an ES identity source whose lookup file ships.
    INPUTS = ('[s_x]\ninterval = 300\n\n[identity_manager://other]\ntarget = identity\n'
              'url = lookup://other\n')

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ta_chk_')
        self.app = os.path.join(self.tmp, self.NAME)
        files = {
            'default/app.conf': '[id]\nversion = {0}\n\n[launcher]\nversion = {0}\n'.format(self.VERSION),
            'app.manifest': json.dumps({'info': {'id': {'version': self.VERSION}}}),
            'README.md': '# x\n\nVersion: {}\n'.format(self.VERSION),
            'README/inputs.conf.spec': self.SPEC,
            'README/alert_actions.conf.spec': '[a]\n',
            'bin/s_x.py': 'print(1)\n',
            'default/inputs.conf': self.INPUTS + 'disabled = false\n',
            'default/transforms.conf': '[other]\nfilename = other.csv\n',
            'lookups/other.csv': 'identity\nx\n',
            'default/props.conf': '[x]\nKV_MODE = json\n',
            'default/savedsearches.conf': '[s]\ndisabled = 1\n',
        }
        for rel, text in files.items():
            write(os.path.join(self.app, rel), text)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def check(self):
        pkg = tar_dir(self.tmp, self.NAME, '{}-{}.tgz'.format(self.NAME, self.VERSION))
        return run_check(pkg, self.app)

    def assert_fails(self, needle):
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn(needle, out)
        return out

    def test_a_complete_input_passes(self):
        rc, out = self.check()
        self.assertEqual(rc, 0, out)
        self.assertIn('PASS  R-INP-001  scheme s_x: entry point bin/s_x.py', out)
        # Another app's scheme (ES identity_manager) is not R-INP-001's business;
        # R-INP-002 checks that its source ships together with its lookup file.
        self.assertEqual([line for line in out.split('\n') if 'R-INP-001' in line and 'identity_manager' in line], [])
        self.assertIn('PASS  R-INP-002  [identity_manager://other]: lookups/other.csv ships', out)

    def test_a_readme_doc_fails(self):
        write(os.path.join(self.app, 'README', 'notes.md'), 'x\n')
        out = self.assert_fails('FAIL  R-PKG-003  package contains dev-only content')
        self.assertIn(self.NAME + '/README/notes.md', out)

    def test_a_nested_readme_spec_fails(self):
        write(os.path.join(self.app, 'README', 'sub', 'y.conf.spec'), 'x\n')
        self.assert_fails(self.NAME + '/README/sub/')

    def test_dev_only_trees_fail(self):
        write(os.path.join(self.app, 'tools', 'helper.py'), 'x\n')
        write(os.path.join(self.app, 'package.sh'), 'x\n')
        out = self.assert_fails('FAIL  R-PKG-003  package contains dev-only content')
        self.assertIn(self.NAME + '/tools/helper.py', out)
        self.assertIn(self.NAME + '/package.sh', out)

    def test_spec_in_repo_but_not_in_package_fails(self):
        spec = os.path.join(self.app, 'README', 'inputs.conf.spec')
        os.remove(spec)
        pkg = tar_dir(self.tmp, self.NAME, '{}-{}.tgz'.format(self.NAME, self.VERSION))
        write(spec, self.SPEC)                      # back in the "repo", not in the package
        rc, out = run_check(pkg, self.app)
        self.assertEqual(rc, 1, out)
        self.assertIn('FAIL  R-INP-001  README/inputs.conf.spec is in the repo but not in the package', out)
        self.assertIn('FAIL  R-INP-001  scheme s_x: no [s_x://<name>] in the packaged README/inputs.conf.spec', out)

    def test_scheme_default_without_any_spec_fails(self):
        os.remove(os.path.join(self.app, 'README', 'inputs.conf.spec'))
        self.assert_fails('FAIL  R-INP-001  scheme s_x: no [s_x://<name>] in the packaged README/inputs.conf.spec')

    def test_missing_entry_point_fails(self):
        os.remove(os.path.join(self.app, 'bin', 's_x.py'))
        write(os.path.join(self.app, 'bin', 's_x_input.py'), 'print(1)\n')
        self.assert_fails('FAIL  R-INP-001  scheme s_x: no bin/s_x.py')

    def test_an_input_instance_in_default_fails_even_disabled(self):
        with io.open(os.path.join(self.app, 'default', 'inputs.conf'), 'a', encoding='utf-8') as handle:
            handle.write('\n[s_x://shipped]\nfoo = bar\ndisabled = 1\n')
        out = self.assert_fails('FAIL  R-INP-001  scheme s_x: input instance(s) ship in default/inputs.conf')
        self.assertIn('[s_x://shipped]', out)

    def test_an_identity_source_without_its_file_fails_even_disabled(self):
        """R-INP-002: ES checks a disabled source's lookup file too, and logs an
        ERROR every 5 minutes while it is missing."""
        write(os.path.join(self.app, 'default', 'inputs.conf'), self.INPUTS + 'disabled = true\n')
        os.remove(os.path.join(self.app, 'lookups', 'other.csv'))
        self.assert_fails('FAIL  R-INP-002  [identity_manager://other]: lookups/other.csv is not in the package')

    def test_an_identity_source_without_a_lookup_definition_fails(self):
        write(os.path.join(self.app, 'default', 'transforms.conf'), '[another]\nfilename = other.csv\n')
        self.assert_fails('FAIL  R-INP-002  [identity_manager://other]: no [other] with a filename in the packaged '
                          'default/transforms.conf')

    def test_an_identity_source_without_a_lookup_url_fails(self):
        write(os.path.join(self.app, 'default', 'inputs.conf'),
              '[s_x]\ninterval = 300\n\n[identity_manager://other]\ntarget = identity\ndisabled = true\n')
        self.assert_fails("FAIL  R-INP-002  [identity_manager://other]: url '' is not lookup://<definition>")

    def test_a_commented_identity_source_is_not_a_source(self):
        """How a source whose file is generated at runtime ships: as an example."""
        with io.open(os.path.join(self.app, 'default', 'inputs.conf'), 'a', encoding='utf-8') as handle:
            handle.write('\n#   [identity_manager://generated]\n#   target = identity\n'
                         '#   url = lookup://generated\n#   disabled = false\n')
        rc, out = self.check()
        self.assertEqual(rc, 0, out)
        self.assertNotIn('generated', out)

    def test_no_identity_source_passes(self):
        write(os.path.join(self.app, 'default', 'inputs.conf'), '[s_x]\ninterval = 300\n')
        rc, out = self.check()
        self.assertEqual(rc, 0, out)
        self.assertIn('PASS  R-INP-002  no [identity_manager://...] source in default/inputs.conf', out)


if __name__ == '__main__':
    unittest.main()
