/**
 * Configuration Page JavaScript
 *
 * Accounts live in ta_gen_ai_cim_account.conf, one stanza each. The page loads
 * every stanza once and sorts them by kind with the "account-rules" block below
 * (the same rules bin/sync_snow_asset.py uses to pick the ServiceNow account):
 *   - ServiceNow accounts: the ServiceNow Settings tab, saved through the conf
 *     and storage/passwords REST endpoints as before;
 *   - Cisco Duo Admin API accounts (auth_type duo_hmac): the Cisco Duo tab,
 *     saved ONLY through the account REST handler
 *     (/servicesNS/nobody/TA-gen_ai_cim/ta_gen_ai_cim_account/ta_gen_ai_cim_account),
 *     which validates the API hostname and keeps the secret key in
 *     storage/passwords; the page never reads a secret back;
 *   - anything else (the soar account): not managed here.
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
    'use strict';

    var APP_NAME = 'TA-gen_ai_cim';
    var CONF_NAME = 'ta_gen_ai_cim_account';
    var GENAI_CONF_NAME = 'ta_gen_ai_cim_llm';
    var DETECTION_CONF_NAME = 'ta_gen_ai_cim_detection';
    
    // Get locale prefix from current URL (e.g., /en-US/)
    var localeMatch = window.location.pathname.match(/^\/[a-z]{2}[-_][A-Z]{2}\//);
    var localePrefix = localeMatch ? localeMatch[0].slice(0, -1) : '';
    
    // REST endpoints for account configuration
    var PROPS_ENDPOINT = localePrefix + '/splunkd/__raw/servicesNS/nobody/' + APP_NAME + '/properties/' + CONF_NAME;
    var CONF_ENDPOINT = localePrefix + '/splunkd/__raw/servicesNS/nobody/' + APP_NAME + '/configs/conf-' + CONF_NAME;
    var GENAI_CONF_ENDPOINT = localePrefix + '/splunkd/__raw/servicesNS/nobody/' + APP_NAME + '/configs/conf-' + GENAI_CONF_NAME;
    var DETECTION_CONF_ENDPOINT = localePrefix + '/splunkd/__raw/servicesNS/nobody/' + APP_NAME + '/configs/conf-' + DETECTION_CONF_NAME;
    var PASSWORDS_ENDPOINT = localePrefix + '/splunkd/__raw/servicesNS/nobody/' + APP_NAME + '/storage/passwords';
    // Account REST handler (restmap.conf [admin:ta_gen_ai_cim_account]); Splunk Web
    // proxies it only while web.conf exposes ta_gen_ai_cim_account/ta_gen_ai_cim_account[/*].
    var HANDLER_ENDPOINT = localePrefix + '/splunkd/__raw/servicesNS/nobody/' + APP_NAME + '/ta_gen_ai_cim_account/ta_gen_ai_cim_account';
    var accounts = [];          // ServiceNow accounts (ServiceNow Settings tab)
    var allAccounts = [];       // every account stanza, any kind (name collision checks)
    var duoAccounts = [];       // Cisco Duo accounts (Cisco Duo tab)
    var otherAccounts = [];     // neither (for example the soar account)
    var snowInUse = null;       // the ServiceNow account the alert actions use
    var editMode = false;
    var duoEditMode = false;
    var genaiSettings = {};
    var detectionSettings = {};

    // Get CSRF token: THIS Splunk Web's own cookie (splunkweb_csrf_token_<port>).
    // Cookies are scoped by host, not port, so a browser that has used two
    // Splunk instances on one host holds a token for each. Up to v1.8.0 this
    // took the first one, and a write then failed CSRF validation (401), on
    // which Splunk Web silently reloads the page. pickCsrfToken (below) holds
    // the rule; the stale-prone hidden input is only the last resort.
    function getCSRFToken() {
        var ports = [window.$C && window.$C.MRSPARKLE_PORT_NUMBER, window.location.port];
        return pickCsrfToken(document.cookie, ports) || $('input[name="splunk_form_key"]').val();
    }

    // BEGIN account-rules
    // Pure functions, no jQuery. They mirror bin/sync_snow_asset.py
    // (is_servicenow_account, select_snow_account) and
    // bin/ta_gen_ai_cim_account_handler.py (normalize_duo_api_url,
    // validate_duo_ikey, validate_duo_skey); tools/tests/test_duo_account.py
    // runs this block under node against the Python over the same vectors.
    // The handler stays the authority: these checks only save a round trip.
    var NON_ACCOUNT_STANZAS = ['default', 'asset_discovery'];
    var SNOW_AUTH_TYPES = ['basic', 'oauth_auth_code', 'oauth_client_creds'];
    var NON_SNOW_ACCOUNT_NAMES = ['soar', 'duo'];
    var URL_HOST_RE = /^[A-Za-z][A-Za-z0-9+.\-]*:\/\/(?:[^@\/?#]*@)?([^:\/?#]*)/;
    var SNOW_HOST_RE = /(^|\.)(service-now|servicenow)\.com$/;
    var DUO_API_HOST_RE = /^api-[a-z0-9]+\.(duosecurity|duofederal)\.com$/;
    var ACCOUNT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$/;
    var DUO_IKEY_RE = /^[A-Za-z0-9]{16,64}$/;
    var DUO_SKEY_RE = /^[\x21-\x7e]{20,128}$/;
    var SECRET_MASK = '********';
    var DUO_URL_HELP = 'The API hostname must be the Duo Admin API hostname, for example ' +
        'api-XXXXXXXX.duosecurity.com or https://api-XXXXXXXX.duofederal.com ' +
        '(https only, no path, port or credentials).';

    function accountHost(url) {
        var value = String(url == null ? '' : url).trim();
        if (!value) { return ''; }
        if (value.indexOf('://') === -1) { value = 'https://' + value; }
        var match = URL_HOST_RE.exec(value);
        return match ? match[1].toLowerCase() : '';
    }

    function isNonAccountStanza(name) {
        name = String(name == null ? '' : name);
        return !name || NON_ACCOUNT_STANZAS.indexOf(name) !== -1 || name.charAt(0) === '_';
    }

    function isServiceNowAccount(name, content) {
        name = String(name == null ? '' : name);
        if (isNonAccountStanza(name)) { return false; }
        content = content || {};
        var authType = String(content.auth_type || 'basic').trim().toLowerCase();
        if (authType === 'duo_hmac') { return false; }
        var host = accountHost(content.url);
        if (SNOW_HOST_RE.test(host)) { return true; }
        if (DUO_API_HOST_RE.test(host)) { return false; }
        return SNOW_AUTH_TYPES.indexOf(authType) !== -1 &&
            NON_SNOW_ACCOUNT_NAMES.indexOf(name.toLowerCase()) === -1;
    }

    // 'none' (not an account), 'duo', 'servicenow' or 'other'
    function accountKind(name, content) {
        if (isNonAccountStanza(name)) { return 'none'; }
        if (String((content || {}).auth_type || '').trim().toLowerCase() === 'duo_hmac') { return 'duo'; }
        return isServiceNowAccount(name, content) ? 'servicenow' : 'other';
    }

    // The name get_snow_config picks from [{name, url, auth_type}], or null.
    function selectServiceNowAccount(list) {
        var candidates = (list || []).filter(function(a) {
            return isServiceNowAccount(a.name, a);
        }).sort(function(a, b) {
            return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
        });
        for (var i = 0; i < candidates.length; i++) {
            if (SNOW_HOST_RE.test(accountHost(candidates[i].url))) { return candidates[i].name; }
        }
        return candidates.length ? candidates[0].name : null;
    }

    // {url: 'https://<host>'} or {error}; never echoes the input.
    function normalizeDuoApiUrl(value) {
        var text = String(value == null ? '' : value).trim();
        if (!text) { return { error: 'The API hostname is required.' }; }
        var host;
        var sep = text.indexOf('://');
        if (sep !== -1) {
            if (text.slice(0, sep).toLowerCase() !== 'https') {
                return { error: 'The Duo API hostname must use https.' };
            }
            var rest = text.slice(sep + 3);
            var slash = rest.indexOf('/');
            var authority = slash === -1 ? rest : rest.slice(0, slash);
            var path = slash === -1 ? '' : rest.slice(slash);
            if (/[?#@]/.test(rest) || authority.indexOf(':') !== -1 || (path !== '' && path !== '/')) {
                return { error: DUO_URL_HELP };
            }
            host = authority.toLowerCase();
        } else {
            host = text.toLowerCase();
            if (host.charAt(host.length - 1) === '/') { host = host.slice(0, -1); }
        }
        if (!DUO_API_HOST_RE.test(host)) { return { error: DUO_URL_HELP }; }
        return { url: 'https://' + host };
    }

    function validateDuoIkey(value) {
        var ikey = String(value == null ? '' : value).trim();
        if (!DUO_IKEY_RE.test(ikey)) {
            return { error: 'The integration key must be 16-64 letters and digits ' +
                '(Duo shows it as DIXXXXXXXXXXXXXXXXXX).' };
        }
        return { value: ikey };
    }

    function validateDuoSkey(value) {
        var skey = String(value == null ? '' : value).trim();
        if (skey === SECRET_MASK || !DUO_SKEY_RE.test(skey)) {
            return { error: 'The secret key must be 20-128 characters with no spaces.' };
        }
        return { value: skey };
    }

    // The CSRF token for this Splunk Web out of a document.cookie string:
    // the splunkweb_csrf_token_<port> cookie of the first port in `ports` that
    // has one, else the first splunkweb_csrf_token_* cookie, else ''.
    function pickCsrfToken(cookieString, ports) {
        var prefix = 'splunkweb_csrf_token_';
        var byPort = {};
        var first = '';
        String(cookieString || '').split(';').forEach(function(part) {
            var cookie = part.trim();
            var eq = cookie.indexOf('=');
            if (cookie.indexOf(prefix) !== 0 || eq < 0) { return; }
            var value = cookie.substring(eq + 1);
            try { value = decodeURIComponent(value); } catch (e) { /* keep the raw value */ }
            byPort[cookie.substring(prefix.length, eq)] = value;
            if (!first) { first = value; }
        });
        for (var i = 0; i < (ports || []).length; i++) {
            var port = String(ports[i] == null ? '' : ports[i]).trim();
            if (port && byPort[port]) { return byPort[port]; }
        }
        return first;
    }
    // END account-rules

    // Format auth type for display
    function formatAuthType(authType) {
        var types = {
            'basic': 'Basic Authentication',
            'oauth_auth_code': 'OAuth 2.0 (Authorization Code)',
            'oauth_client_creds': 'OAuth 2.0 (Client Credentials)'
        };
        return types[authType] || authType || 'Basic Authentication';
    }

    // One account record from a stanza's settings (never a secret: the conf holds none)
    function accountRecord(name, content) {
        content = content || {};
        return {
            name: name,
            url: content.url || '',
            auth_type: content.auth_type || 'basic',
            username: content.username || '',
            client_id: content.client_id || ''
        };
    }

    // Sort the loaded stanzas into the ServiceNow, Cisco Duo and other lists, then render
    function classifyAndRender(records) {
        allAccounts = [];
        accounts = [];
        duoAccounts = [];
        otherAccounts = [];
        records.forEach(function(account) {
            var kind = accountKind(account.name, account);
            if (kind === 'none') { return; }
            allAccounts.push(account);
            if (kind === 'servicenow') { accounts.push(account); }
            else if (kind === 'duo') { duoAccounts.push(account); }
            else { otherAccounts.push(account); }
        });
        snowInUse = selectServiceNowAccount(accounts);
        renderAccountsTable();
        renderDuoAccountsTable();
    }

    // Load accounts from conf file using configs endpoint
    function loadAccounts() {
        console.log('Loading accounts from:', CONF_ENDPOINT);

        $.ajax({
            url: CONF_ENDPOINT,
            type: 'GET',
            data: { output_mode: 'json', count: 0 },
            success: function(response) {
                var records = [];
                (response.entry || []).forEach(function(entry) {
                    records.push(accountRecord(entry.name, entry.content));
                });
                classifyAndRender(records);
            },
            error: function(xhr) {
                console.log('Load error:', xhr.status, xhr.statusText);
                // Try properties endpoint as fallback
                loadAccountsFromProperties();
            }
        });
    }
    
    // Fallback: Load accounts from properties endpoint
    function loadAccountsFromProperties() {
        console.log('Fallback: Loading from properties endpoint:', PROPS_ENDPOINT);
        
        $.ajax({
            url: PROPS_ENDPOINT,
            type: 'GET',
            data: { output_mode: 'json' },
            success: function(response) {
                console.log('Properties response:', response);
                var stanzaNames = [];
                var records = [];

                (response.entry || []).forEach(function(entry) {
                    if (!isNonAccountStanza(entry.name)) {
                        stanzaNames.push(entry.name);
                    }
                });

                if (stanzaNames.length === 0) {
                    classifyAndRender(records);
                    return;
                }

                var loaded = 0;
                stanzaNames.forEach(function(name) {
                    loadStanzaDetails(name, records, function() {
                        loaded++;
                        if (loaded === stanzaNames.length) {
                            classifyAndRender(records);
                        }
                    });
                });
            },
            error: function(xhr) {
                console.log('Properties load error:', xhr.status, xhr.statusText);
                classifyAndRender([]);
            }
        });
    }

    // Load details for a specific stanza
    function loadStanzaDetails(stanzaName, records, callback) {
        $.ajax({
            url: PROPS_ENDPOINT + '/' + encodeURIComponent(stanzaName),
            type: 'GET',
            data: { output_mode: 'json' },
            success: function(response) {
                var content = {};
                (response.entry || []).forEach(function(prop) {
                    if (['url', 'auth_type', 'username', 'client_id'].indexOf(prop.name) !== -1) {
                        content[prop.name] = prop.content ? prop.content['$text'] : '';
                    }
                });
                records.push(accountRecord(stanzaName, content));
                if (callback) callback();
            },
            error: function(xhr) {
                console.log('Error loading stanza details:', stanzaName, xhr.status);
                if (callback) callback();
            }
        });
    }

    // Render accounts table
    function renderAccountsTable() {
        var $tbody = $('#accounts-tbody');
        $tbody.empty();

        $('#account-count').text(accounts.length);

        var $other = $('#other-accounts-note');
        if (otherAccounts.length) {
            $other.text('Not shown: ' + otherAccounts.map(function(a) { return a.name; }).join(', ') +
                ' (not a ServiceNow or Cisco Duo account, for example the soar account | genaiseedes reads; ' +
                'manage it in ta_gen_ai_cim_account.conf).').show();
        } else {
            $other.text('').hide();
        }

        if (accounts.length === 0) {
            $tbody.html('<tr class="no-records"><td colspan="3">No records found</td></tr>');
            return;
        }

        accounts.forEach(function(account) {
            var badge = account.name === snowInUse
                ? ' <span class="help-text" style="display:inline;">(in use)</span>' : '';
            var row = '<tr data-name="' + escapeHtml(account.name) + '">' +
                '<td>' + escapeHtml(account.name) + badge + '</td>' +
                '<td>' + escapeHtml(formatAuthType(account.auth_type)) + '</td>' +
                '<td class="actions-cell">' +
                    '<a class="action-link edit-account" href="#">Edit</a>' +
                    '<a class="action-link delete delete-account" href="#">Delete</a>' +
                '</td>' +
            '</tr>';
            $tbody.append(row);
        });
    }

    // Only the last four characters of an integration key are shown in the table
    function maskIkey(ikey) {
        ikey = String(ikey || '');
        return ikey.length > 4 ? '••••' + ikey.slice(-4) : (ikey ? '••••' : '');
    }

    // Render the Cisco Duo accounts table
    function renderDuoAccountsTable() {
        var $tbody = $('#duo-accounts-tbody');
        $tbody.empty();
        $('#duo-account-count').text(duoAccounts.length);

        if (duoAccounts.length === 0) {
            $tbody.html('<tr class="no-records"><td colspan="4">No records found</td></tr>');
            return;
        }

        duoAccounts.forEach(function(account) {
            var row = '<tr data-name="' + escapeHtml(account.name) + '">' +
                '<td>' + escapeHtml(account.name) + '</td>' +
                '<td>' + escapeHtml(accountHost(account.url)) + '</td>' +
                '<td>' + escapeHtml(maskIkey(account.client_id)) + '</td>' +
                '<td class="actions-cell">' +
                    '<a class="action-link edit-duo-account" href="#">Edit</a>' +
                    '<a class="action-link delete delete-duo-account" href="#">Delete</a>' +
                '</td>' +
            '</tr>';
            $tbody.append(row);
        });
    }

    // Escape HTML
    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;')
                  .replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;')
                  .replace(/"/g, '&quot;');
    }

    // Show modal
    function showModal(modalId) {
        $('#' + modalId).addClass('show');
    }

    // Hide modal
    function hideModal(modalId) {
        $('#' + modalId).removeClass('show');
    }

    // Clear form
    function clearForm() {
        $('#account-name').val('').prop('disabled', false);
        $('#account-url').val('');
        
        // Reset select using prop for reliability
        var $select = $('#account-auth-type');
        $select.find('option').prop('selected', false);
        $select.find('option[value="basic"]').prop('selected', true);
        
        $('#basic-username').val('');
        $('#basic-password').val('');
        $('#oauth-cc-client-id').val('');
        $('#oauth-cc-client-secret').val('');
        $('#edit-account-name').val('');
        $('#form-error').removeClass('show').text('');
        updateAuthFields();
    }

    // Update visible auth fields based on selection
    function updateAuthFields() {
        var authType = $('#account-auth-type').val();
        $('.auth-fields').hide();
        
        if (authType === 'basic') {
            $('#fields-basic').show();
        } else if (authType === 'oauth_client_creds') {
            $('#fields-oauth-client-creds').show();
        }
    }

    // Show error message
    function showError(message) {
        $('#form-error').addClass('show').text(message);
    }

    // Store password securely
    function storePassword(accountName, fieldName, password) {
        return new Promise(function(resolve, reject) {
            var realm = 'ta_gen_ai_cim_account__' + accountName;
            var csrfToken = getCSRFToken();

            // First try to delete existing password
            $.ajax({
                url: PASSWORDS_ENDPOINT + '/' + encodeURIComponent(realm + ':' + fieldName + ':'),
                type: 'DELETE',
                headers: { 'X-Splunk-Form-Key': csrfToken },
                complete: function() {
                    // Now create new password
                    $.ajax({
                        url: PASSWORDS_ENDPOINT,
                        type: 'POST',
                        data: {
                            name: fieldName,
                            password: password,
                            realm: realm,
                            output_mode: 'json'
                        },
                        headers: { 'X-Splunk-Form-Key': csrfToken },
                        success: function() { resolve(); },
                        error: function(xhr) {
                            console.error('Failed to store password:', xhr.responseText);
                            reject('Failed to store credentials');
                        }
                    });
                }
            });
        });
    }

    // Delete password
    function deletePassword(accountName, fieldName) {
        return new Promise(function(resolve) {
            var realm = 'ta_gen_ai_cim_account__' + accountName;
            var csrfToken = getCSRFToken();

            $.ajax({
                url: PASSWORDS_ENDPOINT + '/' + encodeURIComponent(realm + ':' + fieldName + ':'),
                type: 'DELETE',
                headers: { 'X-Splunk-Form-Key': csrfToken },
                complete: function() { resolve(); }
            });
        });
    }

    // Save account to conf file
    function saveAccount() {
        var name = $('#account-name').val().trim();
        var url = $('#account-url').val().trim();
        var authType = $('#account-auth-type').val();
        var editName = $('#edit-account-name').val();

        // Validation
        if (!name) {
            showError('Account Name is required');
            return;
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
            showError('Account Name can only contain letters, numbers, underscores, and hyphens');
            return;
        }
        if (!editMode) {
            if (isNonAccountStanza(name) || NON_SNOW_ACCOUNT_NAMES.indexOf(name.toLowerCase()) !== -1) {
                showError('"' + name + '" is reserved; choose another Account Name');
                return;
            }
            if (allAccounts.some(function(a) { return a.name === name; })) {
                showError('An account named "' + name + '" already exists; choose another name');
                return;
            }
        }
        if (!url) {
            showError('URL is required');
            return;
        }
        if (authType !== 'duo_hmac' && DUO_API_HOST_RE.test(accountHost(url))) {
            showError('That is a Cisco Duo API hostname; add it on the Cisco Duo (Admin API) tab');
            return;
        }

        var confData = {
            url: url,
            auth_type: authType,
            output_mode: 'json'
        };

        var passwordPromises = [];
        var csrfToken = getCSRFToken();

        // Add auth-specific fields
        if (authType === 'basic') {
            var username = $('#basic-username').val().trim();
            var password = $('#basic-password').val();
            if (!username) {
                showError('Username is required');
                return;
            }
            if (!password && !editMode) {
                showError('Password is required');
                return;
            }
            confData.username = username;
            if (password && password !== '********') {
                passwordPromises.push(storePassword(name, 'password', password));
            }
        } else if (authType === 'oauth_client_creds') {
            var clientId = $('#oauth-cc-client-id').val().trim();
            var clientSecret = $('#oauth-cc-client-secret').val();
            if (!clientId) {
                showError('Client ID is required');
                return;
            }
            if (!clientSecret && !editMode) {
                showError('Client Secret is required');
                return;
            }
            confData.client_id = clientId;
            if (clientSecret && clientSecret !== '********') {
                passwordPromises.push(storePassword(name, 'client_secret', clientSecret));
            }
        }

        $('#btn-save').prop('disabled', true).text('Saving...');

        // Save conf entry using configs endpoint
        var stanzaUrl = CONF_ENDPOINT + '/' + encodeURIComponent(name);

        console.log('Saving account to:', stanzaUrl);
        
        // First create or update the stanza
        if (!editMode) {
            // Create new stanza
            confData.name = name;
            $.ajax({
                url: CONF_ENDPOINT,
                type: 'POST',
                data: confData,
                headers: { 'X-Splunk-Form-Key': csrfToken },
                success: function() {
                    console.log('Account created');
                    finishSave(null);
                },
                error: function(xhr) {
                    console.log('Create error:', xhr.status);
                    if (xhr.status === 409) {
                        // Never fall back to an update: the stanza may be another
                        // kind of account (a Cisco Duo or soar account).
                        finishSave('an account named "' + name + '" already exists');
                    } else {
                        finishSave('Failed to create account: ' + xhr.status);
                    }
                }
            });
        } else {
            updateAccount();
        }
        
        function updateAccount() {
            $.ajax({
                url: stanzaUrl,
                type: 'POST',
                data: confData,
                headers: { 'X-Splunk-Form-Key': csrfToken },
                success: function() {
                    console.log('Account updated');
                    finishSave(null);
                },
                error: function(xhr) {
                    console.log('Update error:', xhr.status, xhr.responseText);
                    finishSave('Failed to update account: ' + xhr.status);
                }
            });
        }
        
        function finishSave(error) {
            if (error) {
                showError('Failed to save: ' + error);
                $('#btn-save').prop('disabled', false).text(editMode ? 'Save' : 'Add');
                return;
            }
            
            // Store passwords
            Promise.all(passwordPromises)
                .then(function() {
                    hideModal('account-modal');
                    loadAccounts();
                    $('#btn-save').prop('disabled', false).text(editMode ? 'Save' : 'Add');
                })
                .catch(function(err) {
                    showError(err);
                    $('#btn-save').prop('disabled', false).text(editMode ? 'Save' : 'Add');
                });
        }
    }

    // Delete account
    function deleteAccount(name) {
        var csrfToken = getCSRFToken();

        $.ajax({
            url: CONF_ENDPOINT + '/' + encodeURIComponent(name),
            type: 'DELETE',
            headers: { 'X-Splunk-Form-Key': csrfToken },
            success: function() {
                // Also delete stored passwords
                Promise.all([
                    deletePassword(name, 'password'),
                    deletePassword(name, 'client_secret')
                ]).then(function() {
                    hideModal('delete-modal');
                    loadAccounts();
                });
            },
            error: function(xhr) {
                console.error('Failed to delete account:', xhr.responseText);
                hideModal('delete-modal');
                alert('Failed to delete account: ' + xhr.status);
            }
        });
    }

    // ==================== Cisco Duo Account Functions ====================
    // Every write goes through HANDLER_ENDPOINT; nothing here calls CONF_ENDPOINT
    // or PASSWORDS_ENDPOINT, and no secret is ever read back.

    // A readable message from a failed handler call
    function handlerErrorMessage(xhr) {
        var body = xhr && xhr.responseJSON;
        if (!body && xhr && xhr.responseText) {
            try { body = JSON.parse(xhr.responseText); } catch (e) { body = null; }
        }
        var messages = (body && body.messages) || [];
        if (messages.length && messages[0].text) {
            return String(messages[0].text).replace(/^\s*In handler '[^']*':\s*/, '');
        }
        if (xhr && xhr.status === 404) {
            return 'The account REST endpoint is not reachable from Splunk Web. web.conf must expose ' +
                'ta_gen_ai_cim_account/ta_gen_ai_cim_account (and /*), and Splunk Web must be restarted after it changes.';
        }
        return 'HTTP ' + (xhr ? xhr.status : 'error');
    }

    function showDuoError(message) {
        $('#duo-form-error').addClass('show').text(message);
    }

    function clearDuoForm() {
        $('#duo-account-name').val('').prop('disabled', false);
        $('#duo-api-hostname').val('');
        $('#duo-integration-key').val('');
        $('#duo-secret-key').val('').attr('placeholder', 'Enter the secret key');
        $('#duo-secret-required').show();
        $('#duo-secret-help').text("Stored in Splunk's credential store; it is never displayed again.");
        $('#duo-edit-account-name').val('');
        $('#duo-form-error').removeClass('show').text('');
    }

    function openDuoModal(account) {
        clearDuoForm();
        duoEditMode = !!account;
        if (account) {
            $('#duo-modal-title').text('Edit Cisco Duo Account');
            $('#btn-duo-save').text('Save');
            $('#duo-account-name').val(account.name).prop('disabled', true);
            $('#duo-edit-account-name').val(account.name);
            $('#duo-api-hostname').val(accountHost(account.url));
            $('#duo-integration-key').val(account.client_id);
            $('#duo-secret-key').attr('placeholder', 'Leave blank to keep the stored secret key');
            $('#duo-secret-required').hide();
            $('#duo-secret-help').text('Leave blank to keep the stored secret key; a new value replaces it.');
        } else {
            $('#duo-modal-title').text('Add Cisco Duo Account');
            $('#btn-duo-save').text('Add');
        }
        showModal('duo-account-modal');
    }

    function saveDuoAccount() {
        var name = duoEditMode ? $('#duo-edit-account-name').val() : $('#duo-account-name').val().trim();
        var secret = $('#duo-secret-key').val();

        if (!duoEditMode) {
            if (!name) { showDuoError('Account Name is required'); return; }
            if (!ACCOUNT_NAME_RE.test(name) || isNonAccountStanza(name)) {
                showDuoError('Account Name is 1-64 letters, digits, "_" or "-", starting with a letter or digit');
                return;
            }
            if (allAccounts.some(function(a) { return a.name === name; })) {
                showDuoError('An account named "' + name + '" already exists; choose another name');
                return;
            }
        }
        var url = normalizeDuoApiUrl($('#duo-api-hostname').val());
        if (url.error) { showDuoError(url.error); return; }
        var ikey = validateDuoIkey($('#duo-integration-key').val());
        if (ikey.error) { showDuoError(ikey.error); return; }

        var data = { url: url.url, auth_type: 'duo_hmac', client_id: ikey.value };
        if (!duoEditMode || String(secret || '').trim()) {
            var skey = validateDuoSkey(secret);
            if (skey.error) { showDuoError(skey.error); return; }
            data.client_secret = skey.value;
        }
        if (!duoEditMode) { data.name = name; }

        var target = duoEditMode ? HANDLER_ENDPOINT + '/' + encodeURIComponent(name) : HANDLER_ENDPOINT;
        var $btn = $('#btn-duo-save');
        $btn.prop('disabled', true).text('Saving...');
        $.ajax({
            url: target + '?output_mode=json',
            type: 'POST',
            data: data,
            headers: { 'X-Splunk-Form-Key': getCSRFToken() },
            success: function() {
                $('#duo-secret-key').val('');
                hideModal('duo-account-modal');
                $btn.prop('disabled', false).text(duoEditMode ? 'Save' : 'Add');
                loadAccounts();
            },
            error: function(xhr) {
                console.log('Cisco Duo account save failed: HTTP', xhr.status);
                showDuoError('Failed to save: ' + handlerErrorMessage(xhr));
                $btn.prop('disabled', false).text(duoEditMode ? 'Save' : 'Add');
            }
        });
    }

    function deleteDuoAccount(name) {
        $('#duo-page-error').removeClass('show').text('');
        $.ajax({
            url: HANDLER_ENDPOINT + '/' + encodeURIComponent(name) + '?output_mode=json',
            type: 'DELETE',
            headers: { 'X-Splunk-Form-Key': getCSRFToken() },
            success: function() {
                hideModal('delete-modal');
                loadAccounts();
            },
            error: function(xhr) {
                console.log('Cisco Duo account delete failed: HTTP', xhr.status);
                hideModal('delete-modal');
                $('#duo-page-error').addClass('show').text('Failed to delete account: ' + handlerErrorMessage(xhr));
            }
        });
    }

    // ==================== GenAI Settings Functions ====================
    
    // Load GenAI settings from conf file
    function loadGenAISettings() {
        console.log('Loading GenAI settings from:', GENAI_CONF_ENDPOINT);
        
        $.ajax({
            url: GENAI_CONF_ENDPOINT,
            type: 'GET',
            data: { output_mode: 'json' },
            success: function(response) {
                console.log('GenAI settings response:', response);
                
                if (response.entry) {
                    response.entry.forEach(function(entry) {
                        if (entry.name === 'settings') {
                            var content = entry.content || {};
                            genaiSettings = {
                                enabled: content.enabled === '1' || content.enabled === 'true'
                            };
                        }
                    });
                }
                
                console.log('Loaded GenAI settings:', genaiSettings);
                applyGenAISettings();
            },
            error: function(xhr) {
                console.log('GenAI settings load error:', xhr.status);
                // Use defaults
                genaiSettings = {
                    enabled: false
                };
                applyGenAISettings();
            }
        });
    }
    
    // Apply GenAI settings to UI
    function applyGenAISettings() {
        $('#genai-enabled').prop('checked', genaiSettings.enabled);
        updateToggleStatus();
    }
    
    
    // Update toggle status label
    function updateToggleStatus() {
        var enabled = $('#genai-enabled').is(':checked');
        var $label = $('#toggle-status');
        if (enabled) {
            $label.text('Enabled').addClass('enabled');
        } else {
            $label.text('Disabled').removeClass('enabled');
        }
    }
    
    // Save GenAI settings
    function saveGenAISettings() {
        var enabled = $('#genai-enabled').is(':checked');
        
        $('#btn-save-genai').prop('disabled', true).text('Saving...');
        
        var csrfToken = getCSRFToken();
        var confData = {
            enabled: enabled ? '1' : '0',
            output_mode: 'json'
        };
        
        // Save to conf file
        $.ajax({
            url: GENAI_CONF_ENDPOINT + '/settings',
            type: 'POST',
            data: confData,
            headers: { 'X-Splunk-Form-Key': csrfToken },
            success: function() {
                console.log('GenAI settings saved');
                $('#btn-save-genai').prop('disabled', false).text('Save Settings');
                showGenAIStatus('Settings saved successfully', 'success');
            },
            error: function(xhr) {
                console.log('Save error:', xhr.status, xhr.responseText);
                // Try to create the stanza first
                confData.name = 'settings';
                $.ajax({
                    url: GENAI_CONF_ENDPOINT,
                    type: 'POST',
                    data: confData,
                    headers: { 'X-Splunk-Form-Key': csrfToken },
                    success: function() {
                        console.log('GenAI settings stanza created');
                        $('#btn-save-genai').prop('disabled', false).text('Save Settings');
                        showGenAIStatus('Settings saved successfully', 'success');
                    },
                    error: function(xhr2) {
                        $('#btn-save-genai').prop('disabled', false).text('Save Settings');
                        showGenAIStatus('Failed to save settings: ' + xhr2.status, 'error');
                    }
                });
            }
        });
    }
    
    // Show GenAI status message
    function showGenAIStatus(message, type) {
        var $status = $('#genai-save-status');
        $status.text(message).removeClass('success error');
        if (type) {
            $status.addClass(type);
        }
        
        // Auto-hide success messages
        if (type === 'success') {
            setTimeout(function() {
                $status.text('');
            }, 3000);
        }
    }
    
    // ==================== AI Asset Discovery Settings Functions ====================

    function loadAssetDiscoverySettings() {
        console.log('Loading AI Asset Discovery settings from:', CONF_ENDPOINT);

        $.ajax({
            url: CONF_ENDPOINT + '/asset_discovery',
            type: 'GET',
            data: { output_mode: 'json' },
            success: function(response) {
                console.log('Asset discovery settings response:', response);
                var content = (response.entry && response.entry[0] && response.entry[0].content) || {};
                $('#ai-system-table').val(content.ai_system_table || '');
                $('#ai-system-match-field').val(content.ai_system_match_field || '');
                $('#ai-system-approval-field').val(content.ai_system_approval_field || '');
                $('#ai-system-approved-values').val(content.ai_system_approved_values || '');
                $('#ai-model-table').val(content.ai_model_table || '');
                $('#ai-model-match-field').val(content.ai_model_match_field || '');
                $('#ai-model-approval-field').val(content.ai_model_approval_field || '');
                $('#ai-model-approved-values').val(content.ai_model_approved_values || '');
            },
            error: function(xhr) {
                console.log('Asset discovery settings load error:', xhr.status);
            }
        });
    }

    function saveAssetDiscoverySettings() {
        $('#btn-save-asset-discovery').prop('disabled', true).text('Saving...');

        var csrfToken = getCSRFToken();
        var confData = {
            ai_system_table: $('#ai-system-table').val().trim(),
            ai_system_match_field: $('#ai-system-match-field').val().trim(),
            ai_system_approval_field: $('#ai-system-approval-field').val().trim(),
            ai_system_approved_values: $('#ai-system-approved-values').val().trim(),
            ai_model_table: $('#ai-model-table').val().trim(),
            ai_model_match_field: $('#ai-model-match-field').val().trim(),
            ai_model_approval_field: $('#ai-model-approval-field').val().trim(),
            ai_model_approved_values: $('#ai-model-approved-values').val().trim(),
            output_mode: 'json'
        };

        $.ajax({
            url: CONF_ENDPOINT + '/asset_discovery',
            type: 'POST',
            data: confData,
            headers: { 'X-Splunk-Form-Key': csrfToken },
            success: function() {
                console.log('Asset discovery settings saved');
                $('#btn-save-asset-discovery').prop('disabled', false).text('Save Settings');
                showAssetDiscoveryStatus('Settings saved successfully', 'success');
            },
            error: function(xhr) {
                console.log('Asset discovery save error:', xhr.status, xhr.responseText);
                $('#btn-save-asset-discovery').prop('disabled', false).text('Save Settings');
                showAssetDiscoveryStatus('Failed to save settings: ' + xhr.status, 'error');
            }
        });
    }

    function showAssetDiscoveryStatus(message, type) {
        var $status = $('#asset-discovery-save-status');
        $status.text(message).removeClass('success error');
        if (type) {
            $status.addClass(type);
        }
        if (type === 'success') {
            setTimeout(function() {
                $status.text('');
            }, 3000);
        }
    }

    // ==================== Detection Settings Functions ====================
    
    // Load Detection settings from conf file
    function loadDetectionSettings() {
        console.log('Loading Detection settings from:', DETECTION_CONF_ENDPOINT);
        
        $.ajax({
            url: DETECTION_CONF_ENDPOINT,
            type: 'GET',
            data: { output_mode: 'json' },
            success: function(response) {
                console.log('Detection settings response:', response);
                
                if (response.entry) {
                    response.entry.forEach(function(entry) {
                        if (entry.name === 'settings') {
                            var content = entry.content || {};
                            detectionSettings = {
                                detect_pii: content.detect_pii === '1' || content.detect_pii === 'true' || content.detect_pii === true,
                                detect_phi: content.detect_phi === '1' || content.detect_phi === 'true' || content.detect_phi === true,
                                detect_prompt_injection: content.detect_prompt_injection === '1' || content.detect_prompt_injection === 'true' || content.detect_prompt_injection === true,
                                detect_anomalies: content.detect_anomalies === '1' || content.detect_anomalies === 'true' || content.detect_anomalies === true,
                                random_escalation: content.random_escalation === '1' || content.random_escalation === 'true' || content.random_escalation === true,
                                rng_seed: content.rng_seed || ''
                            };
                        }
                    });
                }
                
                // Default to all disabled if not set
                if (Object.keys(detectionSettings).length === 0) {
                    detectionSettings = {
                        detect_pii: false,
                        detect_phi: false,
                        detect_prompt_injection: false,
                        detect_anomalies: false,
                        random_escalation: false,
                        rng_seed: ''
                    };
                }
                
                console.log('Loaded Detection settings:', detectionSettings);
                applyDetectionSettings();
            },
            error: function(xhr) {
                console.log('Detection settings load error:', xhr.status);
                // Use defaults (all disabled)
                detectionSettings = {
                    detect_pii: true,
                    detect_phi: true,
                    detect_prompt_injection: true,
                    detect_anomalies: true,
                    random_escalation: false,
                    rng_seed: ''
                };
                applyDetectionSettings();
            }
        });
    }
    
    // Apply Detection settings to UI
    function applyDetectionSettings() {
        $('#detect-pii').prop('checked', detectionSettings.detect_pii);
        $('#detect-phi').prop('checked', detectionSettings.detect_phi);
        $('#detect-prompt-injection').prop('checked', detectionSettings.detect_prompt_injection);
        $('#detect-anomalies').prop('checked', detectionSettings.detect_anomalies);
        $('#random-escalation').prop('checked', detectionSettings.random_escalation);
        $('#rng-seed').val(detectionSettings.rng_seed);
        
        updateDetectionToggleStatus('detect-pii', detectionSettings.detect_pii);
        updateDetectionToggleStatus('detect-phi', detectionSettings.detect_phi);
        updateDetectionToggleStatus('detect-prompt-injection', detectionSettings.detect_prompt_injection);
        updateDetectionToggleStatus('detect-anomalies', detectionSettings.detect_anomalies);
        updateDetectionToggleStatus('random-escalation', detectionSettings.random_escalation);
        updateRngSeedFieldState();
    }
    
    // Update RNG Seed field state based on Random Escalation toggle
    function updateRngSeedFieldState() {
        var enabled = $('#random-escalation').is(':checked');
        if (enabled) {
            $('#rng-seed-group').removeClass('disabled');
            $('#rng-seed').prop('disabled', false);
        } else {
            $('#rng-seed-group').addClass('disabled');
            $('#rng-seed').prop('disabled', true);
        }
    }
    
    // Update individual detection toggle status label
    function updateDetectionToggleStatus(toggleId, enabled) {
        var $label = $('#' + toggleId + '-status');
        if (enabled) {
            $label.text('Enabled').addClass('enabled');
        } else {
            $label.text('Disabled').removeClass('enabled');
        }
    }
    
    // Save Detection settings
    function saveDetectionSettings() {
        var detectPii = $('#detect-pii').is(':checked');
        var detectPhi = $('#detect-phi').is(':checked');
        var detectPromptInjection = $('#detect-prompt-injection').is(':checked');
        var detectAnomalies = $('#detect-anomalies').is(':checked');
        var randomEscalation = $('#random-escalation').is(':checked');
        var rngSeed = $('#rng-seed').val().trim();
        
        // Validate RNG seed - only alphanumeric characters allowed
        if (randomEscalation && rngSeed && !/^[a-zA-Z0-9]+$/.test(rngSeed)) {
            showDetectionStatus('RNG Seed must contain only alphanumeric characters', 'error');
            return;
        }
        
        $('#btn-save-detection').prop('disabled', true).text('Saving...');
        
        var csrfToken = getCSRFToken();
        var confData = {
            detect_pii: detectPii ? '1' : '0',
            detect_phi: detectPhi ? '1' : '0',
            detect_prompt_injection: detectPromptInjection ? '1' : '0',
            detect_anomalies: detectAnomalies ? '1' : '0',
            random_escalation: randomEscalation ? '1' : '0',
            rng_seed: rngSeed,
            output_mode: 'json'
        };
        
        // Save to conf file
        $.ajax({
            url: DETECTION_CONF_ENDPOINT + '/settings',
            type: 'POST',
            data: confData,
            headers: { 'X-Splunk-Form-Key': csrfToken },
            success: function() {
                console.log('Detection settings saved');
                detectionSettings = {
                    detect_pii: detectPii,
                    detect_phi: detectPhi,
                    detect_prompt_injection: detectPromptInjection,
                    detect_anomalies: detectAnomalies,
                    random_escalation: randomEscalation,
                    rng_seed: rngSeed
                };
                $('#btn-save-detection').prop('disabled', false).text('Save Settings');
                showDetectionStatus('Settings saved successfully', 'success');
            },
            error: function(xhr) {
                console.log('Save error:', xhr.status, xhr.responseText);
                // Try to create the stanza first
                confData.name = 'settings';
                $.ajax({
                    url: DETECTION_CONF_ENDPOINT,
                    type: 'POST',
                    data: confData,
                    headers: { 'X-Splunk-Form-Key': csrfToken },
                    success: function() {
                        console.log('Detection settings stanza created');
                        detectionSettings = {
                            detect_pii: detectPii,
                            detect_phi: detectPhi,
                            detect_prompt_injection: detectPromptInjection,
                            detect_anomalies: detectAnomalies,
                            random_escalation: randomEscalation,
                            rng_seed: rngSeed
                        };
                        $('#btn-save-detection').prop('disabled', false).text('Save Settings');
                        showDetectionStatus('Settings saved successfully', 'success');
                    },
                    error: function(xhr2) {
                        $('#btn-save-detection').prop('disabled', false).text('Save Settings');
                        showDetectionStatus('Failed to save settings: ' + xhr2.status, 'error');
                    }
                });
            }
        });
    }
    
    // Show Detection status message
    function showDetectionStatus(message, type) {
        var $status = $('#detection-save-status');
        $status.text(message).removeClass('success error');
        if (type) {
            $status.addClass(type);
        }
        
        // Auto-hide success messages
        if (type === 'success') {
            setTimeout(function() {
                $status.text('');
            }, 3000);
        }
    }
    
    // Switch tabs
    function switchTab(tabName) {
        $('.config-tab').removeClass('active');
        $('.config-tab[data-tab="' + tabName + '"]').addClass('active');
        $('.config-tab-content').removeClass('active');
        $('#tab-' + tabName).addClass('active');
    }

    // Initialize
    $(document).ready(function() {
        console.log('ServiceNow Config JS initialized');
        console.log('Locale prefix:', localePrefix);
        console.log('CONF_ENDPOINT:', CONF_ENDPOINT);
        console.log('PASSWORDS_ENDPOINT:', PASSWORDS_ENDPOINT);

        // Load initial data
        loadAccounts();
        loadAssetDiscoverySettings();
        loadGenAISettings();
        loadDetectionSettings();

        // Auth type change
        $('#account-auth-type').on('change', updateAuthFields);

        // Add account button
        $('#btn-add-account').on('click', function() {
            editMode = false;
            clearForm();
            $('#modal-title').text('Add ServiceNow Account');
            $('#btn-save').text('Add');
            showModal('account-modal');
        });

        // Edit account
        $(document).on('click', '.edit-account', function(e) {
            e.preventDefault();
            var name = $(this).closest('tr').data('name');
            var account = accounts.find(function(a) { return a.name === name; });
            
            if (account) {
                editMode = true;
                clearForm();
                $('#modal-title').text('Edit ServiceNow Account');
                $('#btn-save').text('Save');
                $('#account-name').val(account.name).prop('disabled', true);
                $('#account-url').val(account.url);
                
                // Set auth type - use prop for more reliable selection
                var authTypeToSet = account.auth_type || 'basic';
                console.log('Setting auth_type to:', authTypeToSet);
                
                var $select = $('#account-auth-type');
                $select.find('option').prop('selected', false);
                $select.find('option[value="' + authTypeToSet + '"]').prop('selected', true);
                $select.trigger('change');
                
                console.log('Auth type after set:', $select.val());
                
                $('#edit-account-name').val(account.name);
                
                if (account.auth_type === 'basic') {
                    $('#basic-username').val(account.username);
                    $('#basic-password').val('********');
                } else if (account.auth_type === 'oauth_client_creds') {
                    $('#oauth-cc-client-id').val(account.client_id);
                    $('#oauth-cc-client-secret').val('********');
                }
                
                updateAuthFields();
                showModal('account-modal');
            }
        });

        // Delete account click
        $(document).on('click', '.delete-account', function(e) {
            e.preventDefault();
            var name = $(this).closest('tr').data('name');
            $('#delete-account-name').text(name);
            $('#btn-delete-confirm').data('name', name).data('kind', 'servicenow');
            showModal('delete-modal');
        });

        // ==================== Cisco Duo Tab Event Handlers ====================

        $('#btn-add-duo-account').on('click', function() {
            openDuoModal(null);
        });

        $(document).on('click', '.edit-duo-account', function(e) {
            e.preventDefault();
            var name = String($(this).closest('tr').data('name'));
            var account = duoAccounts.find(function(a) { return a.name === name; });
            if (account) {
                openDuoModal(account);
            }
        });

        $(document).on('click', '.delete-duo-account', function(e) {
            e.preventDefault();
            var name = String($(this).closest('tr').data('name'));
            $('#delete-account-name').text(name);
            $('#btn-delete-confirm').data('name', name).data('kind', 'duo');
            showModal('delete-modal');
        });

        $('#duo-modal-close, #btn-duo-cancel').on('click', function() {
            $('#duo-secret-key').val('');
            hideModal('duo-account-modal');
        });

        $('#btn-duo-save').on('click', saveDuoAccount);

        $('#duo-account-form input').on('keypress', function(e) {
            if (e.which === 13) {
                e.preventDefault();
                saveDuoAccount();
            }
        });

        $('#duo-account-search').on('input', function() {
            var searchTerm = $(this).val().toLowerCase();
            $('#duo-accounts-tbody tr').each(function() {
                var name = $(this).data('name');
                if (name) {
                    $(this).toggle(String(name).toLowerCase().indexOf(searchTerm) !== -1);
                }
            });
        });

        // Modal close buttons
        $('#modal-close, #btn-cancel').on('click', function() {
            hideModal('account-modal');
        });

        $('#delete-modal-close, #btn-delete-cancel').on('click', function() {
            hideModal('delete-modal');
        });

        // Save button
        $('#btn-save').on('click', saveAccount);

        // Delete confirm: a Cisco Duo account is removed through the handler
        $('#btn-delete-confirm').on('click', function() {
            var name = $(this).data('name');
            if ($(this).data('kind') === 'duo') {
                deleteDuoAccount(String(name));
            } else {
                deleteAccount(name);
            }
        });

        // Close modals on overlay click
        $('.modal-overlay').on('click', function(e) {
            if (e.target === this) {
                $(this).find('input[type="password"]').val('');
                $(this).removeClass('show');
            }
        });

        // Search
        $('#account-search').on('input', function() {
            var searchTerm = $(this).val().toLowerCase();
            $('#accounts-tbody tr').each(function() {
                var name = $(this).data('name');
                if (name) {
                    $(this).toggle(name.toLowerCase().indexOf(searchTerm) !== -1);
                }
            });
        });

        // Enter key in form
        $('#account-form input').on('keypress', function(e) {
            if (e.which === 13) {
                e.preventDefault();
                saveAccount();
            }
        });
        
        // ==================== GenAI Tab Event Handlers ====================
        
        // Tab switching
        $(document).on('click', '.config-tab', function() {
            var tabName = $(this).data('tab');
            switchTab(tabName);
        });
        
        // Toggle switch change
        $('#genai-enabled').on('change', function() {
            updateToggleStatus();
        });
        
        // Save GenAI settings
        $('#btn-save-genai').on('click', saveGenAISettings);
        
        // ==================== Detection Tab Event Handlers ====================
        
        // Detection toggle changes
        $('#detect-pii').on('change', function() {
            updateDetectionToggleStatus('detect-pii', $(this).is(':checked'));
        });
        
        $('#detect-phi').on('change', function() {
            updateDetectionToggleStatus('detect-phi', $(this).is(':checked'));
        });
        
        $('#detect-prompt-injection').on('change', function() {
            updateDetectionToggleStatus('detect-prompt-injection', $(this).is(':checked'));
        });
        
        $('#detect-anomalies').on('change', function() {
            updateDetectionToggleStatus('detect-anomalies', $(this).is(':checked'));
        });
        
        $('#random-escalation').on('change', function() {
            updateDetectionToggleStatus('random-escalation', $(this).is(':checked'));
            updateRngSeedFieldState();
        });
        
        // Save Detection settings
        $('#btn-save-detection').on('click', saveDetectionSettings);
        
        // Save AI Asset Discovery settings
        $('#btn-save-asset-discovery').on('click', saveAssetDiscoverySettings);
    });
});
