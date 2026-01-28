/**
 * ServiceNow Configuration Page JavaScript
 * Handles account management using Splunk's built-in conf REST API
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
    var accounts = [];
    var editMode = false;
    var genaiSettings = {};
    var detectionSettings = {};

    // Get CSRF token
    function getCSRFToken() {
        var token = $('input[name="splunk_form_key"]').val();
        if (!token) {
            var cookies = document.cookie.split(';');
            for (var i = 0; i < cookies.length; i++) {
                var cookie = cookies[i].trim();
                if (cookie.indexOf('splunkweb_csrf_token_') === 0) {
                    token = cookie.split('=')[1];
                    break;
                }
            }
        }
        return token;
    }

    // Format auth type for display
    function formatAuthType(authType) {
        var types = {
            'basic': 'Basic Authentication',
            'oauth_client_creds': 'OAuth 2.0 (Client Credentials)'
        };
        return types[authType] || authType || 'Basic Authentication';
    }

    // Load accounts from conf file using configs endpoint
    function loadAccounts() {
        console.log('Loading accounts from:', CONF_ENDPOINT);
        accounts = [];
        
        $.ajax({
            url: CONF_ENDPOINT,
            type: 'GET',
            data: { output_mode: 'json' },
            success: function(response) {
                console.log('Accounts response:', response);
                
                if (response.entry) {
                    response.entry.forEach(function(entry) {
                        // Skip default stanza
                        if (entry.name !== 'default' && !entry.name.startsWith('_')) {
                            var content = entry.content || {};
                            accounts.push({
                                name: entry.name,
                                url: content.url || '',
                                auth_type: content.auth_type || 'basic',
                                username: content.username || '',
                                client_id: content.client_id || ''
                            });
                        }
                    });
                }
                
                console.log('Found accounts:', accounts);
                renderAccountsTable();
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
                
                if (response.entry) {
                    response.entry.forEach(function(entry) {
                        if (entry.name !== 'default' && !entry.name.startsWith('_')) {
                            stanzaNames.push(entry.name);
                        }
                    });
                }
                
                if (stanzaNames.length === 0) {
                    renderAccountsTable();
                    return;
                }
                
                var loaded = 0;
                stanzaNames.forEach(function(name) {
                    loadStanzaDetails(name, function() {
                        loaded++;
                        if (loaded === stanzaNames.length) {
                            renderAccountsTable();
                        }
                    });
                });
            },
            error: function(xhr) {
                console.log('Properties load error:', xhr.status, xhr.statusText);
                renderAccountsTable();
            }
        });
    }
    
    // Load details for a specific stanza
    function loadStanzaDetails(stanzaName, callback) {
        $.ajax({
            url: PROPS_ENDPOINT + '/' + encodeURIComponent(stanzaName),
            type: 'GET',
            data: { output_mode: 'json' },
            success: function(response) {
                console.log('Stanza details for', stanzaName, ':', response);
                var account = {
                    name: stanzaName,
                    url: '',
                    auth_type: 'basic',
                    username: '',
                    client_id: ''
                };
                
                if (response.entry) {
                    response.entry.forEach(function(prop) {
                        var value = prop.content ? prop.content['$text'] : '';
                        if (prop.name === 'url') account.url = value || '';
                        else if (prop.name === 'auth_type') account.auth_type = value || 'basic';
                        else if (prop.name === 'username') account.username = value || '';
                        else if (prop.name === 'client_id') account.client_id = value || '';
                    });
                }
                
                accounts.push(account);
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

        if (accounts.length === 0) {
            $tbody.html('<tr class="no-records"><td colspan="3">No records found</td></tr>');
            return;
        }

        accounts.forEach(function(account) {
            var row = '<tr data-name="' + escapeHtml(account.name) + '">' +
                '<td>' + escapeHtml(account.name) + '</td>' +
                '<td>' + formatAuthType(account.auth_type) + '</td>' +
                '<td class="actions-cell">' +
                    '<a class="action-link edit-account" href="#">Edit</a>' +
                    '<a class="action-link delete delete-account" href="#">Delete</a>' +
                '</td>' +
            '</tr>';
            $tbody.append(row);
        });
    }

    // Escape HTML
    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;')
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
        if (!url) {
            showError('URL is required');
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
        console.log('Data:', confData);
        
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
                    console.log('Create error:', xhr.status, xhr.responseText);
                    if (xhr.status === 409) {
                        // Already exists, try update
                        updateAccount();
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
                
                // Default to all enabled if not set (except random_escalation)
                if (Object.keys(detectionSettings).length === 0) {
                    detectionSettings = {
                        detect_pii: true,
                        detect_phi: true,
                        detect_prompt_injection: true,
                        detect_anomalies: true,
                        random_escalation: false,
                        rng_seed: ''
                    };
                }
                
                console.log('Loaded Detection settings:', detectionSettings);
                applyDetectionSettings();
            },
            error: function(xhr) {
                console.log('Detection settings load error:', xhr.status);
                // Use defaults (all enabled except random_escalation)
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
            $('#btn-delete-confirm').data('name', name);
            showModal('delete-modal');
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

        // Delete confirm
        $('#btn-delete-confirm').on('click', function() {
            var name = $(this).data('name');
            deleteAccount(name);
        });

        // Close modals on overlay click
        $('.modal-overlay').on('click', function(e) {
            if (e.target === this) {
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
    });
});
