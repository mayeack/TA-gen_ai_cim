/**
 * GenAI Scoring Configuration Page JavaScript
 * Manages scoring pipeline configuration via ta_gen_ai_cim_genai_scoring.conf
 * and syncs saved search enable/disable state.
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
    'use strict';

    var APP_NAME = 'TA-gen_ai_cim';
    var SCORING_CONF_NAME = 'ta_gen_ai_cim_genai_scoring';
    var PIPELINE_COUNT = 10;

    var localeMatch = window.location.pathname.match(/^\/[a-z]{2}[-_][A-Z]{2}\//);
    var localePrefix = localeMatch ? localeMatch[0].slice(0, -1) : '';

    var SCORING_CONF_ENDPOINT = localePrefix + '/splunkd/__raw/servicesNS/nobody/' + APP_NAME + '/configs/conf-' + SCORING_CONF_NAME;
    var SAVED_SEARCHES_ENDPOINT = localePrefix + '/splunkd/__raw/servicesNS/nobody/' + APP_NAME + '/saved/searches';

    var systemPrompt = '';
    var pipelines = {};

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

    function showStatus(elementId, message, type) {
        var $status = $('#' + elementId);
        $status.text(message).removeClass('success error').addClass(type || '');
        if (type === 'success') {
            setTimeout(function() { $status.text(''); }, 3000);
        }
    }

    function loadConfig() {
        $.ajax({
            url: SCORING_CONF_ENDPOINT,
            type: 'GET',
            data: { output_mode: 'json', count: 20 },
            success: function(response) {
                if (response.entry) {
                    response.entry.forEach(function(entry) {
                        var content = entry.content || {};
                        if (entry.name === 'settings') {
                            systemPrompt = content.system_prompt || '';
                        } else if (entry.name.indexOf('pipeline_') === 0) {
                            pipelines[entry.name] = {
                                enabled: content.enabled === '1' || content.enabled === 'true',
                                name: content.pipeline_name || '',
                                prompt: content.prompt || ''
                            };
                        }
                    });
                }

                for (var i = 1; i <= PIPELINE_COUNT; i++) {
                    var key = 'pipeline_' + i;
                    if (!pipelines[key]) {
                        pipelines[key] = { enabled: false, name: '', prompt: '' };
                    }
                }

                renderSystemPrompt();
                renderPipelines();
            },
            error: function(xhr) {
                console.error('Failed to load scoring config:', xhr.status);
                for (var i = 1; i <= PIPELINE_COUNT; i++) {
                    pipelines['pipeline_' + i] = { enabled: false, name: '', prompt: '' };
                }
                renderSystemPrompt();
                renderPipelines();
            }
        });
    }

    function renderSystemPrompt() {
        $('#system-prompt').val(systemPrompt);
    }

    function renderPipelines() {
        var $container = $('#pipelines-container');
        $container.empty();

        for (var i = 1; i <= PIPELINE_COUNT; i++) {
            var key = 'pipeline_' + i;
            var p = pipelines[key];
            var enabledClass = p.enabled ? 'enabled' : '';
            var checkedAttr = p.enabled ? 'checked="checked"' : '';
            var statusText = p.enabled ? 'Enabled' : 'Disabled';
            var statusClass = p.enabled ? 'enabled' : '';
            var nameVal = $('<div/>').text(p.name).html();
            var promptVal = $('<div/>').text(p.prompt).html();

            var card = [
                '<div class="pipeline-card ' + enabledClass + '" data-pipeline="' + key + '">',
                '  <div class="pipeline-header">',
                '    <div class="pipeline-title">',
                '      <span class="pipeline-number">Pipeline ' + i + '</span>',
                '      <span class="pipeline-name-display">' + (nameVal ? ' - ' + nameVal : '') + '</span>',
                '    </div>',
                '    <div class="pipeline-toggle">',
                '      <label class="toggle-switch">',
                '        <input type="checkbox" class="pipeline-enabled" data-pipeline="' + key + '" ' + checkedAttr + ' />',
                '        <span class="toggle-slider"></span>',
                '      </label>',
                '      <span class="toggle-label ' + statusClass + '" id="status-' + key + '">' + statusText + '</span>',
                '    </div>',
                '  </div>',
                '  <div class="pipeline-body">',
                '    <div class="form-group">',
                '      <label>Pipeline Name</label>',
                '      <input type="text" class="pipeline-name" data-pipeline="' + key + '" value="' + nameVal + '" placeholder="e.g., pii, toxicity, compliance" />',
                '      <div class="help-text">Lowercase alphanumeric and underscores only. Used in field names (gen_ai.&lt;name&gt;.*) and source (&lt;name&gt;_genai_scoring).</div>',
                '    </div>',
                '    <div class="form-group">',
                '      <label>Scoring Prompt</label>',
                '      <textarea class="pipeline-prompt" data-pipeline="' + key + '" rows="4" placeholder="Describe what this pipeline should score events for...">' + promptVal + '</textarea>',
                '      <div class="help-text">Pipeline-specific instructions for the LLM. Event data is automatically appended.</div>',
                '    </div>',
                '    <div class="pipeline-meta">',
                '      <span class="meta-item"><strong>Source:</strong> <code>' + (nameVal || '&lt;name&gt;') + '_genai_scoring</code></span>',
                '      <span class="meta-item"><strong>Sourcetype:</strong> <code>ai_cim:' + (nameVal || '&lt;name&gt;') + ':gen_ai_scoring</code></span>',
                '      <span class="meta-item"><strong>Schedule:</strong> Every 1 minute</span>',
                '    </div>',
                '    <div class="pipeline-actions">',
                '      <button class="btn btn-primary btn-save-pipeline" data-pipeline="' + key + '">Save Pipeline</button>',
                '      <span class="save-status" id="pipeline-status-' + key + '"></span>',
                '    </div>',
                '  </div>',
                '</div>'
            ].join('\n');

            $container.append(card);
        }

        bindPipelineEvents();
    }

    function bindPipelineEvents() {
        $('.pipeline-enabled').off('change').on('change', function() {
            var key = $(this).data('pipeline');
            var enabled = $(this).is(':checked');
            var $card = $(this).closest('.pipeline-card');
            var $label = $('#status-' + key);

            if (enabled) {
                $card.addClass('enabled');
                $label.text('Enabled').addClass('enabled');
            } else {
                $card.removeClass('enabled');
                $label.text('Disabled').removeClass('enabled');
            }

            updatePipelineMeta(key);
        });

        $('.pipeline-name').off('input').on('input', function() {
            var key = $(this).data('pipeline');
            var val = $(this).val().replace(/[^a-z0-9_]/g, '');
            $(this).val(val);
            updatePipelineMeta(key);
        });

        $('.btn-save-pipeline').off('click').on('click', function() {
            var key = $(this).data('pipeline');
            savePipeline(key);
        });
    }

    function updatePipelineMeta(key) {
        var $card = $('[data-pipeline="' + key + '"].pipeline-card');
        var name = $card.find('.pipeline-name').val() || '<name>';
        $card.find('.pipeline-name-display').text(name !== '<name>' ? ' - ' + name : '');
        $card.find('.meta-item').eq(0).html('<strong>Source:</strong> <code>' + name + '_genai_scoring</code>');
        $card.find('.meta-item').eq(1).html('<strong>Sourcetype:</strong> <code>ai_cim:' + name + ':gen_ai_scoring</code>');
    }

    function savePipeline(key) {
        var $card = $('[data-pipeline="' + key + '"].pipeline-card');
        var enabled = $card.find('.pipeline-enabled').is(':checked');
        var name = $card.find('.pipeline-name').val().trim();
        var prompt = $card.find('.pipeline-prompt').val().trim();

        if (enabled && !name) {
            showStatus('pipeline-status-' + key, 'Pipeline name is required when enabled', 'error');
            return;
        }
        if (enabled && !prompt) {
            showStatus('pipeline-status-' + key, 'Scoring prompt is required when enabled', 'error');
            return;
        }
        if (name && !/^[a-z0-9_]+$/.test(name)) {
            showStatus('pipeline-status-' + key, 'Name must be lowercase alphanumeric and underscores only', 'error');
            return;
        }

        var $btn = $card.find('.btn-save-pipeline');
        $btn.prop('disabled', true).text('Saving...');

        var csrfToken = getCSRFToken();
        var confData = {
            enabled: enabled ? '1' : '0',
            pipeline_name: name,
            prompt: prompt,
            output_mode: 'json'
        };

        $.ajax({
            url: SCORING_CONF_ENDPOINT + '/' + key,
            type: 'POST',
            data: confData,
            headers: { 'X-Splunk-Form-Key': csrfToken },
            success: function() {
                pipelines[key] = { enabled: enabled, name: name, prompt: prompt };
                syncSavedSearch(key, enabled, function(err) {
                    $btn.prop('disabled', false).text('Save Pipeline');
                    if (err) {
                        showStatus('pipeline-status-' + key, 'Config saved but failed to sync saved search: ' + err, 'error');
                    } else {
                        showStatus('pipeline-status-' + key, 'Pipeline saved successfully', 'success');
                    }
                });
            },
            error: function(xhr) {
                $.ajax({
                    url: SCORING_CONF_ENDPOINT,
                    type: 'POST',
                    data: $.extend({ name: key }, confData),
                    headers: { 'X-Splunk-Form-Key': csrfToken },
                    success: function() {
                        pipelines[key] = { enabled: enabled, name: name, prompt: prompt };
                        syncSavedSearch(key, enabled, function(err) {
                            $btn.prop('disabled', false).text('Save Pipeline');
                            showStatus('pipeline-status-' + key, 'Pipeline saved successfully', 'success');
                        });
                    },
                    error: function(xhr2) {
                        $btn.prop('disabled', false).text('Save Pipeline');
                        showStatus('pipeline-status-' + key, 'Failed to save: ' + xhr2.status, 'error');
                    }
                });
            }
        });
    }

    function syncSavedSearch(pipelineKey, enabled, callback) {
        var pipelineNum = pipelineKey.replace('pipeline_', '');
        var searchName = 'GenAI Scoring - Pipeline ' + pipelineNum;
        var encodedName = encodeURIComponent(searchName);
        var csrfToken = getCSRFToken();

        $.ajax({
            url: SAVED_SEARCHES_ENDPOINT + '/' + encodedName,
            type: 'POST',
            data: {
                disabled: enabled ? '0' : '1',
                output_mode: 'json'
            },
            headers: { 'X-Splunk-Form-Key': csrfToken },
            success: function() {
                console.log('Saved search ' + searchName + ' ' + (enabled ? 'enabled' : 'disabled'));
                if (callback) callback(null);
            },
            error: function(xhr) {
                console.error('Failed to sync saved search:', xhr.status);
                if (callback) callback('HTTP ' + xhr.status);
            }
        });
    }

    function saveSystemPrompt() {
        var prompt = $('#system-prompt').val().trim();
        if (!prompt) {
            showStatus('system-prompt-status', 'System prompt cannot be empty', 'error');
            return;
        }

        $('#btn-save-system-prompt').prop('disabled', true).text('Saving...');
        var csrfToken = getCSRFToken();

        $.ajax({
            url: SCORING_CONF_ENDPOINT + '/settings',
            type: 'POST',
            data: {
                system_prompt: prompt,
                output_mode: 'json'
            },
            headers: { 'X-Splunk-Form-Key': csrfToken },
            success: function() {
                systemPrompt = prompt;
                $('#btn-save-system-prompt').prop('disabled', false).text('Save System Prompt');
                showStatus('system-prompt-status', 'System prompt saved successfully', 'success');
            },
            error: function(xhr) {
                $.ajax({
                    url: SCORING_CONF_ENDPOINT,
                    type: 'POST',
                    data: {
                        name: 'settings',
                        system_prompt: prompt,
                        output_mode: 'json'
                    },
                    headers: { 'X-Splunk-Form-Key': csrfToken },
                    success: function() {
                        systemPrompt = prompt;
                        $('#btn-save-system-prompt').prop('disabled', false).text('Save System Prompt');
                        showStatus('system-prompt-status', 'System prompt saved successfully', 'success');
                    },
                    error: function(xhr2) {
                        $('#btn-save-system-prompt').prop('disabled', false).text('Save System Prompt');
                        showStatus('system-prompt-status', 'Failed to save: ' + xhr2.status, 'error');
                    }
                });
            }
        });
    }

    $('#btn-save-system-prompt').on('click', function() {
        saveSystemPrompt();
    });

    loadConfig();
});
