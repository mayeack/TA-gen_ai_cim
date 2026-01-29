/**
 * review_save.js - Handle Save Review Findings button
 * Uses KV Store REST API to save without requiring risky command approval
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
    
    console.log("=== REVIEW_SAVE.JS LOADED ===");
    
    var defaultTokens = mvc.Components.get("default");
    var submittedTokens = mvc.Components.get("submitted");
    
    // Load detection settings and control field visibility via CSS
    function loadDetectionSettings() {
        console.log("=== Loading detection settings for field visibility ===");
        
        // Use Splunk.util.make_url for reliable URL construction
        var detectionUrl = Splunk.util.make_url(
            '/splunkd/__raw/servicesNS/nobody/TA-gen_ai_cim/configs/conf-ta_gen_ai_cim_detection/settings'
        );
        
        console.log("Detection settings URL:", detectionUrl);
        
        $.ajax({
            url: detectionUrl,
            type: 'GET',
            data: { output_mode: 'json' },
            success: function(response) {
                console.log("Detection settings response:", response);
                
                if (response.entry && response.entry.length > 0) {
                    var content = response.entry[0].content || {};
                    console.log("Detection settings content:", content);
                    console.log("detect_pii:", content.detect_pii);
                    console.log("detect_phi:", content.detect_phi);
                    console.log("detect_prompt_injection:", content.detect_prompt_injection);
                    console.log("detect_anomalies:", content.detect_anomalies);
                    
                    // Apply visibility based on detection settings
                    applyDetectionVisibility('pii', content.detect_pii === '1' || content.detect_pii === 'true');
                    applyDetectionVisibility('phi', content.detect_phi === '1' || content.detect_phi === 'true');
                    applyDetectionVisibility('injection', content.detect_prompt_injection === '1' || content.detect_prompt_injection === 'true');
                    applyDetectionVisibility('anomaly', content.detect_anomalies === '1' || content.detect_anomalies === 'true');
                } else {
                    console.log("No detection settings entries found, showing all fields");
                    showAllDetectionFields();
                }
            },
            error: function(xhr) {
                console.error("Failed to load detection settings:", xhr.status, xhr.responseText);
                console.log("Defaulting to show all fields due to error");
                // Default to showing all fields if we can't load settings
                showAllDetectionFields();
            }
        });
    }
    
    // Apply visibility for a specific detection type
    // Uses multiple strategies to reliably find and hide/show input wrappers
    function applyDetectionVisibility(type, enabled) {
        console.log("=== applyDetectionVisibility called for:", type, "enabled:", enabled, "===");
        
        // Map type to input IDs (from event_review.xml)
        var inputIdMap = {
            'pii': ['input_pii_confirmed', 'pii_types_detected_display', 'input_pii_types_reviewed'],
            'phi': ['input_phi_confirmed', 'input_phi_types'],
            'injection': ['input_injection_confirmed', 'input_injection_type'],
            'anomaly': ['input_anomaly_prompt_detected', 'input_anomaly_prompt_reviewed', 'input_anomaly_response_detected', 'input_anomaly_response_reviewed']
        };
        
        // Map type to label texts as fallback
        var labelMap = {
            'pii': ['PII Present (Detected)', 'PII Types (Detected)', 'PII Types (Reviewed)'],
            'phi': ['PHI Present?', 'PHI Types'],
            'injection': ['Injection Detected?', 'Injection Type'],
            'anomaly': ['Prompt Anomaly (Detected)', 'Prompt Anomaly (Reviewed)', 'Response Anomaly (Detected)', 'Response Anomaly (Reviewed)']
        };
        
        var inputIds = inputIdMap[type] || [];
        var labels = labelMap[type] || [];
        var foundCount = 0;
        
        // Helper function to show/hide a wrapper element
        function setVisibility($wrapper, show, source) {
            if ($wrapper.length > 0) {
                foundCount++;
                if (show) {
                    $wrapper.removeClass('detection-hidden').addClass('detection-visible');
                    $wrapper.show();
                    console.log("Showing input via", source);
                } else {
                    $wrapper.removeClass('detection-visible').addClass('detection-hidden');
                    $wrapper.hide();
                    console.log("Hiding input via", source);
                }
            }
        }
        
        // Strategy 1: Find by input ID (most reliable)
        inputIds.forEach(function(inputId) {
            // Splunk wraps inputs in a div with id like "input_pii_confirmed"
            var $inputWrapper = $('#' + inputId);
            
            if ($inputWrapper.length > 0) {
                setVisibility($inputWrapper, enabled, "ID: " + inputId);
            } else {
                // Try finding wrapper with data-input-id attribute
                $inputWrapper = $('[data-input-id="' + inputId + '"]');
                if ($inputWrapper.length > 0) {
                    setVisibility($inputWrapper, enabled, "data-input-id: " + inputId);
                }
            }
        });
        
        // Strategy 2: Find by label text if ID approach didn't find all inputs
        if (foundCount < labels.length) {
            labels.forEach(function(labelText) {
                $('label').each(function() {
                    var $label = $(this);
                    if ($label.text().trim() === labelText) {
                        // Find the parent input wrapper (Splunk uses .input or .fieldset-item)
                        var $inputWrapper = $label.closest('.input, .splunk-view, .fieldset-item');
                        
                        if ($inputWrapper.length === 0) {
                            // Try going up to parent div with class containing 'input'
                            $inputWrapper = $label.parent().closest('[class*="input"]');
                        }
                        
                        if ($inputWrapper.length === 0) {
                            // Try the grandparent as a last resort
                            $inputWrapper = $label.parent().parent();
                        }
                        
                        if ($inputWrapper.length > 0) {
                            setVisibility($inputWrapper, enabled, "label: " + labelText);
                        }
                    }
                });
            });
        }
        
        console.log("applyDetectionVisibility for", type, "- found", foundCount, "inputs");
    }
    
    // Show all detection fields (default behavior)
    function showAllDetectionFields() {
        applyDetectionVisibility('pii', true);
        applyDetectionVisibility('phi', true);
        applyDetectionVisibility('injection', true);
        applyDetectionVisibility('anomaly', true);
    }
    
    // Load detection settings after a short delay to ensure DOM is ready
    console.log("Scheduling detection settings load...");
    setTimeout(function() {
        console.log("500ms timeout fired, calling loadDetectionSettings");
        loadDetectionSettings();
    }, 500);
    // Re-apply after longer delay in case of slower loading
    setTimeout(function() {
        console.log("2000ms timeout fired, calling loadDetectionSettings again");
        loadDetectionSettings();
    }, 2000);
    
    // Wait for button to be available, then attach handler
    function setupSaveButton() {
        var $btn = $('#saveReviewBtn');
        
        if ($btn.length === 0) {
            setTimeout(setupSaveButton, 500);
            return;
        }
        
        console.log("Save button found, attaching click handler");
        
        $btn.on('click', function(e) {
            e.preventDefault();
            console.log("=== SAVE BUTTON CLICKED ===");
            saveReviewFindings();
        });
        
        console.log("=== SAVE HANDLER READY ===");
    }
    
    function saveReviewFindings() {
        var $btn = $('#saveReviewBtn');
        var $msg = $('#saveStatusMsg');
        
        // Get event_id
        var eventId = defaultTokens.get("form.event_id") || defaultTokens.get("event_id");
        console.log("Event ID:", eventId);
        
        if (!eventId) {
            alert("Please select an Event ID first");
            return;
        }
        
        // Update UI
        $btn.prop('disabled', true).css('opacity', '0.6');
        $msg.html('<span style="color: #f0ad4e;">⏳ Saving...</span>');
        
        // Get current user
        var currentUser = "";
        try {
            currentUser = Splunk.util.getConfigValue("USERNAME") || "";
        } catch(e) {
            console.log("Could not get username");
        }
        
        // Get form values
        var getToken = function(name) {
            return defaultTokens.get("form." + name) || defaultTokens.get(name) || "";
        };
        
        var assignee = getToken("input_assignee");
        if (!assignee || assignee === "-- Unassigned --") {
            assignee = currentUser;
        }
        
        // Use underscore field names for KV Store REST API compatibility
        // (dotted field names don't work with REST API JSON payloads)
        // Note: gen_ai_review_pii_types stores detected PII types (from ML)
        //       gen_ai_review_pii_types_reviewed stores reviewer-confirmed PII types
        var record = {
            "_key": eventId,
            "gen_ai_event_id": eventId,
            "gen_ai_review_status": getToken("input_status") || "new",
            "gen_ai_review_priority": getToken("input_priority") || "medium",
            "gen_ai_review_assignee": assignee,
            "gen_ai_review_reviewer": currentUser,
            "gen_ai_review_pii_confirmed": getToken("input_pii_confirmed") || "n/a",
            "gen_ai_review_pii_types": getToken("input_pii_types_detected") || "",
            "gen_ai_review_pii_types_reviewed": getToken("input_pii_types_reviewed") || "",
            "gen_ai_review_phi_confirmed": getToken("input_phi_confirmed") || "false",
            "gen_ai_review_phi_types": getToken("input_phi_types") || "",
            "gen_ai_review_prompt_injection_confirmed": getToken("input_injection_confirmed") || "false",
            "gen_ai_review_prompt_injection_type": getToken("input_injection_type") || "",
            "gen_ai_review_anomaly_prompt_detected": getToken("input_anomaly_prompt_detected") || "n/a",
            "gen_ai_review_anomaly_prompt_reviewed": getToken("input_anomaly_prompt_reviewed") || "n/a",
            "gen_ai_review_anomaly_response_detected": getToken("input_anomaly_response_detected") || "n/a",
            "gen_ai_review_anomaly_response_reviewed": getToken("input_anomaly_response_reviewed") || "n/a",
            "gen_ai_review_notes": getNotesValue(),
            "gen_ai_review_updated_at": Math.floor(Date.now() / 1000),
            "gen_ai_review_created_at": Math.floor(Date.now() / 1000)
        };
        
        console.log("Saving record:", JSON.stringify(record, null, 2));
        
        var kvStoreUrl = Splunk.util.make_url(
            "/splunkd/__raw/servicesNS/nobody/TA-gen_ai_cim/storage/collections/data/gen_ai_review_findings"
        );
        
        // First check if record exists (query by gen_ai_event_id)
        var queryUrl = kvStoreUrl + "?query=" + encodeURIComponent(JSON.stringify({"gen_ai_event_id": eventId}));
        
        $.ajax({
            url: queryUrl,
            type: "GET",
            dataType: "json",
            contentType: "application/json"
        }).done(function(existing) {
            console.log("Existing records:", existing);
            
            if (existing && existing.length > 0) {
                // Update existing record
                var updateUrl = kvStoreUrl + "/" + encodeURIComponent(existing[0]._key);
                console.log("Updating existing record:", existing[0]._key);
                
                $.ajax({
                    url: updateUrl,
                    type: "POST",
                    data: JSON.stringify(record),
                    contentType: "application/json"
                }).done(function() {
                    saveSuccess();
                }).fail(function(xhr) {
                    saveFailed(xhr);
                });
            } else {
                // Insert new record
                insertRecord();
            }
        }).fail(function() {
            // Query failed, try insert
            insertRecord();
        });
        
        function insertRecord() {
            console.log("Inserting new record");
            $.ajax({
                url: kvStoreUrl,
                type: "POST",
                data: JSON.stringify(record),
                contentType: "application/json"
            }).done(function() {
                saveSuccess();
            }).fail(function(xhr) {
                saveFailed(xhr);
            });
        }
        
        function saveSuccess() {
            console.log("=== SAVE SUCCESS ===");
            $msg.html('<span style="color: #5cb85c;">✅ Saved!</span>');
            
            // Show popup and refresh
            alert("✅ Event Review has been saved successfully!");
            window.location.reload();
        }
        
        function saveFailed(xhr) {
            console.error("=== SAVE FAILED ===", xhr.status, xhr.responseText);
            $btn.prop('disabled', false).css('opacity', '1');
            $msg.html('<span style="color: #d9534f;">❌ Save failed</span>');
            alert("❌ Save failed: " + (xhr.responseText || xhr.statusText || "Unknown error"));
        }
    }
    
    // Setup notes textarea - sync with token and load existing values
    function setupNotesTextarea() {
        var $textarea = $('#notesTextarea');
        
        if ($textarea.length === 0) {
            // Textarea not ready yet, retry
            setTimeout(setupNotesTextarea, 500);
            return;
        }
        
        console.log("Notes textarea found, setting up sync");
        
        // Sync textarea changes to token
        $textarea.on('input change', function() {
            var value = $(this).val();
            defaultTokens.set("form.input_notes", value);
            defaultTokens.set("input_notes", value);
            console.log("Notes textarea updated, synced to token");
        });
        
        // Load existing value from token if available
        var existingNotes = defaultTokens.get("form.input_notes") || defaultTokens.get("input_notes") || "";
        if (existingNotes) {
            $textarea.val(existingNotes);
            console.log("Loaded existing notes into textarea");
        }
    }
    
    // Load notes into textarea when token changes (e.g., when loading existing review)
    function loadNotesIntoTextarea() {
        var $textarea = $('#notesTextarea');
        if ($textarea.length > 0) {
            var notes = defaultTokens.get("form.input_notes") || defaultTokens.get("input_notes") || "";
            $textarea.val(notes);
            console.log("Loaded notes into textarea:", notes ? "has content" : "empty");
        }
    }
    
    // Get notes value - prefer textarea, fallback to token
    function getNotesValue() {
        var $textarea = $('#notesTextarea');
        if ($textarea.length > 0) {
            return $textarea.val() || "";
        }
        return defaultTokens.get("form.input_notes") || defaultTokens.get("input_notes") || "";
    }
    
    // Start setup
    setupSaveButton();
    setupNotesTextarea();
    
    // Re-apply detection visibility when event changes (panel re-renders)
    if (defaultTokens) {
        defaultTokens.on("change:form.event_id", function(m, v) {
            console.log("=== Event ID changed to:", v, "===");
            if (v) {
                // Wait for panel to render, then re-apply detection visibility
                setTimeout(loadDetectionSettings, 500);
                setTimeout(loadDetectionSettings, 1500);
                // Re-setup notes textarea after panel re-renders
                setTimeout(setupNotesTextarea, 600);
            }
        });
        
        // Listen for notes token changes to update textarea
        defaultTokens.on("change:form.input_notes", function(m, v) {
            console.log("Notes token changed:", v ? "has value" : "empty");
            setTimeout(loadNotesIntoTextarea, 100);
        });
    }
});
