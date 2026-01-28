/**
 * review_landing.js - Handle AI Review record creation and redirect
 * Fetches event data, creates KV store record via REST API, then redirects
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc, SearchManager) {
    
    console.log("=== REVIEW_LANDING.JS LOADED ===");
    
    // Get event_id from URL
    var urlParams = new URLSearchParams(window.location.search);
    var eventId = urlParams.get('event_id');
    
    console.log("Event ID from URL:", eventId);
    
    if (!eventId) {
        showError("No event_id provided in URL");
        return;
    }
    
    // Wait for search manager to be available
    var maxRetries = 20;
    var retryCount = 0;
    
    function waitForSearchManager() {
        var searchManager = mvc.Components.get("fetch_event_data");
        
        if (searchManager) {
            console.log("Search manager found");
            setupSearchListener(searchManager);
        } else if (retryCount < maxRetries) {
            retryCount++;
            console.log("Waiting for search manager... attempt", retryCount);
            setTimeout(waitForSearchManager, 250);
        } else {
            console.warn("Search manager not found after retries, creating record with URL param only");
            createKVStoreRecord({
                "gen_ai.event.id": eventId,
                "gen_ai.trace.id": "",
                event_time: Math.floor(Date.now() / 1000),
                "gen_ai.app.name": "Unknown",
                "gen_ai.request.model": "Unknown",
                "gen_ai.input.preview": "",
                "gen_ai.output.preview": ""
            });
        }
    }
    
    function setupSearchListener(searchManager) {
        var resultsModel = searchManager.data("results", {count: 1});
        
        resultsModel.on("data", function() {
            console.log("Results received");
            var data = resultsModel.data();
            
            if (data && data.rows && data.rows.length > 0) {
                var fields = data.fields;
                var row = data.rows[0];
                var record = {};
                
                fields.forEach(function(field, index) {
                    record[field] = row[index] || "";
                });
                
                record["gen_ai.event.id"] = eventId;
                console.log("Event data:", record);
                createKVStoreRecord(record);
            } else {
                console.warn("No results, creating minimal record");
                createKVStoreRecord({
                    "gen_ai.event.id": eventId,
                    "gen_ai.trace.id": "",
                    event_time: Math.floor(Date.now() / 1000),
                    "gen_ai.app.name": "Unknown",
                    "gen_ai.request.model": "Unknown",
                    "gen_ai.input.preview": "",
                    "gen_ai.output.preview": ""
                });
            }
        });
        
        resultsModel.on("error", function(err) {
            console.error("Results error:", err);
            createKVStoreRecord({
                "gen_ai.event.id": eventId,
                "gen_ai.trace.id": "",
                event_time: Math.floor(Date.now() / 1000),
                "gen_ai.app.name": "Unknown",
                "gen_ai.request.model": "Unknown",
                "gen_ai.input.preview": "",
                "gen_ai.output.preview": ""
            });
        });
        
        // If search is already done, check for results
        if (searchManager.get("data") && searchManager.get("data").resultCount > 0) {
            console.log("Search already complete, fetching results");
        }
    }
    
    function createKVStoreRecord(eventData) {
        var eventId = eventData["gen_ai.event.id"] || eventData.event_id;
        console.log("Creating KV store record for:", eventId);
        
        // Use underscore field names for KV Store REST API compatibility
        // (dotted field names don't work with REST API JSON payloads)
        var record = {
            "_key": eventId,
            "gen_ai_event_id": eventId,
            "gen_ai_trace_id": eventData["gen_ai.trace.id"] || eventData.trace_id || "",
            "event_time": eventData.event_time || Math.floor(Date.now() / 1000),
            "gen_ai_app_name": eventData["gen_ai.app.name"] || eventData.app || "Unknown",
            "gen_ai_request_model": eventData["gen_ai.request.model"] || eventData.model || "Unknown",
            "gen_ai_input_preview": eventData["gen_ai.input.preview"] || eventData.prompt_preview || "",
            "gen_ai_output_preview": eventData["gen_ai.output.preview"] || eventData.response_preview || "",
            "gen_ai_review_reviewer": "",
            "gen_ai_review_assignee": "",
            "gen_ai_review_status": "new",
            "gen_ai_review_priority": "medium",
            "gen_ai_review_pii_confirmed": "false",
            "gen_ai_review_pii_types": "",
            "gen_ai_review_phi_confirmed": "false",
            "gen_ai_review_phi_types": "",
            "gen_ai_review_prompt_injection_confirmed": "false",
            "gen_ai_review_prompt_injection_type": "",
            "gen_ai_review_anomaly_confirmed": "false",
            "gen_ai_review_anomaly_type": "",
            "gen_ai_review_notes": "",
            "gen_ai_review_created_at": Math.floor(Date.now() / 1000),
            "gen_ai_review_updated_at": Math.floor(Date.now() / 1000),
            "gen_ai_review_created_by": "workflow_action",
            "gen_ai_review_updated_by": "workflow_action"
        };
        
        var kvStoreUrl = Splunk.util.make_url(
            "/splunkd/__raw/servicesNS/nobody/TA-gen_ai_cim/storage/collections/data/gen_ai_review_findings"
        );
        
        // First check if record already exists (query by _key which equals event ID)
        var queryUrl = kvStoreUrl + "?query=" + encodeURIComponent(JSON.stringify({"gen_ai_event_id": eventId}));
        
        $.ajax({
            url: queryUrl,
            type: "GET",
            dataType: "json",
            contentType: "application/json"
        }).done(function(existing) {
            console.log("Existing records:", existing);
            
            if (existing && existing.length > 0) {
                console.log("Record already exists, redirecting...");
                showSuccess(eventId);
                setTimeout(function() {
                    redirectToEventReview(eventId);
                }, 300);
            } else {
                insertRecord(record);
            }
        }).fail(function(xhr) {
            console.log("Query failed, trying to insert:", xhr.status);
            insertRecord(record);
        });
        
        function insertRecord(rec) {
            console.log("Inserting new record:", rec);
            $.ajax({
                url: kvStoreUrl,
                type: "POST",
                data: JSON.stringify(rec),
                contentType: "application/json"
            }).done(function(response) {
                console.log("Record created successfully:", response);
                showSuccess(eventId);
                setTimeout(function() {
                    redirectToEventReview(eventId);
                }, 300);
            }).fail(function(xhr) {
                console.error("Failed to create record:", xhr.status, xhr.responseText);
                showSuccess(eventId);
                setTimeout(function() {
                    redirectToEventReview(eventId);
                }, 500);
            });
        }
    }
    
    function showError(message) {
        $('#loading_message').hide();
        $('#error_text').text(message);
        $('#error_message').show();
    }
    
    function showSuccess(eventId) {
        $('#loading_message').hide();
        var reviewUrl = Splunk.util.make_url('/app/TA-gen_ai_cim/event_review') + 
            '?form.event_id=' + encodeURIComponent(eventId);
        $('#manual_link').attr('href', reviewUrl);
        $('#success_message').show();
    }
    
    function redirectToEventReview(eventId) {
        var reviewUrl = Splunk.util.make_url('/app/TA-gen_ai_cim/event_review') + 
            '?form.event_id=' + encodeURIComponent(eventId);
        console.log("Redirecting to:", reviewUrl);
        window.location.href = reviewUrl;
    }
    
    // Start waiting for search manager
    setTimeout(waitForSearchManager, 500);
    
    console.log("=== REVIEW_LANDING.JS READY ===");
});
