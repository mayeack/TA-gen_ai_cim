/**
 * tfidf_feedback_loop_promote.js - Handle Model Promotion Buttons
 * Promotes challenger TF-IDF anomaly models to champion and registers in model registry
 * 
 * Supports both prompt and response model promotion.
 * Since TF-IDF uses OneClassSVM (unsupervised), we track training sample counts rather than
 * traditional precision/recall metrics.
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc, SearchManager) {
    
    console.log("=== TFIDF_FEEDBACK_LOOP_PROMOTE.JS LOADED ===");
    
    // Wait for buttons to be available, then attach handlers
    function setupPromoteButtons() {
        var $promptBtn = $('#promotePromptModelBtn');
        var $responseBtn = $('#promoteResponseModelBtn');
        
        if ($promptBtn.length === 0 && $responseBtn.length === 0) {
            setTimeout(setupPromoteButtons, 500);
            return;
        }
        
        if ($promptBtn.length > 0) {
            console.log("Prompt promote button found, attaching click handler");
            $promptBtn.on('click', function(e) {
                e.preventDefault();
                console.log("=== PROMPT PROMOTE BUTTON CLICKED ===");
                promoteModel('prompt');
            });
        }
        
        if ($responseBtn.length > 0) {
            console.log("Response promote button found, attaching click handler");
            $responseBtn.on('click', function(e) {
                e.preventDefault();
                console.log("=== RESPONSE PROMOTE BUTTON CLICKED ===");
                promoteModel('response');
            });
        }
        
        console.log("=== TFIDF PROMOTE HANDLERS READY ===");
    }
    
    function promoteModel(modelType) {
        var $promptBtn = $('#promotePromptModelBtn');
        var $responseBtn = $('#promoteResponseModelBtn');
        var $msg = $('#promoteStatusMsg');
        
        var modelName = modelType === 'prompt' ? 'prompt_anomaly_model' : 'response_anomaly_model';
        var feedbackField = modelType === 'prompt' ? 'has_prompt_feedback' : 'has_response_feedback';
        var modelDisplayName = modelType === 'prompt' ? 'Prompt Anomaly Model' : 'Response Anomaly Model';
        
        // Confirm with user
        if (!confirm("Are you sure you want to promote the " + modelDisplayName + " challenger to champion?\n\nThis will:\n- Register a new model version\n- Mark it as the current champion\n- The previous champion will continue to work until you manually update the scoring search")) {
            return;
        }
        
        // Update UI
        $promptBtn.prop('disabled', true).css('opacity', '0.6');
        $responseBtn.prop('disabled', true).css('opacity', '0.6');
        $msg.html('<span style="color: #f0ad4e;">Promoting ' + modelDisplayName + '...</span>');
        
        // Get current user
        var currentUser = "";
        try {
            currentUser = Splunk.util.getConfigValue("USERNAME") || "unknown";
        } catch(e) {
            currentUser = "unknown";
        }
        
        // Generate version string
        var now = new Date();
        var modelVersion = now.getFullYear().toString() +
            ('0' + (now.getMonth() + 1)).slice(-2) +
            ('0' + now.getDate()).slice(-2) + '_' +
            ('0' + now.getHours()).slice(-2) +
            ('0' + now.getMinutes()).slice(-2) +
            ('0' + now.getSeconds()).slice(-2);
        
        // Get training data statistics
        var statsSearch = new SearchManager({
            id: 'getStatsSearch_' + modelType + '_' + Date.now(),
            search: '| inputlookup tfidf_training_data_v3 ' +
                '| stats count AS original_samples ' +
                '| append ' +
                    '[| inputlookup tfidf_training_feedback_lookup ' +
                    '| where ' + feedbackField + '=1 AND split_assignment="train" ' +
                    '| stats count AS feedback_samples] ' +
                '| stats sum(original_samples) AS original_samples, sum(feedback_samples) AS feedback_samples ' +
                '| eval training_samples=original_samples+feedback_samples',
            earliest_time: '-1m',
            latest_time: 'now',
            autostart: true
        });
        
        statsSearch.on('search:done', function(properties) {
            var results = statsSearch.data('results');
            
            results.on('data', function() {
                if (results.hasData()) {
                    var rows = results.data().rows;
                    if (rows && rows.length > 0) {
                        var fields = results.data().fields;
                        var row = rows[0];
                        
                        // Extract stats
                        var stats = {};
                        fields.forEach(function(field, idx) {
                            stats[field] = row[idx];
                        });
                        
                        console.log("Stats:", stats);
                        
                        // Create registry record
                        var record = {
                            "_key": modelName + "_" + modelVersion,
                            "model_name": modelName,
                            "model_type": modelType,
                            "model_version": modelVersion,
                            "algorithm": "OneClassSVM",
                            "feature_count": 50,
                            "training_samples": parseInt(stats.training_samples) || 0,
                            "original_samples": parseInt(stats.original_samples) || 0,
                            "feedback_samples": parseInt(stats.feedback_samples) || 0,
                            "status": "champion",
                            "created_at": Math.floor(Date.now() / 1000),
                            "promoted_at": Math.floor(Date.now() / 1000),
                            "promoted_by": currentUser,
                            "notes": "Promoted via dashboard by " + currentUser + " - includes " + (parseInt(stats.feedback_samples) || 0) + " human-confirmed normal samples"
                        };
                        
                        console.log("Registry record:", JSON.stringify(record, null, 2));
                        
                        // Save to KV Store
                        var kvStoreUrl = Splunk.util.make_url(
                            "/splunkd/__raw/servicesNS/nobody/TA-gen_ai_cim/storage/collections/data/tfidf_model_registry"
                        );
                        
                        $.ajax({
                            url: kvStoreUrl,
                            type: "POST",
                            data: JSON.stringify(record),
                            contentType: "application/json"
                        }).done(function() {
                            console.log("=== " + modelType.toUpperCase() + " MODEL PROMOTED SUCCESSFULLY ===");
                            $msg.html('<span style="color: #5cb85c;">' + modelDisplayName + ' promoted successfully! Version: ' + modelVersion + '</span>');
                            $promptBtn.prop('disabled', false).css('opacity', '1');
                            $responseBtn.prop('disabled', false).css('opacity', '1');
                            
                            alert(modelDisplayName + " promoted successfully!\n\n" +
                                "Version: " + modelVersion + "\n" +
                                "Total Training Samples: " + stats.training_samples + "\n" +
                                "Original Samples: " + stats.original_samples + "\n" +
                                "Feedback Samples: " + stats.feedback_samples + "\n\n" +
                                "Note: The challenger model has been registered as champion. To deploy it in production, update the scoring search to use the new model.");
                            
                        }).fail(function(xhr) {
                            console.error("=== PROMOTION FAILED ===", xhr.status, xhr.responseText);
                            $promptBtn.prop('disabled', false).css('opacity', '1');
                            $responseBtn.prop('disabled', false).css('opacity', '1');
                            $msg.html('<span style="color: #d9534f;">Promotion failed</span>');
                            alert("Promotion failed: " + (xhr.responseText || xhr.statusText || "Unknown error"));
                        });
                    } else {
                        $promptBtn.prop('disabled', false).css('opacity', '1');
                        $responseBtn.prop('disabled', false).css('opacity', '1');
                        $msg.html('<span style="color: #d9534f;">No training data available</span>');
                        alert("No training data available. Please ensure training data exists.");
                    }
                }
            });
        });
        
        statsSearch.on('search:failed', function() {
            console.error("Stats search failed");
            $promptBtn.prop('disabled', false).css('opacity', '1');
            $responseBtn.prop('disabled', false).css('opacity', '1');
            $msg.html('<span style="color: #d9534f;">Failed to get stats</span>');
            alert("Failed to retrieve training statistics. Please check the console for errors.");
        });
    }
    
    // Start setup
    setupPromoteButtons();
});
