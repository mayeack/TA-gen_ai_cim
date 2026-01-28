/**
 * pii_feedback_loop_promote.js - Handle Model Promotion Button
 * Promotes challenger model to champion and registers in model registry
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/searchmanager',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc, SearchManager) {
    
    console.log("=== PII_FEEDBACK_LOOP_PROMOTE.JS LOADED ===");
    
    // Wait for button to be available, then attach handler
    function setupPromoteButton() {
        var $btn = $('#promoteModelBtn');
        
        if ($btn.length === 0) {
            setTimeout(setupPromoteButton, 500);
            return;
        }
        
        console.log("Promote button found, attaching click handler");
        
        $btn.on('click', function(e) {
            e.preventDefault();
            console.log("=== PROMOTE BUTTON CLICKED ===");
            promoteModel();
        });
        
        console.log("=== PROMOTE HANDLER READY ===");
    }
    
    function promoteModel() {
        var $btn = $('#promoteModelBtn');
        var $msg = $('#promoteStatusMsg');
        
        // Confirm with user
        if (!confirm("Are you sure you want to promote the challenger model to champion?\n\nThis will:\n- Register a new model version\n- Mark it as the current champion\n- The previous champion will continue to work until you manually update the scoring search")) {
            return;
        }
        
        // Update UI
        $btn.prop('disabled', true).css('opacity', '0.6');
        $msg.html('<span style="color: #f0ad4e;">Promoting model...</span>');
        
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
        
        // First, get metrics from the challenger model on test set
        var metricsSearch = new SearchManager({
            id: 'getMetricsSearch_' + Date.now(),
            search: '| inputlookup pii_training_feedback_lookup ' +
                '| where split_assignment="test" ' +
                '| apply pii_detection_model_challenger ' +
                '| eval pred=if(\'predicted(pii_label)\'>0.5, 1, 0) ' +
                '| eval tp=if(pii_label=1 AND pred=1, 1, 0), fp=if(pii_label=0 AND pred=1, 1, 0), fn=if(pii_label=1 AND pred=0, 1, 0), tn=if(pii_label=0 AND pred=0, 1, 0) ' +
                '| stats sum(tp) AS tp, sum(fp) AS fp, sum(fn) AS fn, sum(tn) AS tn, count AS total, sum(pii_label) AS pii_count ' +
                '| eval accuracy=round((tp+tn)/total, 4) ' +
                '| eval precision=round(tp/(tp+fp), 4) ' +
                '| eval recall=round(tp/(tp+fn), 4) ' +
                '| eval f1_score=round(2*precision*recall/(precision+recall), 4)',
            earliest_time: '-1m',
            latest_time: 'now',
            autostart: true
        });
        
        metricsSearch.on('search:done', function(properties) {
            var results = metricsSearch.data('results');
            
            results.on('data', function() {
                if (results.hasData()) {
                    var rows = results.data().rows;
                    if (rows && rows.length > 0) {
                        var fields = results.data().fields;
                        var row = rows[0];
                        
                        // Extract metrics
                        var metrics = {};
                        fields.forEach(function(field, idx) {
                            metrics[field] = row[idx];
                        });
                        
                        console.log("Metrics:", metrics);
                        
                        // Create registry record
                        var record = {
                            "_key": "pii_detection_model_" + modelVersion,
                            "model_name": "pii_detection_model",
                            "model_version": modelVersion,
                            "algorithm": "RandomForestClassifier",
                            "feature_count": 20,
                            "accuracy": parseFloat(metrics.accuracy) || 0,
                            "precision": parseFloat(metrics.precision) || 0,
                            "recall": parseFloat(metrics.recall) || 0,
                            "f1_score": parseFloat(metrics.f1_score) || 0,
                            "threshold": 0.5,
                            "training_samples": parseInt(metrics.total) || 0,
                            "pii_samples": parseInt(metrics.pii_count) || 0,
                            "clean_samples": (parseInt(metrics.total) || 0) - (parseInt(metrics.pii_count) || 0),
                            "feedback_samples": parseInt(metrics.total) || 0,
                            "status": "champion",
                            "created_at": Math.floor(Date.now() / 1000),
                            "promoted_at": Math.floor(Date.now() / 1000),
                            "promoted_by": currentUser,
                            "notes": "Promoted via dashboard by " + currentUser
                        };
                        
                        console.log("Registry record:", JSON.stringify(record, null, 2));
                        
                        // Save to KV Store
                        var kvStoreUrl = Splunk.util.make_url(
                            "/splunkd/__raw/servicesNS/nobody/TA-gen_ai_cim/storage/collections/data/pii_model_registry"
                        );
                        
                        $.ajax({
                            url: kvStoreUrl,
                            type: "POST",
                            data: JSON.stringify(record),
                            contentType: "application/json"
                        }).done(function() {
                            console.log("=== MODEL PROMOTED SUCCESSFULLY ===");
                            $msg.html('<span style="color: #5cb85c;">Model promoted successfully! Version: ' + modelVersion + '</span>');
                            $btn.prop('disabled', false).css('opacity', '1');
                            
                            alert("Model promoted successfully!\n\nVersion: " + modelVersion + "\nF1 Score: " + metrics.f1_score + "\n\nNote: The challenger model has been registered as champion. To deploy it in production, update the scoring search to use the new model.");
                            
                        }).fail(function(xhr) {
                            console.error("=== PROMOTION FAILED ===", xhr.status, xhr.responseText);
                            $btn.prop('disabled', false).css('opacity', '1');
                            $msg.html('<span style="color: #d9534f;">Promotion failed</span>');
                            alert("Promotion failed: " + (xhr.responseText || xhr.statusText || "Unknown error"));
                        });
                    } else {
                        $btn.prop('disabled', false).css('opacity', '1');
                        $msg.html('<span style="color: #d9534f;">No test data available</span>');
                        alert("No test data available. Please ensure there is feedback data in the test split.");
                    }
                }
            });
        });
        
        metricsSearch.on('search:failed', function() {
            console.error("Metrics search failed");
            $btn.prop('disabled', false).css('opacity', '1');
            $msg.html('<span style="color: #d9534f;">Failed to get metrics</span>');
            alert("Failed to retrieve model metrics. Please ensure the challenger model exists.");
        });
    }
    
    // Start setup
    setupPromoteButton();
});
