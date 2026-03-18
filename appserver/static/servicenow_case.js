/**
 * ServiceNow Case Redirect JavaScript
 * Automatically redirects to ServiceNow case URL when search completes
 */

require([
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/simplexml/ready!'
], function($, mvc) {
    'use strict';

    console.log('ServiceNow Case JS loaded');

    // Get the search manager
    var searchManager = mvc.Components.get('case_search');
    
    if (!searchManager) {
        console.error('Search manager not found');
        $('#loading_message').hide();
        $('#error_message').show();
        $('#error_text').text('Search manager not found');
        return;
    }

    console.log('Search manager found:', searchManager);

    // Listen for search results
    var results = searchManager.data('results', { count: 0 });
    
    results.on('data', function() {
        console.log('Results received');
        var data = results.data();
        var rows = data.rows;
        
        if (rows && rows.length > 0) {
            var fields = data.fields;
            var row = rows[0];
            
            // Find field indices
            var urlIdx = fields.indexOf('snow_case_url');
            var statusIdx = fields.indexOf('snow_case_status');
            var messageIdx = fields.indexOf('snow_case_message');
            
            var url = urlIdx >= 0 ? row[urlIdx] : '';
            var status = statusIdx >= 0 ? row[statusIdx] : '';
            var message = messageIdx >= 0 ? row[messageIdx] : '';
            
            console.log('Case result:', { url: url, status: status, message: message });
            
            if (url && (status === 'created' || status === 'existing')) {
                // Success - redirect to ServiceNow
                $('#loading_message').hide();
                $('#success_message').show();
                $('#manual_link').attr('href', url);
                
                // Auto-redirect after short delay
                setTimeout(function() {
                    window.location.href = url;
                }, 500);
            } else {
                // Error
                $('#loading_message').hide();
                $('#error_message').show();
                $('#error_text').text(message || 'Unknown error occurred');
            }
        }
    });
    
    // Handle search errors
    searchManager.on('search:error', function(properties) {
        console.error('Search error:', properties);
        $('#loading_message').hide();
        $('#error_message').show();
        $('#error_text').text('Search failed: ' + (properties.message || 'Unknown error'));
    });
    
    searchManager.on('search:fail', function(properties) {
        console.error('Search failed:', properties);
        $('#loading_message').hide();
        $('#error_message').show();
        $('#error_text').text('Search failed: ' + (properties.message || 'Unknown error'));
    });
    
    searchManager.on('search:done', function(properties) {
        console.log('Search done:', properties);
    });
});
