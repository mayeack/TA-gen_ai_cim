# Dashboard Studio vs Classic Dashboards

## Feature Comparison

| Feature | Dashboard Studio | Classic Dashboards |
|---------|-----------------|-------------------|
| **Splunk Version** | 9.0+ required | All versions |
| **Format** | JSON | XML |
| **Interface** | Modern, responsive | Traditional |
| **Mobile Support** | ✅ Excellent | ⚠️ Limited |
| **Drag & Drop Editor** | ✅ Yes | ❌ No |
| **Custom Visualizations** | ✅ Extensive | ⚠️ Limited |
| **Data Source Management** | ✅ Reusable | ❌ Inline only |
| **Theme Support** | ✅ Built-in dark/light | ⚠️ Basic |
| **Performance** | ✅ Optimized | ✅ Good |
| **Color Formatting** | ✅ Advanced (context-based) | ✅ Good (static) |
| **Sparklines** | ✅ Built-in | ❌ Manual workaround |
| **Learning Curve** | Medium | Low |

---

## When to Use Dashboard Studio (Recommended)

✅ **Use Dashboard Studio if:**
- You're on Splunk 9.0 or newer
- You want a modern, responsive interface
- You need advanced visualizations and formatting
- You want reusable data sources across panels
- Mobile access is important
- You prefer visual drag-and-drop editing

**Key Advantages:**
- Modern JSON format with better structure
- Reusable data sources reduce duplication
- Advanced color formatting with context-based ranges
- Better mobile and tablet support
- Built-in sparklines for single value visualizations
- Drag-and-drop interface for easier customization

---

## When to Use Classic Dashboards

✅ **Use Classic Dashboards if:**
- You're on Splunk version < 9.0
- You need backward compatibility
- Your team is familiar with XML format
- You have existing Classic dashboards to maintain
- You prefer simple, text-based editing
- You need to support legacy Splunk deployments

**Key Advantages:**
- Works on all Splunk versions
- Simpler XML format
- Easier for text-based editing and version control
- Lower learning curve for new users
- Well-documented with extensive examples
- Predictable behavior across versions

---

## Migration Path

If you're currently using Classic Dashboards and want to migrate to Dashboard Studio:

### Step-by-Step Migration

1. **Export Existing Classic Dashboard**
   - Open your Classic Dashboard
   - Click **Edit → Edit Source**
   - Copy the entire XML

2. **Identify Key Components**
   - List all searches/queries
   - Note visualization types (single, chart, table)
   - Document any custom formatting or drilldowns

3. **Convert to Dashboard Studio Format**
   - Create new Dashboard Studio dashboard
   - Define data sources in the `dataSources` section
   - Map visualizations to Dashboard Studio types
   - Recreate formatting using `options` and `context`
   - Define layout positions

4. **Test Thoroughly**
   - Verify all queries return expected data
   - Check visualizations render correctly
   - Test color formatting and thresholds
   - Validate on different screen sizes
   - Test any drilldowns or interactions

5. **Update Documentation**
   - Document any changes in behavior
   - Train team on Dashboard Studio interface
   - Update runbooks and SOPs

6. **Deploy to Production**
   - Test in staging environment first
   - Schedule deployment during maintenance window
   - Have rollback plan ready
   - Monitor for issues after deployment

### Common Conversion Patterns

#### Single Value with Color Ranges

**Classic Dashboard (XML):**
```xml
<single>
  <search>
    <query>| stats count as total</query>
  </search>
  <option name="rangeColors">["0x53a051","0xf8be34","0xdc4e41"]</option>
  <option name="rangeValues">[50,80]</option>
</single>
```

**Dashboard Studio (JSON):**
```json
{
  "type": "viz.singlevalue",
  "options": {
    "backgroundColor": "> primary | seriesByName('total') | lastPoint() | rangeValue(colorRanges)"
  },
  "context": {
    "colorRanges": [
      {"to": 50, "value": "#53a051"},
      {"from": 50, "to": 80, "value": "#f8be34"},
      {"from": 80, "value": "#dc4e41"}
    ]
  }
}
```

#### Area Chart with Stacked Mode

**Classic Dashboard (XML):**
```xml
<chart>
  <search>
    <query>| timechart count by category</query>
  </search>
  <option name="charting.chart">area</option>
  <option name="charting.chart.stackMode">stacked</option>
</chart>
```

**Dashboard Studio (JSON):**
```json
{
  "type": "viz.area",
  "options": {
    "stackMode": "stacked",
    "xAxisTitleText": "Time",
    "yAxisTitleText": "Count"
  }
}
```

**Note:** Splunk does not provide automatic conversion from Classic to Dashboard Studio format. Manual conversion is required, but the patterns are consistent once you understand the mapping.

---

## Dashboard Customization Tips

### Dashboard Studio Customizations

#### 1. Change Color Thresholds

Adjust color ranges for better visibility:

```json
"context": {
  "violationRateColorRanges": [
    {
      "to": 0.5,
      "value": "#53a051"
    },
    {
      "from": 0.5,
      "to": 3,
      "value": "#f8be34"
    },
    {
      "from": 3,
      "value": "#dc4e41"
    }
  ]
}
```

#### 2. Add Global Time Range Picker

Enable users to change time ranges for all panels:

```json
"inputs": {
  "input_global_trp": {
    "type": "input.timerange",
    "options": {
      "token": "global_time",
      "defaultValue": "-24h@h,now"
    },
    "title": "Global Time Range"
  }
},
"dataSources": {
  "ds_example": {
    "type": "ds.search",
    "options": {
      "query": "index=gen_ai_log | ...",
      "queryParameters": {
        "earliest": "$global_time.earliest$",
        "latest": "$global_time.latest$"
      }
    }
  }
}
```

#### 3. Add Dropdown Filter

Filter data by specific fields:

```json
"inputs": {
  "input_model_filter": {
    "type": "input.dropdown",
    "options": {
      "items": [
        {"label": "All Models", "value": "*"},
        {"label": "GPT-4", "value": "gpt-4*"},
        {"label": "Claude", "value": "claude*"}
      ],
      "defaultValue": "*",
      "token": "model_filter"
    },
    "title": "Model"
  }
}
```

Reference in query:
```
index=gen_ai_log gen_ai.request.model=$model_filter$ | ...
```

#### 4. Customize Layout Positions

Adjust panel sizes and positions:

```json
"layout": {
  "structure": [
    {
      "item": "viz_example",
      "position": {
        "x": 0,      // Horizontal position
        "y": 0,      // Vertical position
        "w": 720,    // Width
        "h": 300     // Height
      }
    }
  ]
}
```

### Classic Dashboard Customizations

#### 1. Add Time Range Picker

```xml
<form>
  <label>GenAI Governance Dashboard</label>
  <fieldset submitButton="false">
    <input type="time" token="time_range">
      <label>Time Range</label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  
  <row>
    <panel>
      <search>
        <query>index=gen_ai_log | ...</query>
        <earliest>$time_range.earliest$</earliest>
        <latest>$time_range.latest$</latest>
      </search>
    </panel>
  </row>
</form>
```

#### 2. Add Dropdown Filter

```xml
<input type="dropdown" token="model_filter">
  <label>Model</label>
  <choice value="*">All Models</choice>
  <choice value="gpt-4*">GPT-4</choice>
  <choice value="claude*">Claude</choice>
  <default>*</default>
</input>
```

Reference in search:
```xml
<query>index=gen_ai_log gen_ai.request.model=$model_filter$ | ...</query>
```

#### 3. Add Drilldown Actions

```xml
<table>
  <search>...</search>
  <option name="drilldown">cell</option>
  <drilldown>
    <link target="_blank">/app/search/search?q=index=gen_ai_log gen_ai.session.id=$row.session_id$&amp;earliest=$earliest$&amp;latest=$latest$</link>
  </drilldown>
</table>
```

---

## Troubleshooting

### Dashboard Studio Issues

#### Issue: Dashboard doesn't load or shows blank panels

**Symptoms:**
- White/blank screen
- "Failed to load dashboard" error
- Panels don't render

**Solutions:**
1. Check browser console for JavaScript errors (F12)
2. Ensure Splunk version is 9.0 or higher
3. Validate JSON syntax using a JSON validator (jsonlint.com)
4. Check for missing commas or brackets in JSON
5. Verify all visualization types are supported
6. Clear browser cache and reload

**Debug Command:**
```bash
# Check Splunk version
$SPLUNK_HOME/bin/splunk version

# Check dashboard definition for errors
cat $SPLUNK_HOME/etc/apps/TA-gen_ai_cim/local/data/ui/views/dashboard.json
```

#### Issue: Data sources return no results

**Symptoms:**
- Empty panels
- "No results found" message
- Panels show "Waiting for data"

**Solutions:**
1. Test SPL queries independently in Search & Reporting app
2. Verify index names match your environment
3. Check time ranges are appropriate for your data
4. Verify user has permissions to indexes
5. Check search quotas and limits
6. Look for search errors in Messages

**Debug SPL:**
```spl
| rest /services/search/jobs 
| search label="GenAI*" 
| table label, runDuration, resultCount, isFinalized
```

#### Issue: Colors/formatting not applying

**Symptoms:**
- Wrong colors displayed
- Formatting not matching configuration
- backgroundColor not working

**Solutions:**
1. Check `context` sections for typos in range definitions
2. Ensure field names match exactly (case-sensitive)
3. Verify range values are numeric or proper strings
4. Test with simple static values first
5. Check that data type matches formatter expectations

**Example Debug:**
```json
// Instead of complex expression
"backgroundColor": "#dc4e41"  // Test with static value first

// Then add complexity
"backgroundColor": "> primary | seriesByName('value') | lastPoint() | rangeValue(ranges)"
```

#### Issue: Layout problems or overlapping panels

**Symptoms:**
- Panels overlap
- Panels not visible
- Layout looks incorrect

**Solutions:**
1. Check position coordinates don't overlap
2. Ensure width (w) + x position doesn't exceed container width (1440)
3. Verify height values are reasonable
4. Use absolute layout for precise control
5. Test on different screen sizes

### Classic Dashboard Issues

#### Issue: XML parse errors

**Symptoms:**
- "Dashboard could not be loaded" error
- Red error messages in UI
- Blank dashboard

**Solutions:**
1. Validate XML syntax
2. Check for unescaped special characters:
   - `&` → `&amp;`
   - `<` → `&lt;`
   - `>` → `&gt;`
   - `"` → `&quot;`
   - `'` → `&apos;`
3. Ensure all tags are properly closed
4. Check for mismatched opening/closing tags
5. Validate against SimpleXML schema

**XML Validator Command:**
```bash
# Use xmllint to validate
xmllint --noout $SPLUNK_HOME/etc/apps/TA-gen_ai_cim/default/data/ui/views/dashboard.xml
```

#### Issue: Charts not rendering

**Symptoms:**
- Empty chart area
- "No data available" message
- Chart shows but with wrong data

**Solutions:**
1. Verify visualization type is supported
2. Check that data format matches chart requirements
   - Line charts need time series data
   - Pie charts need categorical data with counts
   - Tables need tabular data
3. Test with simplified queries first
4. Check for null values in data
5. Verify chart options are valid

**Test Query:**
```spl
| makeresults count=10 
| streamstats count 
| eval value=random() % 100
| timechart avg(value)
```

#### Issue: Searches timing out

**Symptoms:**
- "Search was cancelled" message
- Long loading times
- Intermittent results

**Solutions:**
1. Optimize SPL queries (add filters early)
2. Adjust time ranges to be more specific
3. Use summary indexing for expensive searches
4. Increase search timeout in limits.conf
5. Use stats instead of transaction when possible
6. Add index and source filters

**Optimization Example:**
```spl
# Before (slow)
index=gen_ai_log | search gen_ai.provider.name="openai" | stats count

# After (fast)
index=gen_ai_log gen_ai.provider.name="openai" | stats count
```

---

## Performance Optimization

### Dashboard Studio Performance

1. **Use Data Source Caching:**
```json
"dataSources": {
  "ds_example": {
    "options": {
      "refresh": "300s",  // Refresh every 5 minutes
      "refreshType": "delay"
    }
  }
}
```

2. **Limit Result Sets:**
```spl
index=gen_ai_log 
| stats count by model 
| head 20  // Limit to top 20 results
```

3. **Use Accelerated Data Models:**
```spl
| datamodel GenAI_CIM search 
| stats count by gen_ai.provider.name
```

### Classic Dashboard Performance

1. **Use Base Searches:**
```xml
<search id="base_search">
  <query>index=gen_ai_log earliest=-24h | fields _time, gen_ai.*</query>
</search>

<panel>
  <search base="base_search">
    <query>| stats count by gen_ai.provider.name</query>
  </search>
</panel>
```

2. **Schedule Dashboard Preloading:**
```xml
<search>
  <query>| savedsearch "GenAI Summary"</query>
  <earliest>-24h@h</earliest>
  <latest>now</latest>
</search>
```

---

## Support and Resources

### Official Documentation

**Dashboard Studio:**
- [Splunk Dashboard Studio Documentation](https://docs.splunk.com/Documentation/SplunkCloud/latest/DashStudio/Introduction)
- [Dashboard Studio Reference](https://docs.splunk.com/Documentation/SplunkCloud/latest/DashStudio/visualizations)
- [Dashboard Studio Examples](https://dev.splunk.com/enterprise/docs/developapps/visualizedata/usedashtoolkit/)

**Classic Dashboards:**
- [Splunk Classic Dashboard Documentation](https://docs.splunk.com/Documentation/Splunk/latest/Viz/Dashboards)
- [SimpleXML Reference](https://docs.splunk.com/Documentation/Splunk/latest/Viz/PanelreferenceforSimplifiedXML)
- [Dashboard Examples](https://docs.splunk.com/Documentation/Splunk/latest/Viz/Exampledashand panels)

### Community Resources

- [Splunk Answers](https://community.splunk.com/) - Community Q&A
- [Splunk Dev Community](https://dev.splunk.com/) - Developer resources
- [Splunk GitHub](https://github.com/splunk/) - Example dashboards and apps
- [#splunk on Slack](https://splunk-usergroups.slack.com/) - Real-time help

### Training

- [Splunk Fundamentals](https://www.splunk.com/en_us/training/free-courses/splunk-fundamentals-1.html) - Free introductory course
- [Creating Dashboards with Dashboard Studio](https://www.splunk.com/en_us/training/courses/creating-dashboards-with-dashboard-studio.html) - Official training
- [Advanced Dashboards and Visualizations](https://www.splunk.com/en_us/training/courses/advanced-dashboards-and-visualizations.html) - Advanced topics

---

## Quick Reference

### Dashboard Studio JSON Structure

```json
{
  "title": "Dashboard Title",
  "description": "Dashboard description",
  "dataSources": {
    "ds_name": {
      "type": "ds.search",
      "options": {
        "query": "search query",
        "queryParameters": {
          "earliest": "-24h",
          "latest": "now"
        }
      }
    }
  },
  "visualizations": {
    "viz_name": {
      "type": "viz.singlevalue|viz.line|viz.area|viz.column|viz.table",
      "options": { /* viz options */ },
      "dataSources": {
        "primary": "ds_name"
      },
      "title": "Panel Title"
    }
  },
  "layout": {
    "type": "absolute",
    "structure": [
      {
        "item": "viz_name",
        "position": {"x": 0, "y": 0, "w": 360, "h": 150}
      }
    ]
  }
}
```

### Classic Dashboard XML Structure

```xml
<dashboard>
  <label>Dashboard Title</label>
  <description>Dashboard description</description>
  
  <row>
    <panel>
      <title>Panel Title</title>
      <single|chart|table>
        <search>
          <query>search query</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
        </search>
        <option name="key">value</option>
      </single|chart|table>
    </panel>
  </row>
</dashboard>
```

---

## Version History

- **v1.1** (2026-01-15): Added Dashboard Studio JSON format
- **v1.0** (2026-01-15): Initial release with Classic Dashboard XML
