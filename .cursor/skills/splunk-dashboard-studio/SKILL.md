---
name: splunk-dashboard-studio
description: Build Splunk Dashboard Studio dashboards using JSON dashboard definitions. Covers visualization selection, layout design, tokens, interactivity, dynamic options syntax, and conditional formatting. Use when creating Dashboard Studio dashboards, designing JSON dashboard definitions, building interactive Splunk dashboards, or when the user wants to go beyond Simple XML into modern Splunk dashboard design.
---

# Splunk Dashboard Studio

Build production-quality dashboards using Dashboard Studio's JSON-based dashboard definitions. This skill covers the full definition schema, all visualization types, interactivity patterns, dynamic formatting, and design best practices.

## Prerequisites

- Splunk MCP server connected for running queries and deploying dashboards
- For the existing Simple XML dashboard builder skill, see the `splunk-dashboard-builder` subagent type

## Dashboard Definition Structure

Every Dashboard Studio dashboard is a single JSON object with these sections:

```json
{
  "title": "Dashboard Title",
  "description": "Dashboard description",
  "inputs": {},
  "defaults": {},
  "visualizations": {},
  "dataSources": {},
  "layout": {},
  "expressions": {},
  "applicationProperties": {}
}
```

| Section | Purpose |
|---------|---------|
| `title` / `description` | Dashboard metadata displayed in the header |
| `inputs` | User inputs (dropdowns, time pickers, text boxes) |
| `defaults` | Global defaults for data sources, visualizations, and tokens |
| `visualizations` | All visualization definitions with type, options, data bindings |
| `dataSources` | SPL searches, chain searches, saved searches |
| `layout` | Grid or absolute layout with positioning |
| `expressions` | Conditions for panel visibility and token eval |
| `applicationProperties` | Dashboard-level settings (hide export, collapse nav) |

## Workflow

When a user requests a Dashboard Studio dashboard:

```
Task Progress:
- [ ] Step 1: Understand the requirements (data, audience, purpose)
- [ ] Step 2: Design data architecture (searches, chains, tokens)
- [ ] Step 3: Select visualization types for each data element
- [ ] Step 4: Build the dashboard definition JSON
- [ ] Step 5: Add interactivity (inputs, tokens, drilldowns)
- [ ] Step 6: Apply dynamic formatting (DOS, conditional colors)
- [ ] Step 7: Deploy and validate
```

### Step 1: Requirements Gathering

Ask or infer:
- What data/indexes are involved?
- Who is the audience? (SOC analyst, executive, engineer)
- What decisions should the dashboard support?
- Interactive or static? Grid or pixel-perfect absolute layout?

### Step 2: Data Architecture

Design efficient SPL with base + chain searches:

```json
"dataSources": {
  "ds_base": {
    "type": "ds.search",
    "options": {
      "query": "index=main sourcetype=access_combined | stats count by status, method, uri_path",
      "queryParameters": {
        "earliest": "$global_time.earliest$",
        "latest": "$global_time.latest$"
      }
    },
    "name": "Base Search"
  },
  "ds_by_status": {
    "type": "ds.chain",
    "options": {
      "query": "| stats sum(count) as total by status",
      "extend": "ds_base"
    },
    "name": "By Status"
  },
  "ds_by_method": {
    "type": "ds.chain",
    "options": {
      "query": "| stats sum(count) as total by method",
      "extend": "ds_base"
    },
    "name": "By Method"
  }
}
```

**Data source types:**

| Type | When to use |
|------|------------|
| `ds.search` | Primary SPL queries. Use `queryParameters` for time tokens. |
| `ds.chain` | Post-process a parent search via `extend`. Reduces load. |
| `ds.savedSearch` | Reference existing saved searches by name. |
| `ds.test` | Mock data for prototyping. Uses inline `data` object. |

### Step 3: Visualization Selection

Choose the right visualization for each data element. See [viz-reference.md](viz-reference.md) for the complete catalog with options.

**Decision guide:**

| Data shape | Recommended visualization |
|-----------|--------------------------|
| Single metric + trend | `splunk.singlevalue` |
| Time series | `splunk.line` or `splunk.area` |
| Categorical comparison | `splunk.bar` (horizontal) or `splunk.column` (vertical) |
| Part-of-whole | `splunk.pie` |
| Correlation (2 vars) | `splunk.scatter` |
| Correlation (3 vars) | `splunk.bubble` |
| Tabular detail | `splunk.table` |
| Geographic | `splunk.map` or `splunk.choropleth.svg` |
| Status/threshold | `splunk.fillergauge` or `splunk.markergauge` |
| Flow/relationship | `splunk.sankey` or `splunk.linkgraph` |
| Annotations/text | `splunk.markdown` |
| Decorative elements | `splunk.rectangle`, `splunk.ellipse`, `splunk.image` |
| Multi-dimensional | `splunk.parallelcoordinates` |
| Raw events | `splunk.events` |

### Step 4: Build the Definition

**Visualization stanza pattern:**

```json
"viz_uniqueId": {
  "type": "splunk.column",
  "title": "Requests by Method",
  "description": "HTTP method distribution",
  "dataSources": {
    "primary": "ds_by_method"
  },
  "options": {
    "seriesColors": ["#7B56DB", "#009CEB", "#00CDAF"],
    "legendDisplay": "right",
    "stackMode": "stacked"
  },
  "containerOptions": {
    "title": { "color": "#FFFFFF" },
    "description": { "color": "#999A9C" }
  }
}
```

**Layout: Grid vs Absolute**

| Feature | Grid | Absolute |
|---------|------|----------|
| Positioning | Row-column snap | Pixel-perfect x/y/w/h |
| Responsiveness | Auto-scales to browser | Fixed canvas with display modes |
| Shapes/icons | Rectangles only | All shapes + icons |
| Background | No custom | Custom color + images |
| Best for | Data-focused dashboards | Executive/branded dashboards |

**Grid layout:**
```json
"layout": {
  "globalInputs": ["input_time"],
  "tabs": {
    "items": [{ "layoutId": "layout_1", "label": "Overview" }]
  },
  "layoutDefinitions": {
    "layout_1": {
      "type": "grid",
      "options": { "width": 1440 },
      "structure": [
        { "item": "viz_sv1", "type": "block", "position": { "x": 0, "y": 0, "w": 300, "h": 150 } },
        { "item": "viz_sv2", "type": "block", "position": { "x": 300, "y": 0, "w": 300, "h": 150 } },
        { "item": "viz_chart", "type": "block", "position": { "x": 0, "y": 150, "w": 600, "h": 400 } }
      ]
    }
  }
}
```

**Absolute layout** adds: `"display": "auto-scale"`, `"backgroundColor"`, `"backgroundImage"`, and `"height"` options.

### Step 5: Interactivity

**Inputs** create tokens. Available types:

| Type | Token behavior |
|------|---------------|
| `input.timerange` | Sets `$token.earliest$` and `$token.latest$` |
| `input.dropdown` | Sets `$token$` to selected value |
| `input.multiselect` | Sets `$token$` to selected values |
| `input.text` | Sets `$token$` to entered text |
| `input.number` | Sets `$token$` to entered number |

**Input definition pattern:**
```json
"inputs": {
  "input_time": {
    "type": "input.timerange",
    "title": "Time Range",
    "options": {
      "token": "global_time",
      "defaultValue": "-24h@h,now"
    }
  },
  "input_host": {
    "type": "input.dropdown",
    "title": "Host",
    "options": {
      "token": "selected_host",
      "defaultValue": "*",
      "items": [
        { "label": "All Hosts", "value": "*" }
      ]
    },
    "dataSources": { "primary": "ds_hosts" }
  }
}
```

**Token filters** for safe interpolation in SPL:

| Filter | Syntax | Use case |
|--------|--------|----------|
| String quote | `$token\|s$` | Wraps value in quotes, escapes inner quotes |
| HTML safe | `$token\|h$` | Sanitizes for HTML display |
| URL encode | `$token\|u$` | Encodes for URL parameters |
| No escape | `$token\|n$` | Raw value, no escaping |

**Event handlers for drilldown:**
```json
"eventHandlers": [
  {
    "type": "drilldown.setToken",
    "options": {
      "tokens": [
        { "token": "selected_method", "key": "row.method.value" }
      ]
    }
  }
]
```

Other handler types: `drilldown.linkToDashboard`, `drilldown.linkToUrl`, `drilldown.linkToSearch`.

**Default token values** prevent empty panels on load:
```json
"defaults": {
  "tokens": {
    "default": {
      "selected_method": { "value": "GET" }
    }
  }
}
```

### Step 6: Dynamic Options Syntax (DOS)

DOS enables conditional formatting using the pattern:
```
"> [data source] | [selector] | [formatting function]"
```

**Key formatting functions:**

| Function | Purpose | Example use |
|----------|---------|-------------|
| `rangeValue(config)` | Map numeric ranges to values (colors) | Status coloring by threshold |
| `matchValue(config)` | Map exact matches to values | Color by severity label |
| `gradient(config)` | Continuous color gradient from stops | Heat-map style coloring |
| `formatByType(config)` | Format numbers/strings (currency, precision) | Revenue formatting |
| `pick(config)` | Cycle through or map field-specific values | Alternating row colors |

**rangeValue example** (single value delta coloring):
```json
"options": {
  "deltaColor": "> deltaValue | rangeValue(deltaColorConfig)"
},
"context": {
  "deltaColorConfig": [
    { "from": 0, "value": "#1a9035" },
    { "to": 0, "value": "#dc4e41" }
  ]
}
```

**Table column formatting with matchValue:**
```json
"options": {
  "columnFormat": {
    "severity": {
      "rowBackgroundColors": "> table | seriesByName(\"severity\") | matchValue(sevConfig)"
    }
  }
},
"context": {
  "sevConfig": [
    { "match": "critical", "value": "#DC4E41" },
    { "match": "high", "value": "#F8BE34" },
    { "match": "medium", "value": "#F1813F" },
    { "match": "low", "value": "#53A051" },
    { "match": "info", "value": "#0076D3" }
  ]
}
```

See [viz-reference.md](viz-reference.md) for the full DOS function catalog.

### Step 7: Delegate to the Builder Subagent

Once you have gathered requirements (steps 1-3) and made design decisions, delegate the actual dashboard construction to the **`dashboard-studio-builder`** subagent. Pass it a build spec:

```
Build Spec:
- Title: <dashboard title>
- Description: <dashboard description>
- Audience: <SOC analyst | executive | engineer | etc.>
- Layout: <grid | absolute>
- Data sources:
  - Index: <index name(s)>
  - Sourcetype: <sourcetype(s)>
  - Key fields: <field1, field2, ...>
  - Time range default: <-24h, -7d, etc.>
- Visualizations needed:
  - <description of viz 1 + type if known>
  - <description of viz 2 + type if known>
  - ...
- Interactivity:
  - Inputs: <time range, dropdown filters, text search, etc.>
  - Drilldowns: <click-to-filter, link-to-dashboard, link-to-URL, etc.>
  - Conditional panels: <show/hide behavior>
- Formatting:
  - Severity coloring: <yes/no + field names>
  - Number formatting: <currency, percentage, units>
  - Table column formatting: <gradient, range colors, etc.>
- Deployment: <deploy via MCP | output JSON only>
- Special requirements: <any additional context>
```

The subagent handles data discovery via Splunk MCP, JSON assembly, deployment, and validation. It returns the complete dashboard definition and a summary.

If you prefer to build the JSON directly without the subagent, follow the schema and patterns documented in this skill and the reference files.

## Expressions for Conditional Visibility

Show or hide panels based on conditions:

```json
"visualizations": {
  "viz_detail": {
    "containerOptions": {
      "visibility": {
        "showConditions": ["cond_has_selection"]
      }
    },
    "type": "splunk.table",
    "dataSources": { "primary": "ds_detail" }
  }
},
"expressions": {
  "conditions": {
    "cond_has_selection": {
      "name": "Has selection",
      "value": "$selected_host$ != \"*\""
    }
  }
}
```

## Application Properties

```json
"applicationProperties": {
  "hideExport": false,
  "hideViewModeActionMenu": false,
  "hideEdit": false,
  "hideOpenInSearch": false,
  "collapseNavigation": false
}
```

## Design Best Practices

1. **Information hierarchy**: Single values at top for KPIs, charts in middle for trends, tables at bottom for detail
2. **Color discipline**: Use Splunk's default palette. Reserve red for critical, green for healthy. Limit to 5-7 colors per chart.
3. **Grid layout first**: Use grid unless you need pixel-perfect placement or background images
4. **Chain searches aggressively**: One base search with multiple chains beats N independent searches
5. **Default token values**: Always set defaults so dashboards render meaningfully on first load
6. **Title every panel**: Every visualization should have a clear, descriptive title
7. **Progressive disclosure**: Use tabs for multi-topic dashboards, conditional visibility for detail panels
8. **Standard canvas width**: 1440px for absolute, 1200px for grid
9. **Consistent spacing**: Use multiples of 8px for gutters and margins

## Builder Subagent

The **`dashboard-studio-builder`** subagent (`~/.cursor/agents/dashboard-studio-builder.md`) handles the full build lifecycle:
1. Data discovery via Splunk MCP (indexes, sourcetypes, fields)
2. JSON definition assembly with all sections
3. Deployment to Splunk via MCP (if available)
4. Structural validation (viz-to-layout, datasource refs, token consistency)

Invoke it with the build spec template from Step 7 above. The subagent has the complete Splunk UI Design System standards baked in -- color palette, accessibility rules, and information hierarchy patterns.

## Additional Resources

- Complete visualization type catalog and options: [viz-reference.md](viz-reference.md)
- Full dashboard definition examples: [examples.md](examples.md)
- Splunk docs: https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/dashboard-studio/
- Splunk UI Design System: https://splunkui.splunk.com/DesignSystem/Overview
