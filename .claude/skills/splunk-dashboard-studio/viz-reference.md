# Visualization Reference

Complete catalog of Dashboard Studio visualization types, their key options, and Dynamic Options Syntax (DOS) functions.

## Visualization Types

### Charts

| Type | Viz Type String | Data Requirements |
|------|----------------|-------------------|
| Area chart | `splunk.area` | x: time/category, y: numeric series |
| Bar chart | `splunk.bar` | x: numeric, y: category (horizontal) |
| Bubble chart | `splunk.bubble` | x: numeric, y: numeric, size: numeric |
| Column chart | `splunk.column` | x: category/time, y: numeric (vertical) |
| Line chart | `splunk.line` | x: time/category, y: numeric series |
| Pie chart | `splunk.pie` | category + count/value |
| Scatter chart | `splunk.scatter` | x: numeric, y: numeric |

### Data Displays

| Type | Viz Type String | Data Requirements |
|------|----------------|-------------------|
| Single value | `splunk.singlevalue` | One primary value, optional trend |
| Table | `splunk.table` | Any tabular result set |
| Events viewer | `splunk.events` | Raw event data |

### Gauges

| Type | Viz Type String | Data Requirements |
|------|----------------|-------------------|
| Filler gauge | `splunk.fillergauge` | Single numeric value + ranges |
| Marker gauge | `splunk.markergauge` | Single numeric value + ranges |

### Maps & Geography

| Type | Viz Type String | Data Requirements |
|------|----------------|-------------------|
| Cluster map | `splunk.map` | lat, lon fields |
| Choropleth SVG | `splunk.choropleth.svg` | Area IDs + values + SVG source |

### Specialized

| Type | Viz Type String | Data Requirements |
|------|----------------|-------------------|
| Sankey diagram | `splunk.sankey` | source, target, value |
| Link graph | `splunk.linkgraph` | source, target |
| Parallel coordinates | `splunk.parallelcoordinates` | Multiple numeric dimensions |
| Punchcard | `splunk.punchcard` | x-category, y-category, size |

### Content & Decoration

| Type | Viz Type String | Data Requirements |
|------|----------------|-------------------|
| Markdown | `splunk.markdown` | None (static text) |
| Image | `splunk.image` | None (URL or uploaded) |
| Rectangle | `splunk.rectangle` | None |
| Ellipse | `splunk.ellipse` | None |
| Icon | `splunk.icon` | None (absolute layout only) |

---

## Key Options by Visualization Type

### splunk.singlevalue

```json
{
  "type": "splunk.singlevalue",
  "options": {
    "majorFontSize": 36,
    "majorColor": "#FFFFFF",
    "majorValue": "> primary | lastPoint(_time)",
    "deltaFontSize": 16,
    "deltaValue": "> primary | delta(-2)",
    "deltaColor": "> deltaValue | rangeValue(deltaColorConfig)",
    "trendDisplay": "sparkline",
    "trendColor": "> trendValue | rangeValue(trendConfig)",
    "sparklineDisplay": "below",
    "sparklineValues": "> primary | sparkline()",
    "underLabel": "Total Events",
    "unit": "events",
    "unitPosition": "after",
    "numberPrecision": 0,
    "backgroundColor": "transparent",
    "showSparklineAreaGraph": true,
    "showTrendIndicator": true
  }
}
```

### splunk.table

```json
{
  "type": "splunk.table",
  "options": {
    "count": 20,
    "dataOverlayMode": "none",
    "drilldown": "row",
    "rowNumbers": false,
    "wrap": true,
    "columnFormat": {
      "status": {
        "data": "> table | seriesByName(\"status\") | formatByType(statusFormat)",
        "rowBackgroundColors": "> table | seriesByName(\"status\") | rangeValue(statusColors)",
        "rowColors": "> table | seriesByName(\"status\") | rangeValue(statusTextColors)"
      }
    },
    "tableFormat": {
      "rowBackgroundColors": "> table | pick(rowBgConfig)",
      "rowColors": "> table | pick(rowTextConfig)"
    }
  }
}
```

### splunk.line / splunk.area

```json
{
  "type": "splunk.line",
  "options": {
    "xAxisTitleText": "Time",
    "yAxisTitleText": "Count",
    "legendDisplay": "right",
    "legendTruncation": "ellipsisEnd",
    "seriesColors": ["#7B56DB", "#009CEB", "#00CDAF"],
    "nullValueDisplay": "connect",
    "showDataValues": false,
    "showXMajorGridLines": false,
    "showYMajorGridLines": true,
    "yAxisScale": "linear",
    "lineWidth": 2,
    "areaOpacity": 0.75,
    "stackMode": "auto",
    "resultLimit": 50000
  }
}
```

For area charts, add: `"showLines": true` and `"areaOpacity"`.

### splunk.bar / splunk.column

```json
{
  "type": "splunk.column",
  "options": {
    "stackMode": "stacked",
    "seriesColors": ["#7B56DB", "#009CEB", "#00CDAF"],
    "legendDisplay": "right",
    "dataValuesDisplay": "off",
    "showSplitSeries": false,
    "xAxisLabelRotation": -45,
    "yAxisAbbreviation": "auto"
  }
}
```

Bar charts (`splunk.bar`) use `barSpacing`. Column charts use `columnSpacing` and support `annotationX`.

### splunk.pie

```json
{
  "type": "splunk.pie",
  "options": {
    "labelDisplay": "valuesAndPercentage",
    "seriesColors": ["#7B56DB", "#009CEB", "#00CDAF", "#DD9900", "#FF677B"],
    "showDonutHole": false
  }
}
```

### splunk.map

```json
{
  "type": "splunk.map",
  "options": {
    "center": [39.8283, -98.5795],
    "zoom": 4,
    "scrollZoom": false
  }
}
```

### splunk.fillergauge / splunk.markergauge

```json
{
  "type": "splunk.fillergauge",
  "options": {
    "orientation": "horizontal",
    "backgroundColor": "transparent",
    "gaugeRanges": [
      { "from": 0, "to": 50, "value": "#53A051" },
      { "from": 50, "to": 75, "value": "#F8BE34" },
      { "from": 75, "to": 100, "value": "#DC4E41" }
    ]
  }
}
```

### splunk.markdown

```json
{
  "type": "splunk.markdown",
  "options": {
    "markdown": "# Section Title\n\nDescriptive text with **bold** and *italic*.",
    "fontColor": "#999A9C",
    "fontSize": 14,
    "backgroundColor": "transparent"
  }
}
```

### splunk.image

```json
{
  "type": "splunk.image",
  "options": {
    "src": "splunk-enterprise-kvstore://<id>",
    "preserveAspectRatio": true
  }
}
```

### splunk.rectangle / splunk.ellipse

```json
{
  "type": "splunk.rectangle",
  "options": {
    "fillColor": "#080D12",
    "fillOpacity": 0.9,
    "strokeColor": "transparent",
    "strokeWidth": 0
  }
}
```

Used in absolute layout as background panels, section dividers, or decorative grouping.

---

## Shared Chart Options

These options are common across area, bar, column, line, and scatter charts:

| Option | Values | Default |
|--------|--------|---------|
| `seriesColors` | Array of hex colors | Splunk default palette |
| `seriesColorsByField` | `{"fieldName": "#color"}` | n/a |
| `legendDisplay` | `"right"`, `"left"`, `"top"`, `"bottom"`, `"off"` | `"right"` |
| `legendTruncation` | `"ellipsisEnd"`, `"ellipsisMiddle"`, `"ellipsisStart"`, `"ellipsisOff"` | `"ellipsisEnd"` |
| `stackMode` | `"auto"`, `"stacked"`, `"stacked100"` | `"auto"` |
| `showSplitSeries` | boolean | `false` |
| `backgroundColor` | hex color | theme default |
| `resultLimit` | number | `50000` |
| `showYMajorGridLines` | boolean | `true` |
| `showXMajorGridLines` | boolean | `false` |
| `yAxisScale` | `"linear"`, `"log"` | `"linear"` |
| `dataValuesDisplay` | `"off"`, `"all"`, `"minmax"` | `"off"` |
| `xAxisLabelRotation` | `-90`, `-45`, `0`, `45`, `90` | `0` |

**Splunk default color palette:**
`#7B56DB, #009CEB, #00CDAF, #DD9900, #FF677B, #CB2196, #813193, #0051B5, #008C80, #99B100, #FFA476, #FF6ACE, #AE8CFF, #00689D, #00490A, #465D00, #9D6300, #F6540B, #FF969E, #E47BFE`

---

## Dynamic Options Syntax (DOS) Reference

DOS structure: `"> [data source] | [selector(s)] | [formatting function]"`

### Selector Functions

| Selector | Purpose | Example |
|----------|---------|---------|
| `seriesByIndex(n)` | Select column by index | `> primary \| seriesByIndex(0)` |
| `seriesByName("field")` | Select column by field name | `> primary \| seriesByName("status")` |
| `frameBySeriesIndexRange(start, end)` | Select range of columns | `> primary \| frameBySeriesIndexRange(1)` |
| `lastPoint(field)` | Get last value of a field | `> primary \| lastPoint(_time)` |
| `delta(offset)` | Difference between last and offset point | `> primary \| delta(-2)` |
| `sparkline()` | Get sparkline data series | `> primary \| sparkline()` |
| `getField()` | Get field name from a series | `> x \| getField()` |
| `renameSeries("name")` | Rename a series | `> primary \| seriesByName("host") \| renameSeries("label")` |
| `prepend(config)` | Add rows before data | `> frame(f1, f2) \| prepend(staticOpts)` |

### Formatting Functions

#### rangeValue(config)
Maps numeric ranges to output values. Config is an array of range objects.
Each range can have `from` (inclusive), `to` (exclusive), and `value`.

```json
"context": {
  "statusColors": [
    { "from": 200, "to": 300, "value": "#53A051" },
    { "from": 300, "to": 400, "value": "#F8BE34" },
    { "from": 400, "to": 500, "value": "#F1813F" },
    { "from": 500, "value": "#DC4E41" }
  ]
}
```

#### matchValue(config)
Maps exact values to output values. Config is an array of match objects.

```json
"context": {
  "sevConfig": [
    { "match": "critical", "value": "#DC4E41" },
    { "match": "high", "value": "#F8BE34" },
    { "match": "low", "value": "#53A051" }
  ]
}
```

#### gradient(config)
Creates a continuous color gradient. Config has `stops` (numeric breakpoints) and `colors`.

```json
"context": {
  "gradConfig": {
    "stops": [0, 50, 100],
    "colors": ["#DC4E41", "#F8BE34", "#53A051"]
  }
}
```

#### formatByType(config)
Formats values based on their data type. Supports `number`, `string`, `time` sub-configs.

```json
"context": {
  "revenueFormat": {
    "number": {
      "thousandSeparated": true,
      "unitPosition": "before",
      "unit": "$",
      "precision": 2
    }
  }
}
```

#### pick(config)
Cycles through array values or maps field names to values.

Array mode (alternating row colors):
```json
"context": { "rowColors": ["#1A1C20", "#0D0F12"] }
```
Map mode (per-field alignment):
```json
"context": { "alignConfig": { "name": "left", "count": "right", "status": "center" } }
```

#### frame(series1, series2, ...)
Combines multiple series into a new DataFrame.

#### objects()
Converts a DataFrame into an array of objects. Used to populate input items dynamically.

#### prefix(string) / suffix(string)
Adds prefix or suffix to DataPoint values. Example: `prefix("bar")` turns `100` into `"bar100"`.

#### multiFormat(config)
Applies different formatting functions to different fields. Config requires:
- `nameField`: field that identifies the formatter key
- `valueField`: field containing values to format
- `formatters`: map of keys to `{ type, config }` objects

---

## Input Configuration Options

### input.timerange
```json
{
  "type": "input.timerange",
  "title": "Time Range",
  "options": {
    "token": "global_time",
    "defaultValue": "-24h@h,now"
  }
}
```
Produces tokens: `$global_time.earliest$`, `$global_time.latest$`

### input.dropdown
```json
{
  "type": "input.dropdown",
  "title": "Host Filter",
  "options": {
    "token": "host_tok",
    "defaultValue": "*",
    "items": [
      { "label": "All", "value": "*" }
    ]
  },
  "dataSources": { "primary": "ds_host_list" }
}
```
Dynamic items use DOS: `"items": "> primary | renameSeries(\"label\") | objects()"`

### input.multiselect
Same structure as dropdown. Token value is a comma-separated list.
Use with `$token|s$` filter or `IN ($token$)` in SPL.

### input.text
```json
{
  "type": "input.text",
  "title": "Search Term",
  "options": {
    "token": "search_term",
    "defaultValue": "*"
  }
}
```

### input.number
```json
{
  "type": "input.number",
  "title": "Threshold",
  "options": {
    "token": "threshold",
    "defaultValue": 100,
    "min": 0,
    "max": 1000,
    "step": 10
  }
}
```

---

## Event Handler Types

```json
"eventHandlers": [
  {
    "type": "drilldown.setToken",
    "options": {
      "tokens": [
        { "token": "selected", "key": "row.<fieldname>.value" }
      ]
    }
  }
]
```

| Handler Type | Purpose |
|-------------|---------|
| `drilldown.setToken` | Set token values on click |
| `drilldown.unsetToken` | Clear token values on click |
| `drilldown.linkToUrl` | Navigate to external URL |
| `drilldown.linkToDashboard` | Navigate to another dashboard |
| `drilldown.linkToSearch` | Open in Splunk search |

For `linkToUrl`:
```json
{
  "type": "drilldown.linkToUrl",
  "options": {
    "url": "https://example.com/detail?id=$row.id.value$",
    "newTab": true
  }
}
```

For `linkToDashboard`:
```json
{
  "type": "drilldown.linkToDashboard",
  "options": {
    "app": "search",
    "dashboard": "detail_view",
    "tokens": {
      "form.host_tok": "$row.host.value$"
    },
    "newTab": false
  }
}
```

---

## Environment Tokens

Available without configuration:
- `$env.user$` - Current username
- `$env.app$` - Current app context
- `$env.page$` - Current view name
- `$env.locale$` - User locale
- `$env.product$` - Product type (enterprise, cloud)

---

## Layout Configuration Options

### Absolute layout options
| Option | Type | Description |
|--------|------|-------------|
| `width` | number | Canvas width in pixels (default: 1440) |
| `height` | number | Canvas height in pixels (default: 900) |
| `display` | string | `"auto-scale"`, `"actual-size"`, `"fit-to-width"` |
| `backgroundColor` | string | Hex color for canvas background |
| `backgroundImage` | object | `{ "src": "...", "x": 0, "y": 0, "sizeType": "contain" }` |
| `gutterSize` | number | Spacing between elements in pixels |

### Grid layout options
| Option | Type | Description |
|--------|------|-------------|
| `width` | number | Canvas width (default: 1200) |
| `gutterSize` | number | Spacing between elements |

### Tab configuration
```json
"tabs": {
  "items": [
    { "layoutId": "layout_1", "label": "Overview", "icon": "icon_id" },
    { "layoutId": "layout_2", "label": "Details" }
  ],
  "options": {
    "barPosition": "top",
    "showTabBar": true
  }
}
```
