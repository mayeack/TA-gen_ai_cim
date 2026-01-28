# Token Cost Administration Guide

This guide explains how to manage the `genai_token_cost` KV store for dynamic, time-versioned pricing of GenAI tokens across providers and models.

## Overview

The GenAI Token Cost system enables:
- **Time-versioned pricing**: Track historical pricing changes over time
- **Multi-provider support**: Separate pricing for OpenAI, Anthropic, AWS Bedrock, etc.
- **Input/Output differentiation**: Different rates for prompt vs completion tokens
- **Dynamic lookups**: Automatically match events to the correct pricing based on event timestamp

## KV Store Schema

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | Provider identifier (e.g., "openai", "anthropic", "aws.bedrock") |
| `model` | string | Model identifier (e.g., "gpt-4", "claude-3-opus", "claude-3-5-sonnet-20241022") |
| `direction` | string | Token direction: "input" or "output" |
| `cost_per_million` | number | Cost in USD per 1 million tokens |
| `effective_start` | number | Unix epoch when this price becomes effective |
| `effective_end` | number | Unix epoch when this price expires (null = current) |
| `currency` | string | Currency code (default: "USD") |

---

## Adding and Updating Pricing

### Insert New Pricing (SPL)

Use `| outputlookup append=true` to add new pricing records:

```spl
| makeresults
| eval provider="openai",
       model="gpt-4",
       direction="input",
       cost_per_million=30.00,
       effective_start=strptime("2024-01-01 00:00:00", "%Y-%m-%d %H:%M:%S"),
       effective_end=null(),
       currency="USD"
| table provider, model, direction, cost_per_million, effective_start, effective_end, currency
| outputlookup append=true genai_token_cost_lookup
```

### Bulk Insert Multiple Models

Insert multiple pricing records at once:

```spl
| makeresults count=1
| eval data=mvappend(
    "openai|gpt-4|input|30.00",
    "openai|gpt-4|output|60.00",
    "openai|gpt-4-turbo|input|10.00",
    "openai|gpt-4-turbo|output|30.00",
    "openai|gpt-3.5-turbo|input|0.50",
    "openai|gpt-3.5-turbo|output|1.50",
    "anthropic|claude-3-opus|input|15.00",
    "anthropic|claude-3-opus|output|75.00",
    "anthropic|claude-3-sonnet|input|3.00",
    "anthropic|claude-3-sonnet|output|15.00",
    "anthropic|claude-3-5-sonnet-20241022|input|3.00",
    "anthropic|claude-3-5-sonnet-20241022|output|15.00",
    "anthropic|claude-3-haiku|input|0.25",
    "anthropic|claude-3-haiku|output|1.25"
)
| mvexpand data
| eval parts=split(data, "|"),
       provider=mvindex(parts, 0),
       model=mvindex(parts, 1),
       direction=mvindex(parts, 2),
       cost_per_million=tonumber(mvindex(parts, 3)),
       effective_start=now(),
       effective_end=null(),
       currency="USD"
| table provider, model, direction, cost_per_million, effective_start, effective_end, currency
| outputlookup append=true genai_token_cost_lookup
```

### Update Pricing (Expire Old, Add New)

When pricing changes, **expire the old record** and **insert a new one**:

**Step 1: Expire the existing price**

```spl
| inputlookup genai_token_cost_lookup
| search provider="openai" model="gpt-4" direction="input" effective_end=null
| eval effective_end=now()
| outputlookup genai_token_cost_lookup key_field=_key
```

**Step 2: Add the new price**

```spl
| makeresults
| eval provider="openai",
       model="gpt-4",
       direction="input",
       cost_per_million=25.00,
       effective_start=now(),
       effective_end=null(),
       currency="USD"
| table provider, model, direction, cost_per_million, effective_start, effective_end, currency
| outputlookup append=true genai_token_cost_lookup
```

### Combined Price Update (Single Query)

```spl
| inputlookup genai_token_cost_lookup
| eval effective_end = if(provider="openai" AND model="gpt-4" AND direction="input" AND isnull(effective_end), now(), effective_end)
| outputlookup genai_token_cost_lookup
| append 
    [| makeresults 
     | eval provider="openai", model="gpt-4", direction="input", 
            cost_per_million=25.00, effective_start=now(), 
            effective_end=null(), currency="USD"
     | table provider, model, direction, cost_per_million, effective_start, effective_end, currency]
| outputlookup append=true genai_token_cost_lookup
```

---

## Viewing Current and Historical Pricing

### View All Current Pricing

```spl
| `genai_get_current_pricing`
```

Or manually:

```spl
| inputlookup genai_token_cost_lookup
| eval _now=now()
| where (isnull(effective_end) OR effective_end > _now) AND (isnull(effective_start) OR effective_start <= _now)
| eval effective_start_human=strftime(effective_start, "%Y-%m-%d %H:%M:%S")
| table provider, model, direction, cost_per_million, currency, effective_start_human
| sort provider, model, direction
```

### View Pricing History for Specific Model

```spl
| `genai_get_pricing_history("openai", "gpt-4")`
```

### View All Historical Pricing

```spl
| inputlookup genai_token_cost_lookup
| eval effective_start_human=strftime(effective_start, "%Y-%m-%d %H:%M:%S"),
       effective_end_human=if(isnull(effective_end), "current", strftime(effective_end, "%Y-%m-%d %H:%M:%S"))
| sort provider, model, direction, - effective_start
| table provider, model, direction, cost_per_million, currency, effective_start_human, effective_end_human, _key
```

---

## Calculating Costs on GenAI Events

### Basic Cost Join

Apply current pricing to events:

```spl
index=gen_ai_log earliest=-24h
| `genai_token_cost_join`
| table _time, gen_ai.provider.name, gen_ai.request.model, 
        gen_ai.usage.input_tokens, gen_ai.usage.output_tokens,
        gen_ai.cost.input, gen_ai.cost.output, gen_ai.cost.calculated_total, gen_ai.cost.currency
```

### Cost Summary by Time Period

```spl
index=gen_ai_log earliest=-7d
| `genai_token_cost_join`
| `genai_token_cost_summary(1d)`
```

### Cost Analysis by Provider

```spl
index=gen_ai_log earliest=-30d
| `genai_token_cost_join`
| `genai_cost_by_provider`
```

### Cost Analysis by Model

```spl
index=gen_ai_log earliest=-30d
| `genai_token_cost_join`
| `genai_cost_by_model`
```

### Cost Analysis by Application

```spl
index=gen_ai_log earliest=-30d
| `genai_token_cost_join`
| `genai_cost_by_app`
```

### Cost Trend Over Time

```spl
index=gen_ai_log earliest=-7d
| `genai_token_cost_join`
| `genai_cost_timechart(1h)`
```

---

## Sample Data: Initial Pricing Setup

Run this query to initialize the KV store with common model pricing (as of January 2024):

```spl
| makeresults count=1
| eval data=mvappend(
    "openai|gpt-4|input|30.00|2024-01-01",
    "openai|gpt-4|output|60.00|2024-01-01",
    "openai|gpt-4-turbo|input|10.00|2024-01-01",
    "openai|gpt-4-turbo|output|30.00|2024-01-01",
    "openai|gpt-4o|input|5.00|2024-05-01",
    "openai|gpt-4o|output|15.00|2024-05-01",
    "openai|gpt-4o-mini|input|0.15|2024-07-01",
    "openai|gpt-4o-mini|output|0.60|2024-07-01",
    "openai|gpt-3.5-turbo|input|0.50|2024-01-01",
    "openai|gpt-3.5-turbo|output|1.50|2024-01-01",
    "anthropic|claude-3-opus|input|15.00|2024-03-01",
    "anthropic|claude-3-opus|output|75.00|2024-03-01",
    "anthropic|claude-3-sonnet|input|3.00|2024-03-01",
    "anthropic|claude-3-sonnet|output|15.00|2024-03-01",
    "anthropic|claude-3-5-sonnet-20241022|input|3.00|2024-10-22",
    "anthropic|claude-3-5-sonnet-20241022|output|15.00|2024-10-22",
    "anthropic|claude-3-haiku|input|0.25|2024-03-01",
    "anthropic|claude-3-haiku|output|1.25|2024-03-01",
    "aws.bedrock|anthropic.claude-3-sonnet|input|3.00|2024-03-01",
    "aws.bedrock|anthropic.claude-3-sonnet|output|15.00|2024-03-01",
    "aws.bedrock|anthropic.claude-3-haiku|input|0.25|2024-03-01",
    "aws.bedrock|anthropic.claude-3-haiku|output|1.25|2024-03-01",
    "aws.bedrock|amazon.titan-text-express|input|0.20|2024-01-01",
    "aws.bedrock|amazon.titan-text-express|output|0.60|2024-01-01",
    "aws.bedrock|meta.llama3-70b-instruct|input|2.65|2024-04-01",
    "aws.bedrock|meta.llama3-70b-instruct|output|3.50|2024-04-01"
)
| mvexpand data
| eval parts=split(data, "|"),
       provider=mvindex(parts, 0),
       model=mvindex(parts, 1),
       direction=mvindex(parts, 2),
       cost_per_million=tonumber(mvindex(parts, 3)),
       effective_start=strptime(mvindex(parts, 4)." 00:00:00", "%Y-%m-%d %H:%M:%S"),
       effective_end=null(),
       currency="USD"
| table provider, model, direction, cost_per_million, effective_start, effective_end, currency
| outputlookup genai_token_cost_lookup
```

---

## Deleting Records

### Delete Specific Record by Key

```spl
| inputlookup genai_token_cost_lookup
| search provider="openai" model="gpt-4" direction="input"
| head 1
| eval _key=_key
| outputlookup genai_token_cost_lookup key_field=_key append=false
```

### Delete All Records for a Model

```spl
| inputlookup genai_token_cost_lookup
| where NOT (provider="openai" AND model="gpt-4")
| outputlookup genai_token_cost_lookup
```

### Clear Entire KV Store (Use with Caution!)

```spl
| inputlookup genai_token_cost_lookup
| delete
```

Or via REST API:

```bash
curl -k -u admin:<password> -X DELETE \
  "https://localhost:8089/servicesNS/nobody/TA-gen_ai_cim/storage/collections/data/genai_token_cost"
```

---

## REST API Management

### Add Record via REST

```bash
curl -k -u admin:<password> \
  https://localhost:8089/servicesNS/nobody/TA-gen_ai_cim/storage/collections/data/genai_token_cost \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai",
    "model": "gpt-4",
    "direction": "input",
    "cost_per_million": 30.00,
    "effective_start": 1704067200,
    "effective_end": null,
    "currency": "USD"
  }'
```

### Query Records via REST

```bash
curl -k -u admin:<password> \
  "https://localhost:8089/servicesNS/nobody/TA-gen_ai_cim/storage/collections/data/genai_token_cost?query=%7B%22provider%22%3A%22openai%22%7D"
```

### Update Record via REST

```bash
curl -k -u admin:<password> -X POST \
  "https://localhost:8089/servicesNS/nobody/TA-gen_ai_cim/storage/collections/data/genai_token_cost/<key_id>" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai",
    "model": "gpt-4",
    "direction": "input",
    "cost_per_million": 25.00,
    "effective_start": 1704067200,
    "effective_end": null,
    "currency": "USD"
  }'
```

---

## Available Macros Reference

| Macro | Description |
|-------|-------------|
| `genai_token_cost_join` | Joins token costs to events based on provider, model, and time |
| `genai_token_cost_join_subsearch` | Alternative join using lookup (may perform better in some cases) |
| `genai_token_cost_summary(span)` | Aggregates costs by time period |
| `genai_cost_by_provider` | Summarizes costs grouped by provider |
| `genai_cost_by_model` | Summarizes costs grouped by model |
| `genai_cost_by_app` | Summarizes costs grouped by application |
| `genai_cost_timechart(span)` | Creates cost timechart |
| `genai_get_current_pricing` | Shows all currently active pricing |
| `genai_get_pricing_history(provider, model)` | Shows pricing history for a specific model |

---

## Best Practices

1. **Always use time-versioning**: Never update existing records directly. Expire them and create new ones.

2. **Consistent provider names**: Match the `provider` field to your `gen_ai.provider.name` values exactly.

3. **Model identifier matching**: Ensure `model` matches your `gen_ai.request.model` values exactly.

4. **Track price changes**: Document price changes with accurate `effective_start` timestamps.

5. **Backup before bulk changes**: Export KV store contents before making large updates:
   ```spl
   | inputlookup genai_token_cost_lookup
   | outputlookup genai_token_cost_backup_20240115.csv
   ```

6. **Validate after updates**: After adding/updating pricing, verify with:
   ```spl
   | `genai_get_current_pricing`
   ```

---

## Troubleshooting

### Costs Not Calculating

1. **Check field names match**: Ensure `gen_ai.provider.name` and `gen_ai.request.model` exist in your events
2. **Verify pricing exists**: Run `| `genai_get_current_pricing`` to see active prices
3. **Check time ranges**: Ensure `effective_start` is before your event times

### Duplicate Pricing Records

```spl
| inputlookup genai_token_cost_lookup
| stats count by provider, model, direction, effective_start
| where count > 1
```

### Find Gaps in Pricing Coverage

```spl
index=gen_ai_log earliest=-7d
| stats dc(gen_ai.request.model) AS models, values(gen_ai.request.model) AS model_list by gen_ai.provider.name
| mvexpand model_list
| lookup genai_token_cost_lookup provider AS gen_ai.provider.name, model AS model_list, direction AS dir OUTPUT cost_per_million
| where isnull(cost_per_million)
| eval dir="input"
| table gen_ai.provider.name, model_list
| dedup gen_ai.provider.name, model_list
```
