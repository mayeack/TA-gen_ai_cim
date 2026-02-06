# PII/PHI Detection ML Model

Complete guide for implementing machine learning-based PII (Personally Identifiable Information) and PHI (Protected Health Information) detection in GenAI prompts and responses.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [PII Categories Detected](#pii-categories-detected)
4. [Feature Engineering](#feature-engineering)
5. [Quick Start (5-Minute Setup)](#quick-start-5-minute-setup)
6. [Training the Model](#training-the-model)
7. [Scoring Pipeline](#scoring-pipeline)
8. [Alerts and Monitoring](#alerts-and-monitoring)
9. [Threshold Tuning](#threshold-tuning)
10. [Healthcare-Specific Patterns](#healthcare-specific-patterns)
11. [Model Performance](#model-performance)
12. [Feedback Loop (Active Learning)](#feedback-loop-active-learning)
13. [Troubleshooting](#troubleshooting)
14. [Reference](#reference)

---

## Overview

This ML-based PII/PHI detection system identifies sensitive information in:

- **Prompts (User Inputs):** Detect when users inadvertently share PII
- **Responses (AI Outputs):** Detect when AI models leak PII in responses

### Key Capabilities

| Capability | Description |
|------------|-------------|
| **22+ PII Types** | SSN, Email, Phone, Credit Card, DOB, Address, MRN, Member ID, and more |
| **Healthcare PHI** | MRN, Member ID, Claim Numbers, Medications, NPI, DEA numbers |
| **ML + Rules** | Hybrid approach combining ML probability scores with regex patterns |
| **Risk Scoring** | 0-1 probability score with confidence levels |
| **Multi-Location** | Detects PII in prompts, responses, or both |
| **Pre-Trained Data** | Includes 200k labeled healthcare examples |

### Output Fields

After scoring, events are enriched with:

```
gen_ai.pii.risk_score       - ML probability (0-1)
gen_ai.pii.ml_detected      - Boolean flag ("true"/"false")
gen_ai.pii.confidence       - Level: very_high, high, medium, low, very_low
gen_ai.pii.types            - Comma-separated list of detected PII types
gen_ai.pii.category         - Category: healthcare, identity, financial, contact
gen_ai.pii.severity         - Severity: critical, high, medium, low, none
gen_ai.pii.location         - Where found: prompt, response, both, none
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  GenAI Events (index=gen_ai_log)                                        │
│  ├── gen_ai.input.messages (prompts)                                    │
│  └── gen_ai.output.messages (responses)                                 │
└─────────────────────────┬───────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Feature Engineering (20 features)                                       │
│  ├── Pattern Features (regex):                                          │
│  │   SSN, Email, Phone, CC, DOB, Address, MRN, Member ID, etc.         │
│  ├── Statistical Features:                                              │
│  │   Length, Word Count, Digit Ratio, Special Char Ratio               │
│  └── Keyword Features:                                                  │
│      Medical Terms, Insurance Terms, Financial Terms, Identity Terms    │
└─────────────────────────┬───────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  ML Model (LogisticRegression)                                            │
│  ├── Input: 20 engineered features                                      │
│  ├── Output: Probability score (0-1)                                    │
│  └── Model: pii_detection_model                                         │
└─────────────────────────┬───────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Risk Classification                                                     │
│  ├── Risk Score > 0.9 → very_high confidence                           │
│  ├── Risk Score > 0.7 → high confidence                                │
│  ├── Risk Score > 0.5 → medium confidence (detection threshold)        │
│  ├── Risk Score > 0.3 → low confidence                                 │
│  └── Risk Score ≤ 0.3 → very_low confidence                            │
└─────────────────────────┬───────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Enriched Events + Alerts                                                │
│  ├── Write to index=gen_ai_log (enriched)                              │
│  ├── Trigger alerts (high risk, SSN/CC, healthcare PHI)                │
│  └── Populate dashboards                                                │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## PII Categories Detected

### Identity Information

| Type | Pattern | Example |
|------|---------|---------|
| SSN | `\d{3}-\d{2}-\d{4}` | 123-45-6789 |
| DOB | Date of birth patterns | March 15, 1985 |
| Driver's License | `DL/DLN` + digits | D1234567890 |
| Passport | `passport` + alphanumeric | US12345678 |

### Contact Information

| Type | Pattern | Example |
|------|---------|---------|
| Email | Standard email regex | john@example.com |
| Phone | Multiple formats | (555) 123-4567 |
| Address | Street + City + State + ZIP | 123 Main St, Springfield, IL 62701 |
| ZIP Code | 5-digit or 9-digit | 62701-1234 |

### Financial Information

| Type | Pattern | Example |
|------|---------|---------|
| Credit Card | 16 digits (various formats) | 4111-1111-1111-1111 |
| Bank Account | Account + digits | Account #98765432100 |
| Routing Number | 9 digits | Routing: 091000019 |

### Healthcare PHI (HIPAA)

| Type | Pattern | Example |
|------|---------|---------|
| MRN | `MRN` + alphanumeric | MRN HSP123456 |
| Member ID | `MEM-` or `member ID` | MEM-7834521 |
| Claim Number | `CLM` + digits | CLM99887766 |
| Medication | Drug name + dosage | Metformin 500mg |
| NPI | 10-digit provider ID | NPI: 1234567890 |
| DEA Number | 2 letters + 7 digits | DEA: AB1234567 |
| Medicare ID | 11-character beneficiary ID | 1EG4-TE5-MK72 |

---

## Feature Engineering

### Pattern-Based Features (11 features)

Each feature is binary (0 or 1):

| Feature | Pattern Detected |
|---------|------------------|
| `has_ssn` | SSN format (123-45-6789) |
| `has_email` | Email addresses |
| `has_phone` | Phone numbers (multiple formats) |
| `has_credit_card` | Credit card numbers (16 digits) |
| `has_dob` | Date of birth patterns |
| `has_address` | Street addresses with city/state/ZIP |
| `has_zipcode` | ZIP codes (5 or 9 digit) |
| `has_patient_name` | Patient name patterns |
| `has_member_id` | Insurance member IDs |
| `has_claim_number` | Healthcare claim numbers |
| `has_medication` | Medication names + dosages |

### Statistical Features (5 features)

| Feature | Description |
|---------|-------------|
| `output_length` | Character count of response |
| `word_count` | Word count of response |
| `digit_ratio` | Percentage of digits in text (0.0-1.0) |
| `special_char_ratio` | Percentage of special characters |
| `uppercase_ratio` | Percentage of uppercase letters |

### Keyword Features (4 features)

| Feature | Keywords Detected |
|---------|-------------------|
| `has_insurance_terms` | member ID, insurance, claim, coverage, copay, deductible... |
| `has_financial_terms` | account number, credit card, balance, payment, routing... |
| `has_identity_terms` | SSN, social security, passport, driver's license, DOB... |
| `has_contact_terms` | email, phone, address, contact, zip code, postal code... |

### Feature Engineering SPL

```spl
| eval output_length=len(response_text)
| eval word_count=mvcount(split(response_text, " "))

| rex field=response_text "(?<member_id_match>(?:member\s+ID|MEM-|INS-)\s*[A-Z0-9-]{7,15})"
| eval has_member_id=if(isnotnull(member_id_match), 1, 0)

| rex field=response_text "(?<claim_match>claim\s+CLM\d{8,10})"
| eval has_claim_number=if(isnotnull(claim_match), 1, 0)

| rex field=response_text "(?<ssn_match>\d{3}-\d{2}-\d{4})"
| eval has_ssn=if(isnotnull(ssn_match), 1, 0)

| rex field=response_text "(?<email_match>[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
| eval has_email=if(isnotnull(email_match), 1, 0)

| rex field=response_text "(?<phone_match>(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})|(\d{3}\.\d{3}\.\d{4}))"
| eval has_phone=if(isnotnull(phone_match), 1, 0)

| rex field=response_text "(?<cc_match>\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})"
| eval has_credit_card=if(isnotnull(cc_match), 1, 0)

| rex field=response_text "(?<dob_match>(?:date of birth|DOB|born):?\s*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}))"
| eval has_dob=if(isnotnull(dob_match), 1, 0)

| rex field=response_text "(?<address_match>\d+\s+[A-Za-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Way|Court|Ct|Place|Pl),?\s+[A-Z][a-z]+,?\s+[A-Z]{2}\s+\d{5})"
| eval has_address=if(isnotnull(address_match), 1, 0)

| rex field=response_text "(?<zip_match>\b\d{5}(?:-\d{4})?\b)"
| eval has_zipcode=if(isnotnull(zip_match), 1, 0)

| rex field=response_text "(?<name_match>(?:patient|for|Hi)\s+([A-Z][a-z]+\s+[A-Z][a-z]+))"
| eval has_patient_name=if(isnotnull(name_match), 1, 0)

| rex field=response_text "(?<medication_match>\b[A-Z][a-z]+(?:ine|ol|am|in|ate)\s+\d+\s*mg\b)"
| eval has_medication=if(isnotnull(medication_match), 1, 0)

| eval digit_count=len(replace(response_text, "[^\d]", ""))
| eval digit_ratio=if(output_length>0, round(digit_count/output_length, 4), 0)

| eval special_char_count=len(replace(response_text, "[A-Za-z0-9\s]", ""))
| eval special_char_ratio=if(output_length>0, round(special_char_count/output_length, 4), 0)

| eval uppercase_count=len(replace(response_text, "[^A-Z]", ""))
| eval uppercase_ratio=if(output_length>0, round(uppercase_count/output_length, 4), 0)

| eval has_insurance_terms=if(match(response_text, "(?i)(member ID|insurance|claim|coverage|copay|deductible|policy|provider network)"), 1, 0)
| eval has_financial_terms=if(match(response_text, "(?i)(account number|credit card|balance|payment|routing number|bank|transaction|invoice|billing)"), 1, 0)
| eval has_identity_terms=if(match(response_text, "(?i)(SSN|social security|passport|driver.?s? license|license number|ID number|identification|date of birth|DOB)"), 1, 0)
| eval has_contact_terms=if(match(response_text, "(?i)(email|phone|address|contact|zip code|postal code|reach you|call you)"), 1, 0)
```

---

## Quick Start (5-Minute Setup)

### Step 1: Run Feature Engineering

```spl
| savedsearch "GenAI - PII Train Step 1 - Feature Engineering from Initial Dataset"
```

This processes the included 200k healthcare training dataset (~5-10 minutes).

### Step 2: Train the Model

```spl
| savedsearch "GenAI - PII Train Step 2 - Logistic Regression Model"
```

### Step 3: Validate Performance

```spl
| savedsearch "GenAI - PII Train Step 3 - Validate Model Performance"
```

Expected output:

| Metric | Target | Description |
|--------|--------|-------------|
| Accuracy | > 0.90 | Overall correctness |
| Precision | > 0.75 | Of predicted PII, how many are correct |
| Recall | > 0.85 | Of actual PII, how many caught |
| F1 Score | > 0.80 | Harmonic mean of precision/recall |

### Step 4: Enable Scoring

```bash
$SPLUNK_HOME/bin/splunk enable saved-search "GenAI - PII Scoring - Response Analysis" -app TA-gen_ai_cim
```

### Step 5: Enable Alerts

```bash
$SPLUNK_HOME/bin/splunk enable saved-search "GenAI - PII ML High Risk Alert" -app TA-gen_ai_cim
```

---

## Training the Model

### Training Data

The TA includes `llm_pii_mixed_responses_200k.csv` with 200,000 healthcare AI responses:

| Column | Description |
|--------|-------------|
| `prompt` | User input/question |
| `response` | AI model response |
| `pii_label` | 0 = Clean, 1 = Contains PII |

**Class Distribution:**
- Clean (0): ~190,000 (95%)
- PII (1): ~10,000 (5%)

### Training SPL (LogisticRegression)

```spl
| inputlookup pii_training_data_engineered.csv
| fit LogisticRegression pii_label
    from output_length word_count digit_ratio special_char_ratio uppercase_ratio
    has_ssn has_email has_phone has_dob has_address has_credit_card has_name
    probabilities=true
    into app:pii_detection_model
```

### Custom Training Data

To train with your own data:

1. Create CSV with columns: `response`, `pii_label` (0 or 1)
2. Upload to `$SPLUNK_HOME/etc/apps/TA-gen_ai_cim/lookups/`
3. Modify feature engineering saved search to use your file

---

## Scoring Pipeline

### Scheduled Scoring

The `GenAI - PII Scoring - Response Analysis` saved search runs every minute to:

1. Extract response text from events
2. Engineer 20 features
3. Apply ML model
4. Classify PII types
5. Write enriched events back to index

### Manual Scoring SPL

```spl
index=gen_ai_log NOT sourcetype="ai_cim:pii:ml_scoring" earliest=-1h latest=now
| eval response_text='gen_ai.output.messages'
| where isnotnull(response_text) AND len(response_text) > 20
| dedup gen_ai.event.id

``` Feature engineering (abbreviated - see full version in saved search) ```
| eval output_length=len(response_text)
| eval word_count=mvcount(split(response_text, " "))
``` ... additional feature engineering ... ```

| apply pii_detection_model

| eval "gen_ai.pii.risk_score"=round('predicted(pii_label)', 4)
| eval "gen_ai.pii.ml_detected"=if('gen_ai.pii.risk_score'>0.5, "true", "false")
| eval "gen_ai.pii.confidence"=case(
    'gen_ai.pii.risk_score'>0.9, "very_high",
    'gen_ai.pii.risk_score'>0.7, "high",
    'gen_ai.pii.risk_score'>0.5, "medium",
    'gen_ai.pii.risk_score'>0.3, "low",
    1=1, "very_low"
)

| table _time gen_ai.event.id gen_ai.pii.risk_score gen_ai.pii.ml_detected gen_ai.pii.confidence
```

---

## Alerts and Monitoring

### Pre-Configured Alerts

| Alert | Severity | Schedule | Trigger |
|-------|----------|----------|---------|
| **GenAI - PII ML High Risk Alert** | High | Every 15 min | Risk score > 0.7 |
| **GenAI - PII Detection Alert** | High | Every hour | Any PII detected |
| **GenAI - PII High Volume Alert** | High | Every 4 hours | PII rate > 5% |

### Scheduled Reports

| Report | Schedule | Purpose |
|--------|----------|---------|
| **GenAI - PII ML Daily Summary Report** | Daily 8 AM | Summary of all PII detections |
| **GenAI - PII ML Weekly Model Performance Report** | Weekly Monday | Model health metrics |
| **GenAI - PII Types Distribution Report** | Weekly Monday | Breakdown by PII type |

### Custom Alert Example

```spl
index=gen_ai_log
    gen_ai.pii.ml_detected="true"
    (gen_ai.pii.types="*SSN*" OR gen_ai.pii.types="*CREDIT_CARD*")
    gen_ai.pii.risk_score > 0.8
| stats count by gen_ai.app.name, gen_ai.pii.types
| where count > 3
```

---

## Threshold Tuning

### Default Threshold: 0.5

The default detection threshold is 0.5 (50% probability).

### Adjusting for Your Use Case

| Use Case | Threshold | Trade-off |
|----------|-----------|-----------|
| **High Security (HIPAA, PCI)** | 0.3 | Catches more PII, higher false positives |
| **Balanced** | 0.5 | Default, good balance |
| **Low False Positives** | 0.7 | Fewer alerts, may miss some PII |

### Testing Different Thresholds

```spl
| inputlookup pii_training_data_engineered.csv
| sample 5000
| apply pii_detection_model
| eval risk_score='predicted(pii_label)'

| eval pred_03=if(risk_score>0.3, 1, 0)
| eval pred_05=if(risk_score>0.5, 1, 0)
| eval pred_07=if(risk_score>0.7, 1, 0)

| stats
    sum(eval(if(pii_label=1 AND pred_03=1, 1, 0))) as recall_03,
    sum(eval(if(pii_label=1 AND pred_05=1, 1, 0))) as recall_05,
    sum(eval(if(pii_label=1 AND pred_07=1, 1, 0))) as recall_07,
    sum(eval(if(pii_label=0 AND pred_03=1, 1, 0))) as fp_03,
    sum(eval(if(pii_label=0 AND pred_05=1, 1, 0))) as fp_05,
    sum(eval(if(pii_label=0 AND pred_07=1, 1, 0))) as fp_07,
    sum(pii_label) as total_pii,
    sum(eval(if(pii_label=0, 1, 0))) as total_clean

| eval "Recall @ 0.3"=round(recall_03/total_pii*100, 1)."%"
| eval "Recall @ 0.5"=round(recall_05/total_pii*100, 1)."%"
| eval "Recall @ 0.7"=round(recall_07/total_pii*100, 1)."%"
| eval "FP Rate @ 0.3"=round(fp_03/total_clean*100, 1)."%"
| eval "FP Rate @ 0.5"=round(fp_05/total_clean*100, 1)."%"
| eval "FP Rate @ 0.7"=round(fp_07/total_clean*100, 1)."%"

| table "Recall @ 0.3" "Recall @ 0.5" "Recall @ 0.7" "FP Rate @ 0.3" "FP Rate @ 0.5" "FP Rate @ 0.7"
```

---

## Healthcare-Specific Patterns

### Additional Healthcare PHI Patterns

The model includes healthcare-specific pattern detection:

```spl
``` MRN (Medical Record Number) ```
| rex field=response_text "(?<mrn_pattern>MRN\s+[A-Z]{2,4}\d{5,9})"
| eval has_mrn=if(isnotnull(mrn_pattern), 1, 0)

``` Insurance Member ID ```
| rex field=response_text "(?<member_id_pattern>(?:member\s+ID|MEM-|INS-)\s*[A-Z0-9-]{7,15})"
| eval has_member_id=if(isnotnull(member_id_pattern), 1, 0)

``` Claim Numbers ```
| rex field=response_text "(?<claim_pattern>claim\s+CLM\d{8,10})"
| eval has_claim_number=if(isnotnull(claim_pattern), 1, 0)

``` Medications with dosage ```
| rex field=response_text "(?<medication_pattern>\b[A-Z][a-z]+(?:ine|ol|am|in|ate)\s+\d+\s*mg\b)"
| eval has_medication=if(isnotnull(medication_pattern), 1, 0)

``` Medical terminology keywords ```
| eval has_medical_terms=if(match(response_text, "(?i)(patient|diagnosis|prescription|treatment|symptoms|medication|doctor|hospital|medical|health record|condition|therapy|clinic|MRN|medical record)"), 1, 0)
```

### Sensitive Health Information Keywords

The model also detects keywords related to:
- HIV/AIDS status
- Mental health conditions
- Substance abuse history
- Genetic test results
- Sexual health information
- Disability status

---

## Model Performance

### Expected Metrics

With the 200k healthcare dataset:

| Algorithm | Accuracy | Precision | Recall | F1 Score |
|-----------|----------|-----------|--------|----------|
| Logistic Regression | 93-95% | 78-82% | 88-92% | 82-86% |

### Confusion Matrix Query

```spl
| inputlookup pii_training_data_engineered.csv
| sample 5000
| apply pii_detection_model
| eval predicted_class=if('predicted(pii_label)'>0.5, 1, 0)
| eval result=case(
    pii_label=1 AND predicted_class=1, "True Positive",
    pii_label=0 AND predicted_class=0, "True Negative",
    pii_label=0 AND predicted_class=1, "False Positive",
    pii_label=1 AND predicted_class=0, "False Negative"
)
| stats count by result
| eval percentage=round(count/sum(count)*100, 1)
| table result count percentage
```

### Performance Monitoring

```spl
index=gen_ai_log gen_ai.pii.risk_score=*
| stats count as total_scored,
    avg(gen_ai.pii.risk_score) as avg_score,
    stdev(gen_ai.pii.risk_score) as stdev_score,
    sum(eval(if('gen_ai.pii.ml_detected'="true", 1, 0))) as pii_detected
| eval detection_rate=round((pii_detected/total_scored)*100, 2)
| eval model_health=case(
    detection_rate > 20, "WARNING - High detection rate, review for false positives",
    detection_rate < 1, "WARNING - Low detection rate, review model performance",
    stdev_score > 0.4, "WARNING - High variance in scores",
    1=1, "HEALTHY"
)
| table total_scored avg_score detection_rate model_health
```

---

## Feedback Loop (Active Learning)

The PII detection pipeline includes an active learning feedback loop that leverages human reviews to continuously improve the ML model.

### Overview

The feedback loop enables continuous improvement of PII detection by:

1. **Extracting human labels** from completed Event Reviews
2. **Splitting data** into train/validation/test sets (70/15/15)
3. **Training challenger models** with accumulated feedback
4. **Tuning thresholds** to optimize precision/recall trade-off
5. **Comparing models** (champion vs challenger)
6. **Promoting improved models** to production

### Why Active Learning?

- **Model drift**: AI applications evolve, new PII patterns emerge
- **Domain adaptation**: Customize detection for your specific use cases
- **Quality improvement**: Learn from human expert corrections
- **False positive reduction**: Train on your real-world data

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Active Learning Loop                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   GenAI      │───►│  PII Model   │───►│   Review     │          │
│  │   Events     │    │  (Champion)  │    │    Queue     │          │
│  └──────────────┘    └──────────────┘    └──────┬───────┘          │
│                                                  │                   │
│                                                  ▼                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   Model      │◄───│  Challenger  │◄───│   Human      │          │
│  │   Registry   │    │    Model     │    │   Labels     │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
│         │                   ▲                   │                   │
│         │                   │                   │                   │
│         ▼                   │                   ▼                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   Promote    │───►│   Compare    │◄───│   Training   │          │
│  │   Decision   │    │   Metrics    │    │   Feedback   │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                  index=gen_ai_log                            │
│                              (Raw Telemetry Events)                          │
└───────────────────────────────────────┬─────────────────────────────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    │                                       │
                    ▼                                       ▼
    ┌───────────────────────────────┐       ┌───────────────────────────────┐
    │      Scoring Pipeline         │       │     Auto-Escalation           │
    │   (Every minute)              │       │   (Every minute)              │
    │                               │       │                               │
    │  1. Extract response text     │       │  High-risk events ──────────┐ │
    │  2. Engineer 20 features      │       │  Random sample ─────────────┤ │
    │  3. Apply champion model      │       │                             │ │
    │  4. Calculate risk score      │       │                             │ │
    └───────────────┬───────────────┘       └─────────────────────────────┼─┘
                    │                                                      │
                    ▼                                                      │
    ┌───────────────────────────────┐                                     │
    │    Enriched Events            │                                     │
    │  sourcetype=ai_cim:pii:ml_scoring│                                     │
    └───────────────────────────────┘                                     │
                                                                           │
                                                                           ▼
                                            ┌───────────────────────────────┐
                                            │   gen_ai_review_findings      │
                                            │      (KV Store)               │
                                            └───────────────┬───────────────┘
                                                            │
                                                            │ Human Review
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │    Event Review Dashboard     │
                                            │                               │
                                            │  Reviewer sets:               │
                                            │  - pii_confirmed (0/1)        │
                                            │  - status = "completed"       │
                                            └───────────────┬───────────────┘
                                                            │
                                                            │ Daily 2 AM
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │   pii_training_feedback       │
                                            │      (KV Store)               │
                                            └───────────────┬───────────────┘
                                                            │
                                                            │ Weekly Sunday 4 AM
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │   Challenger Model Training   │
                                            └───────────────┬───────────────┘
                                                            │
                                                            │ Weekly Sunday 5 AM
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │   Champion vs Challenger      │
                                            │       Evaluation              │
                                            └───────────────┬───────────────┘
                                                            │
                                                            │ Manual Promotion
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │     pii_model_registry        │
                                            │       (KV Store)              │
                                            └───────────────────────────────┘
```

### Feedback Loop Workflow

#### 1. Data Collection

Human reviewers label events in the Event Review dashboard:
- **PII Confirmed**: Reviewer confirms PII/PHI is present (`pii_confirmed=1`)
- **PII Not Confirmed**: Reviewer confirms the event is clean (`pii_confirmed=0`)
- **PII Types (Reviewed)**: Reviewer selects specific PII types found (SSN, EMAIL, PHONE, etc.)

The `gen_ai_review_pii_types_reviewed` field captures the reviewer-confirmed PII types, which are used as ground truth labels for model retraining.

#### 2. Feedback Extraction (Daily)

The extraction search runs daily at 2 AM:

1. Reads completed reviews from `gen_ai_review_findings`
2. Extracts `gen_ai_review_pii_types_reviewed` (reviewer-confirmed types) as ground truth
3. Generates per-type labels from reviewed types (e.g., `has_ssn_label`, `has_email_label`)
4. Joins with original event data to get full response text and ML predictions
5. Classifies feedback type by comparing ML predictions with reviewer confirmations:

| Feedback Type | Definition |
|---------------|------------|
| `confirmed_pii_exact` | Human confirmed PII, model predicted PII, and types match exactly |
| `confirmed_pii_type_mismatch` | Human confirmed PII, model predicted PII, but types differ |
| `confirmed_clean` | Human confirmed clean, model predicted clean (True Negative) |
| `false_positive` | Human confirmed clean, model predicted PII |
| `false_negative` | Human confirmed PII, model predicted clean |

6. Assigns random train/valid/test split (70/15/15)
7. Engineers all 20 features for training
8. Stores in `pii_training_feedback` collection with per-type ground truth labels

#### 3. Model Training (Weekly)

The training search runs weekly on Sunday at 4 AM:

1. Loads feedback data (train split only)
2. Appends original training data
3. Trains RandomForestClassifier
4. Saves as `pii_detection_model_challenger`

#### 4. Threshold Tuning

Evaluates thresholds 0.3-0.8 on the validation set:

| Threshold | Use Case |
|-----------|----------|
| 0.3 | High recall - catch all PII (more false positives) |
| 0.5 | Balanced - default operating point |
| 0.7-0.8 | High precision - fewer false alarms |

#### 5. Model Comparison

Evaluates both models on the held-out test set:

- Accuracy, Precision, Recall, F1 Score
- Generates promotion recommendation

#### 6. Model Promotion (Manual)

When challenger outperforms champion:

1. Review metrics in Model Comparison dashboard
2. Click "Promote Challenger to Champion"
3. New version registered in `pii_model_registry`

**Promotion Criteria:**
- Challenger F1 score > Champion F1 score
- Challenger recall >= Champion recall (critical for PII)
- Test set has at least 30 samples

### Scheduled Searches

| Search | Schedule | Purpose |
|--------|----------|---------|
| `GenAI - PII Feedback Loop - Extract Training Feedback` | Daily 2:00 AM | Extract completed reviews |
| `GenAI - PII Feedback Loop - Assign Data Splits` | Daily 2:30 AM | Assign train/valid/test splits |
| `GenAI - PII Feedback Loop - Train Challenger Model` | Weekly Sun 4:00 AM | Train new challenger |
| `GenAI - PII Feedback Loop - Threshold Analysis` | Weekly Sun 4:30 AM | Analyze thresholds 0.3-0.8 |
| `GenAI - PII Feedback Loop - Champion vs Challenger Report` | Weekly Sun 5:00 AM | Compare models |
| `GenAI - PII Feedback Loop - Promote Model Version` | Manual | Promote challenger |
| `GenAI - PII Feedback Loop - Model Health Report` | Weekly Mon 9:00 AM | Performance summary |

### KV Store Collections

#### gen_ai_review_findings

**Purpose:** Event review queue and human labels

| Field | Purpose |
|-------|---------|
| `gen_ai_event_id` | Primary key (links to original event) |
| `gen_ai_review_status` | new → in_progress → completed/rejected |
| `gen_ai_review_pii_confirmed` | Human label: 1 = PII present, 0 = clean |
| `gen_ai_review_phi_confirmed` | Human label: 1 = PHI present |
| `gen_ai_review_pii_types` | ML-detected PII types (auto-populated) |
| `gen_ai_review_pii_types_reviewed` | **Reviewer-confirmed PII types (ground truth)** |
| `gen_ai_review_reviewer` | Username who completed review |

#### pii_training_feedback

**Purpose:** Human-labeled data with cached features for retraining

| Field | Purpose |
|-------|---------|
| `event_id` | Primary key |
| `response_text` | Original response text |
| `pii_label` | Human label (0/1) |
| `pii_types` | ML-detected PII types |
| `pii_types_reviewed` | **Reviewer-confirmed PII types (ground truth)** |
| `feedback_type` | confirmed_pii_exact, confirmed_pii_type_mismatch, false_positive, false_negative, confirmed_clean |
| `split_assignment` | train, valid, or test |
| `ml_predicted_score` | Original ML prediction |
| `ml_predicted_types` | ML-detected types for comparison |
| **Per-Type Labels** | |
| `has_ssn_label` | Reviewer confirmed SSN (0/1) |
| `has_email_label` | Reviewer confirmed EMAIL (0/1) |
| `has_phone_label` | Reviewer confirmed PHONE (0/1) |
| `has_dob_label` | Reviewer confirmed DOB (0/1) |
| `has_address_label` | Reviewer confirmed ADDRESS (0/1) |
| `has_credit_card_label` | Reviewer confirmed CREDIT_CARD (0/1) |
| `has_name_label` | Reviewer confirmed NAME (0/1) |
| 20 feature fields | Cached for training (has_ssn, has_email, etc.) |

#### pii_model_registry

**Purpose:** Track model versions, metrics, and promotion history

| Field | Purpose |
|-------|---------|
| `model_name` | Model identifier |
| `model_version` | Version timestamp |
| `status` | champion or archived |
| `accuracy`, `precision`, `recall`, `f1_score` | Performance metrics |
| `promoted_at`, `promoted_by` | Promotion tracking |

### Quick Start Guide

#### Minimum Requirements

- At least **50 completed reviews** with PII labels set
- Balanced class distribution (aim for 20-40% PII samples)
- Events must exist in `gen_ai_log` index for feature extraction

#### Step 1: Complete Event Reviews

1. Navigate to **Review Queue** dashboard
2. Open events and complete reviews
3. **Critical**: Set the PII confirmation field for each review

#### Step 2: Extract Training Feedback

Run manually or wait for daily schedule:
```spl
| savedsearch "GenAI - PII Feedback Loop - Extract Training Feedback"
```

Verify:
```spl
| inputlookup pii_training_feedback_lookup 
| stats count by feedback_type, split_assignment
```

#### Step 3: Train Challenger Model

After 50+ feedback samples:
```spl
| savedsearch "GenAI - PII Feedback Loop - Train Challenger Model"
```

#### Step 4: Compare Models

```spl
| savedsearch "GenAI - PII Feedback Loop - Champion vs Challenger Report"
```

#### Step 5: Promote (If Improved)

Navigate to Model Comparison dashboard and click "Promote Challenger to Champion".

### Metrics & Monitoring

#### Performance Metrics

| Metric | Definition | Target |
|--------|------------|--------|
| **Accuracy** | (TP + TN) / Total | > 90% |
| **Precision** | TP / (TP + FP) | > 75% |
| **Recall** | TP / (TP + FN) | > 85% |
| **F1 Score** | Harmonic mean | > 80% |

#### Feedback Quality Metrics

| Metric | Definition | Warning Threshold |
|--------|------------|-------------------|
| **False Positive Rate** | FP / Total | > 30% |
| **False Negative Rate** | FN / Total | > 10% (critical) |
| **Type Mismatch Rate** | Type Mismatches / Confirmed PII | > 50% |

#### Model Health Check

```spl
| inputlookup pii_training_feedback_lookup
| stats count AS total_feedback,
    sum(eval(if(feedback_type="confirmed_pii_exact" OR feedback_type="confirmed_pii_type_mismatch", 1, 0))) AS confirmed_pii,
    sum(eval(if(feedback_type="confirmed_pii_type_mismatch", 1, 0))) AS type_mismatches,
    sum(eval(if(feedback_type="false_positive", 1, 0))) AS false_positives,
    sum(eval(if(feedback_type="false_negative", 1, 0))) AS false_negatives
| eval fp_rate=round(false_positives/total_feedback*100, 2)
| eval fn_rate=round(false_negatives/total_feedback*100, 2)
| eval type_mismatch_rate=if(confirmed_pii>0, round(type_mismatches/confirmed_pii*100, 2), 0)
| eval model_health=case(
    fn_rate > 20, "CRITICAL - High false negative rate",
    fp_rate > 30, "WARNING - High false positive rate",
    type_mismatch_rate > 50, "WARNING - High type mismatch rate",
    total_feedback < 50, "WARNING - Insufficient feedback data",
    1=1, "HEALTHY"
)
```

---

## Troubleshooting

### Model Not Found

**Error:** `Model 'pii_detection_model' not found`

**Solution:**
1. Verify MLTK is installed
2. Run training Steps 1 and 2
3. Check model exists:

```spl
| inputlookup mlspl_models
| search model_name="pii_detection_model"
```

### Low Recall (Missing PII)

**Possible Causes:**
- Threshold too high
- Missing features for specific PII types
- Imbalanced training data

**Solutions:**
1. Lower threshold to 0.3-0.4
2. Use `class_weight=balanced` in training
3. Add more positive (PII) examples to training data

### High False Positives

**Possible Causes:**
- Threshold too low
- Overfitting on training data
- Medical terms triggering without actual PII

**Solutions:**
1. Raise threshold to 0.6-0.7
2. Review false positive examples
3. Add negative examples similar to false positives

### Scoring Too Slow

**Solutions:**
1. Limit scoring to responses only (skip prompts)
2. Increase scheduling interval
3. Use summary indexing
4. Sample events: `| sample 10000`

### Empty Feature Values

**Issue:** All features are 0

**Solution:** Verify text extraction:

```spl
index=gen_ai_log | head 5
| eval response_text=coalesce('gen_ai.output.messages', 'event.output', output, response)
| table response_text
```

---

## Reference

### Saved Searches - Training

| Saved Search | Description |
|--------------|-------------|
| GenAI - PII Train Step 1 - Feature Engineering from Initial Dataset | Prepare features from 200k dataset |
| GenAI - PII Train Step 2 - Logistic Regression Model | Train LogisticRegression with probability output |
| GenAI - PII Train Step 3 - Validate Model Performance | Calculate performance metrics |

### Saved Searches - Scoring

| Saved Search | Schedule | Description |
|--------------|----------|-------------|
| GenAI - PII Scoring - Response Analysis | Every minute | Score responses with ML model |

### Saved Searches - Alerts

| Saved Search | Schedule | Description |
|--------------|----------|-------------|
| GenAI - PII ML High Risk Alert | 15 min | Risk > 0.7 |
| GenAI - PII Detection Alert | 1 hour | Any PII detected |
| GenAI - PII High Volume Alert | 4 hours | Rate > 5% |

### Best Practices

1. **Start with pattern matching** before deploying ML scoring
2. **Monitor model drift** - watch for detection rate changes > 20%
3. **Retrain periodically** when false positive/negative rates increase
4. **Layer detection methods** - use both ML and rule-based detection
5. **Log PII metadata only** - avoid storing actual PII values
6. **Set up tiered alerting** based on severity

---

## See Also

- [Prompt_Injection.md](Prompt_Injection.md) - Prompt injection detection
- [TFIDF_Anomaly.md](TFIDF_Anomaly.md) - Anomaly detection

---

**Last Updated:** 2026-02-05
