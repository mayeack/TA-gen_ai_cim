# ✅ YOUR PII TRAINING DATA IS READY!

## What I've Done

✅ **Copied your 200,000 example dataset** to the TA
- Location: `/opt/splunk/etc/apps/TA-gen_ai_cim/lookups/llm_pii_mixed_responses_200k.csv`
- Size: 74MB
- Format: `prompt,response,pii_label`

✅ **Analyzed your data** and identified PII patterns:
- Patient names (Luna Quinn, Isla Stone, Ezra Bennett, etc.)
- MRNs (Medical Record Numbers): HSP846967, REC830624, PT575759
- Member IDs: MEM-6836382, INS-5622089, MEM-1078213
- Claim numbers: CLM37188289, CLM95122908, CLM43130864
- Phone numbers: Multiple formats (555-0119, 801-555-0196, etc.)
- Email addresses: patient@example.com, user@example.net
- Dates of birth: Jan 13, 2004
- Physical addresses: Street addresses with city, state, ZIP
- Medications: cetirizine 10 mg, sertraline 250 mg

✅ **Created healthcare-optimized training SPL**
- 22 engineered features (vs standard 16)
- Healthcare-specific patterns: MRN, Member ID, Claim numbers
- Medical terminology detection
- Insurance/billing keywords
- Medication patterns
- Patient name recognition

✅ **Added lookup definition** to transforms.conf

✅ **Created complete training guide**
- Location: `README/ML Models/PII_Detection.md`
- Step-by-step SPL for your dataset
- 3 algorithm options (Logistic Regression, Random Forest, Gradient Boosting)
- Performance testing queries
- Threshold tuning guide

---

## Quick Start: Train Your Model Now

### Step 1: Prepare Data (5-10 minutes)

Copy this SPL into Splunk Search:

```spl
| inputlookup llm_pii_mixed_responses_200k.csv
| eval response_text=if(isnull(response), "", response)
| eval pii_label=if(isnull(pii_label), 0, pii_label)
| eval output_length=len(response_text)
| eval word_count=mvcount(split(response_text, " "))
| rex field=response_text "(?<mrn_pattern>MRN\s+[A-Z]{2,4}\d{5,9})"
| eval has_mrn=if(isnotnull(mrn_pattern), 1, 0)
| rex field=response_text "(?<member_id_pattern>(?:member\s+ID|MEM-|INS-)\s*[A-Z0-9-]{7,15})"
| eval has_member_id=if(isnotnull(member_id_pattern), 1, 0)
| rex field=response_text "(?<claim_pattern>claim\s+CLM\d{8,10})"
| eval has_claim_number=if(isnotnull(claim_pattern), 1, 0)
| rex field=response_text "(?<ssn_pattern>\d{3}-\d{2}-\d{4})"
| eval has_ssn=if(isnotnull(ssn_pattern), 1, 0)
| rex field=response_text "(?<email_pattern>[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
| eval has_email=if(isnotnull(email_pattern), 1, 0)
| rex field=response_text "(?<phone_pattern>(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})|(\d{3}\.\d{3}\.\d{4}))"
| eval has_phone=if(isnotnull(phone_pattern), 1, 0)
| rex field=response_text "(?<cc_pattern>\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})"
| eval has_credit_card=if(isnotnull(cc_pattern), 1, 0)
| rex field=response_text "(?<dob_pattern>(?:date of birth|DOB|born):?\s*(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2},\s+\d{4}))"
| eval has_dob=if(isnotnull(dob_pattern), 1, 0)
| rex field=response_text "(?<address_pattern>\d+\s+[A-Za-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Way|Court|Ct|Place|Pl),?\s+[A-Z][a-z]+,?\s+[A-Z]{2}\s+\d{5})"
| eval has_address=if(isnotnull(address_pattern), 1, 0)
| rex field=response_text "(?<zip_pattern>\b\d{5}(?:-\d{4})?\b)"
| eval has_zipcode=if(isnotnull(zip_pattern), 1, 0)
| rex field=response_text "(?<name_pattern>(?:patient|for|Hi)\s+([A-Z][a-z]+\s+[A-Z][a-z]+))"
| eval has_patient_name=if(isnotnull(name_pattern), 1, 0)
| eval digit_count=len(replace(response_text, "[^\d]", ""))
| eval digit_ratio=if(output_length>0, round(digit_count/output_length, 3), 0)
| eval special_char_count=len(replace(response_text, "[A-Za-z0-9\s]", ""))
| eval special_char_ratio=if(output_length>0, round(special_char_count/output_length, 3), 0)
| eval uppercase_count=len(replace(response_text, "[^A-Z]", ""))
| eval uppercase_ratio=if(output_length>0, round(uppercase_count/output_length, 3), 0)
| eval has_medical_terms=if(match(response_text, "(?i)(patient|diagnosis|prescription|treatment|symptoms|medication|doctor|hospital|medical|health record|condition|therapy|clinic|MRN|medical record)"), 1, 0)
| eval has_insurance_terms=if(match(response_text, "(?i)(member ID|insurance|claim|coverage|copay|deductible|policy|provider network)"), 1, 0)
| eval has_financial_terms=if(match(response_text, "(?i)(account number|credit card|balance|payment|routing number|bank|transaction|invoice|billing)"), 1, 0)
| eval has_identity_terms=if(match(response_text, "(?i)(SSN|social security|passport|driver.?s? license|license number|ID number|identification|date of birth|DOB)"), 1, 0)
| eval has_contact_terms=if(match(response_text, "(?i)(email|phone|address|contact|zip code|postal code|reach you|call you)"), 1, 0)
| rex field=response_text "(?<medication_pattern>\b[A-Z][a-z]+(?:ine|ol|am|in|ate)\s+\d+\s*mg\b)"
| eval has_medication=if(isnotnull(medication_pattern), 1, 0)
| table response_text pii_label output_length word_count digit_ratio special_char_ratio uppercase_ratio 
    has_mrn has_member_id has_claim_number has_ssn has_email has_phone has_credit_card has_dob 
    has_address has_zipcode has_patient_name has_medication
    has_medical_terms has_insurance_terms has_financial_terms has_identity_terms has_contact_terms
| outputlookup pii_healthcare_training_data_engineered.csv
```

### Step 2: Train Model (10-30 minutes)

**Recommended: Random Forest (Best for your imbalanced data)**

```spl
| inputlookup pii_healthcare_training_data_engineered.csv
| fit RandomForestClassifier pii_label 
    from output_length word_count digit_ratio special_char_ratio uppercase_ratio 
    has_mrn has_member_id has_claim_number has_ssn has_email has_phone has_credit_card has_dob 
    has_address has_zipcode has_patient_name has_medication
    has_medical_terms has_insurance_terms has_financial_terms has_identity_terms has_contact_terms 
    max_depth=15 
    max_features=8 
    n_estimators=100
    class_weight=balanced
    random_state=42
    into app:pii_healthcare_model
```

### Step 3: Test Model (2-5 minutes)

```spl
| inputlookup pii_healthcare_training_data_engineered.csv
| apply pii_healthcare_model
| eval predicted_pii='predicted(pii_label)'
| eval predicted_class=if(predicted_pii>0.5, 1, 0)
| eval true_positive=if(pii_label=1 AND predicted_class=1, 1, 0)
| eval true_negative=if(pii_label=0 AND predicted_class=0, 1, 0)
| eval false_positive=if(pii_label=0 AND predicted_class=1, 1, 0)
| eval false_negative=if(pii_label=1 AND predicted_class=0, 1, 0)
| stats sum(true_positive) as TP, 
    sum(true_negative) as TN, 
    sum(false_positive) as FP, 
    sum(false_negative) as FN
| eval Total=TP+TN+FP+FN
| eval Accuracy=round((TP+TN)/Total, 4)
| eval Precision=round(TP/(TP+FP), 4)
| eval Recall=round(TP/(TP+FN), 4)
| eval F1_Score=round(2*(Precision*Recall)/(Precision+Recall), 4)
| table Accuracy Precision Recall F1_Score TP TN FP FN
```

### Step 4: Export Model

```bash
# Copy trained model to TA
cp $SPLUNK_HOME/etc/apps/Splunk_ML_Toolkit/local/mlspl_models/pii_healthcare_model* \
   $SPLUNK_HOME/etc/apps/TA-gen_ai_cim/mlspl/

# Load model
bash $SPLUNK_HOME/etc/apps/TA-gen_ai_cim/bin/load_pii_model.sh

# Restart Splunk
$SPLUNK_HOME/bin/splunk restart
```

---

## Your Data Characteristics

**Total Examples:** 200,000
**Class Distribution:**
- Clean (0): ~190,000 (95%)
- PII/PHI (1): ~10,000 (5%)

**Imbalance Handling:**
✅ Use `class_weight=balanced` in training
✅ Monitor **Recall** closely (catching PII is critical)
✅ Consider threshold tuning (0.3-0.7 instead of default 0.5)

**PII Types in Your Data:**
- Healthcare IDs (MRN, Member ID, Claim)
- Contact Info (Phone, Email)
- Identity (Names, DOB, Address)
- Medical Info (Medications, Conditions)

---

## Expected Performance

With 200k examples and healthcare-optimized features:

| Metric | Target | Notes |
|--------|--------|-------|
| **Accuracy** | 92-96% | High due to large training set |
| **Precision** | 75-85% | Some false positives acceptable |
| **Recall** | 85-95% | **CRITICAL** - Must catch PII |
| **F1 Score** | 80-90% | Balanced performance |

---

## File Locations

### Training Data
- **Original:** `lookups/llm_pii_mixed_responses_200k.csv` (74MB)
- **Engineered:** `lookups/pii_healthcare_training_data_engineered.csv` (generated)

### Documentation
- **PII Detection Guide:** `README/ML Models/PII_Detection.md` ← **START HERE**
- **MLTK Reference:** `README/ML Models/README.md`
- **Feedback Loop:** `README/ML Models/Feedback_Loop.md`

### Model Files (after training)
- `mlspl/pii_healthcare_model.json`
- `mlspl/pii_healthcare_model.pkl`
- `mlspl/pii_healthcare_model_metadata.json`

### Scripts
- **Model Loader:** `bin/load_pii_model.sh`

---

## Troubleshooting

### If Feature Engineering Takes Too Long
- Add `| head 50000` after inputlookup to train on subset first
- Test on 50k examples, if good, run on full 200k

### If Training Fails
- Check MLTK is installed: `| rest /services/apps/local | search title="Splunk_ML_Toolkit"`
- Check Python: `$SPLUNK_HOME/bin/splunk search "| fit LogisticRegression"`
- Try simpler algorithm first (Logistic Regression)

### If Accuracy is Low
- Try different threshold (0.3 for high recall, 0.7 for high precision)
- Try GradientBoostingClassifier
- Check feature importance: `| fit summary pii_healthcare_model`

---

## Next Actions

1. **Run Step 1** (Feature Engineering SPL above) → `outputlookup pii_healthcare_training_data_engineered.csv`
2. **Run Step 2** (Training SPL above) → `into app:pii_healthcare_model`
3. **Run Step 3** (Test SPL above) → See metrics
4. **If metrics good:** Export model (Step 4)
5. **Read full guide:** `README/ML Models/PII_Detection.md`

---

## Summary

✅ **200,000 training examples** stored in TA  
✅ **Healthcare-optimized features** (22 features including MRN, Member ID, Claims)  
✅ **Complete training SPL** provided above  
✅ **Comprehensive documentation** in `README/ML Models/PII_Detection.md`  
✅ **Model loader script** ready: `bin/load_pii_model.sh`  

**You're ready to train!** Just copy the SPL above into Splunk Search. 🚀

---

**Questions?** Check `README/ML Models/PII_Detection.md` for detailed explanations!
