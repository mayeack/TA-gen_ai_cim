#!/bin/bash
#
# Load pre-trained Prompt Injection detection model into MLTK
#

SPLUNK_HOME=${SPLUNK_HOME:-/opt/splunk}
TA_HOME="$SPLUNK_HOME/etc/apps/TA-gen_ai_cim"
MLTK_MODELS="$SPLUNK_HOME/etc/apps/Splunk_ML_Toolkit/local/mlspl_models"

echo "==============================================="
echo "  Loading Prompt Injection Detection Model"
echo "==============================================="
echo ""

# Check if MLTK is installed
if [ ! -d "$SPLUNK_HOME/etc/apps/Splunk_ML_Toolkit" ]; then
    echo "✗ Error: Splunk Machine Learning Toolkit not found"
    echo ""
    echo "  Please install MLTK from Splunkbase:"
    echo "  https://splunkbase.splunk.com/app/2890"
    echo ""
    exit 1
fi

echo "✓ MLTK found"
echo ""

# Create MLTK models directory if it doesn't exist
mkdir -p "$MLTK_MODELS"

# Check if model files exist in TA
if [ ! -d "$TA_HOME/mlspl" ] || [ -z "$(ls -A $TA_HOME/mlspl 2>/dev/null | grep prompt_injection)" ]; then
    echo "⚠ Warning: Pre-trained model files not found in $TA_HOME/mlspl"
    echo ""
    echo "  This TA includes training examples but not a pre-trained model."
    echo "  You need to train the model using the included training data."
    echo ""
    echo "  Training Steps:"
    echo "  1. Run: | savedsearch \"GenAI - Prompt Injection Train Step 1 - Feature Engineering from Initial Dataset\""
    echo "  2. Run: | savedsearch \"GenAI - Prompt Injection Train Step 2 - Random Forest Model\""
    echo "  3. Run: | savedsearch \"GenAI - Prompt Injection Train Step 3 - Validate Model Performance\""
    echo ""
    echo "  See: README/ML Models/Prompt_Injection.md for detailed instructions"
    echo ""
    exit 0
fi

# Copy model files from TA to MLTK
echo "Copying model files to MLTK..."
cp -v "$TA_HOME/mlspl/prompt_injection_model"* "$MLTK_MODELS/" 2>/dev/null

# Set proper permissions
if [ "$(uname)" != "Darwin" ]; then
    # On Linux/Unix (not macOS), try to set splunk user ownership
    chown -R splunk:splunk "$MLTK_MODELS/prompt_injection_model"* 2>/dev/null || true
fi
chmod 644 "$MLTK_MODELS/prompt_injection_model"* 2>/dev/null

echo ""
echo "✓ Prompt Injection detection model loaded successfully"
echo ""
echo "  Model: prompt_injection_model"
echo "  Location: $MLTK_MODELS"
echo ""

# Verify model is accessible
if [ -f "$MLTK_MODELS/prompt_injection_model.json" ]; then
    echo "✓ Model verification successful"
    echo ""
    
    # Show model metadata if available
    if [ -f "$TA_HOME/lookups/prompt_injection_model_metadata.csv" ]; then
        echo "Model Metadata:"
        cat "$TA_HOME/lookups/prompt_injection_model_metadata.csv" | head -2
        echo ""
    fi
else
    echo "⚠ Warning: Model JSON not found - model may not be properly formatted"
    echo ""
fi

echo "Next steps:"
echo "1. Restart Splunk to register the model"
echo "2. Verify with: | inputlookup mlspl_models | search model_name=prompt_injection_model"
echo "3. Test scoring: See README/ML Models/Prompt_Injection.md"
echo ""

exit 0
