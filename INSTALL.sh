#!/bin/bash
#
# Quick install script for TA-gen_ai_cim
#

# Find Splunk installation
if [ -d "/Applications/Splunk" ]; then
    SPLUNK_HOME="/Applications/Splunk"
elif [ -d "/opt/splunk" ]; then
    SPLUNK_HOME="/opt/splunk"
elif [ -n "$SPLUNK_HOME" ]; then
    echo "Using SPLUNK_HOME from environment: $SPLUNK_HOME"
else
    echo "ERROR: Cannot find Splunk installation"
    echo "Please set SPLUNK_HOME environment variable or specify path"
    exit 1
fi

echo "Found Splunk at: $SPLUNK_HOME"
echo "Deploying TA-gen_ai_cim..."

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "TA location: $SCRIPT_DIR"

# Check if TA already exists
if [ -d "$SPLUNK_HOME/etc/apps/TA-gen_ai_cim" ]; then
    echo "WARNING: TA-gen_ai_cim already exists. Removing old version..."
    rm -rf "$SPLUNK_HOME/etc/apps/TA-gen_ai_cim"
fi

# Copy TA to Splunk apps directory
echo "Copying TA to $SPLUNK_HOME/etc/apps/..."
cp -r "$SCRIPT_DIR" "$SPLUNK_HOME/etc/apps/"

# Verify installation
if [ -f "$SPLUNK_HOME/etc/apps/TA-gen_ai_cim/default/props.conf" ]; then
    echo "✅ TA deployed successfully!"
    echo ""
    echo "Files installed:"
    ls -la "$SPLUNK_HOME/etc/apps/TA-gen_ai_cim/default/"
    echo ""
    echo "Next step: Restart Splunk to load the TA"
    echo "Run: $SPLUNK_HOME/bin/splunk restart"
else
    echo "❌ ERROR: TA deployment failed"
    exit 1
fi
