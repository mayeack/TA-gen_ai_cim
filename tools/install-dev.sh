#!/bin/bash
#
# install-dev.sh - Developer-only helper to copy TA-gen_ai_cim into a local
# Splunk Enterprise install for testing.
#
# This is NOT shipped in the Splunkbase / Splunk Cloud package
# (excluded by ../package.sh). For production deployments use Splunk
# Deployment Server, Splunk Cloud self-service install, or Splunkbase.
#

set -euo pipefail

if [ -d "/Applications/Splunk" ]; then
    SPLUNK_HOME="/Applications/Splunk"
elif [ -d "/opt/splunk" ]; then
    SPLUNK_HOME="/opt/splunk"
elif [ -n "${SPLUNK_HOME:-}" ]; then
    echo "Using SPLUNK_HOME from environment: $SPLUNK_HOME"
else
    echo "ERROR: Cannot find Splunk installation"
    echo "Set SPLUNK_HOME environment variable or install Splunk to a standard path"
    exit 1
fi

echo "Found Splunk at: $SPLUNK_HOME"

# Resolve the TA root (parent of this tools/ dir)
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TA_ROOT="$(dirname "$TOOLS_DIR")"
TA_NAME="$(basename "$TA_ROOT")"
echo "TA location: $TA_ROOT"

if [ -d "$SPLUNK_HOME/etc/apps/$TA_NAME" ]; then
    echo "WARNING: $TA_NAME already exists at $SPLUNK_HOME/etc/apps/. Removing old version."
    rm -rf "$SPLUNK_HOME/etc/apps/$TA_NAME"
fi

echo "Copying $TA_NAME to $SPLUNK_HOME/etc/apps/..."
cp -r "$TA_ROOT" "$SPLUNK_HOME/etc/apps/"

if [ -f "$SPLUNK_HOME/etc/apps/$TA_NAME/default/props.conf" ]; then
    echo "TA deployed successfully."
    echo
    echo "Next step: restart Splunk to load the TA"
    echo "  $SPLUNK_HOME/bin/splunk restart"
else
    echo "ERROR: TA deployment failed"
    exit 1
fi
