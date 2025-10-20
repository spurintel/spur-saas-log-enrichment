#!/bin/bash
# Example script showing how to run the anomaly detector
# Make sure to set your credentials first!

# Option 1: Using environment variables
# Load credentials from .env file
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Option 2: Set credentials directly (not recommended for production)
# export SLACK_API_TOKEN="xoxp-your-token"
# export ZOOM_ACCOUNT_ID="your-account-id"
# export ZOOM_CLIENT_ID="your-client-id"
# export ZOOM_CLIENT_SECRET="your-client-secret"
# export SPUR_API_TOKEN="your-spur-token"

# Create output directory
mkdir -p reports

# Run with Spur enrichment
echo "Running anomaly detection with Spur enrichment..."
python3 anomaly_detector.py \
  --slack-token "$SLACK_API_TOKEN" \
  --zoom-account-id "$ZOOM_ACCOUNT_ID" \
  --zoom-client-id "$ZOOM_CLIENT_ID" \
  --zoom-client-secret "$ZOOM_CLIENT_SECRET" \
  --enrichment spur \
  --spur-token "$SPUR_API_TOKEN" \
  --days 7 \
  --output "reports/anomaly_report_$(date +%Y%m%d).json"

echo "Done! Check the reports/ directory for results."

# Alternative: Run with file-based enrichment
# echo "Running anomaly detection with IP file..."
# python anomaly_detector.py \
#   --slack-token "$SLACK_API_TOKEN" \
#   --zoom-account-id "$ZOOM_ACCOUNT_ID" \
#   --zoom-client-id "$ZOOM_CLIENT_ID" \
#   --zoom-client-secret "$ZOOM_CLIENT_SECRET" \
#   --enrichment file \
#   --ip-file examples/suspicious_ips.txt \
#   --days 30 \
#   --output "reports/file_enrichment_$(date +%Y%m%d).json"

