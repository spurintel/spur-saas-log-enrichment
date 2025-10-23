# SaaS IP Anomaly Detector

Detect anonymous VPN tunnels and suspicious IP addresses in your Slack and Zoom logs. Perfect for security teams conducting audits, compliance checks, or investigating potential account compromises.

## Features

- **Slack Integration** - Extract IP logs from workspace access logs
- **Zoom Integration** - Pull participant IP addresses from meetings
- **Spur API** - Detect anonymous VPN tunnels/proxies
- **Filtered Alerts** - Only display critical VPN/proxy operators on command line
- **Full Reports** - Complete enrichment data saved to JSON reports
- **Zero PII Leakage** - Deduplicated user display, minimal CLI output

## Requirements

- Python 3.7+
- **Slack**: Paid plan (Standard/Plus/Enterprise Grid) with admin access
- **Zoom**: Business or Business+ plan (Pro does NOT work)
- **Spur API**: Token from https://spur.us/ (optional)

## Quick Start

### 1. Install

```bash
git clone https://github.com/yourusername/saas-enrichment.git
cd saas-enrichment
pip install -r requirements.txt
```

### 2. Get Credentials

#### Slack
1. Go to https://api.slack.com/apps → Create New App
2. Add **User Token Scopes**:
   - `admin` (or `admin.teams:read` for Enterprise Grid)
   - `users:read`
   - `users:read.email`
3. Install to workspace (must be Workspace Admin)
4. Copy User OAuth Token (starts with `xoxp-`)

#### Zoom
1. Go to https://marketplace.zoom.us/ → Develop → Build App → Server-to-Server OAuth
2. Add scope: `dashboard:read:list_meeting_participants:admin`, `dashboard:read:list_meetings:admin`, and `meeting:read:list_past_participants:admin`
3. Copy Account ID, Client ID, and Client Secret
4. Activate the app

#### Spur API
1. Sign up at https://spur.us/
2. Copy your API token

### 3. Test Credentials

```bash
python test_credentials.py \
  --slack-token xoxp-YOUR-TOKEN \
  --zoom-account-id YOUR-ACCOUNT-ID \
  --zoom-client-id YOUR-CLIENT-ID \
  --zoom-client-secret YOUR-SECRET \
  --spur-token YOUR-SPUR-TOKEN
```

### 4. Run Detection

```bash
python anomaly_detector.py \
  --slack-token xoxp-YOUR-TOKEN \
  --zoom-account-id YOUR-ACCOUNT-ID \
  --zoom-client-id YOUR-CLIENT-ID \
  --zoom-client-secret YOUR-SECRET \
  --enrichment spur \
  --spur-token YOUR-SPUR-TOKEN \
  --days 7
```

Or use environment variables:

```bash
# Create .env file
echo "SLACK_API_TOKEN=xoxp-your-token" >> .env
echo "SPUR_API_TOKEN=your-spur-token" >> .env

# Run with env vars
source .env
python anomaly_detector.py \
  --slack-token "$SLACK_API_TOKEN" \
  --enrichment spur \
  --spur-token "$SPUR_API_TOKEN" \
  --days 7
```

## Configuration

### Critical VPN/Proxy Operators

By default, only these operators trigger command-line alerts:
- **ASTRILL_VPN**
- **PROXYSOCKS5_PROXY**

All detections are saved to reports, but only critical operators appear in CLI output. This minimizes PII exposure during webinars or live demos.

**To customize**, edit `anomaly_detector.py`:

```python
class AnomalyDetector:
    CRITICAL_OPERATORS = [
        'ASTRILL_VPN',
        'PROXYSOCKS5_PROXY',
        'NORDVPN',           # Add more
        'MULLVAD_VPN',       # as needed
    ]
```

**Common operator names**:
- VPNs: `NORDVPN`, `EXPRESSVPN`, `MULLVAD_VPN`, `PROTONVPN`, `SURFSHARK`
- Privacy: `TOR_EXIT_NODE`, `SHADOWSOCKS`, `LANTERN`
- Proxies: `LUMINATI`, `SMARTPROXY`, `OXYLABS`, `BRIGHTDATA`

Find operator names in your reports at `reports/enrichment_report_YYYYMMDD.json` under the `tunnels.operator` field.

## Output

### Command Line (Critical Alerts Only)

```
============================================================
DETECTION SUMMARY
============================================================
Entries analyzed: 225
Anonymous VPN detections: 5
Critical alerts (displayed): 2

============================================================
🚨 CRITICAL VPN/PROXY DETECTIONS
============================================================
User: john.doe
  VPN/Proxy: Astrill Vpn
  Source: Slack

User: jane.smith
  VPN/Proxy: Proxysocks5 Proxy
  Meeting: Q4 Financial Review
  Source: Zoom

Note: 3 other VPN detections saved to report (not critical)
============================================================
```

### Reports Directory

All data is saved to `reports/`:

- `anomaly_report_YYYYMMDD.json` - Summary with all anomalies detected
- `enrichment_report_YYYYMMDD.json` - Full Spur API enrichment data for all IPs

## Command Line Options

```bash
# Data Sources
--slack-token TOKEN          Slack API token (required for Slack)
--zoom-account-id ID         Zoom Account ID (required for Zoom)
--zoom-client-id ID          Zoom Client ID (required for Zoom)
--zoom-client-secret SECRET  Zoom Client Secret (required for Zoom)
--days N                     Days to analyze (default: 30, Slack limited to 7 on most plans)

# Enrichment Method (required)
--enrichment spur            Use Spur API for VPN/proxy detection
--enrichment file            Use IP file for detection
--spur-token TOKEN           Spur API token (if using spur)
--ip-file PATH               Path to IP list file (if using file)

# Output
--output FILE                Output JSON file (default: reports/anomaly_report_YYYYMMDD.json)
--reports-dir DIR            Reports directory (default: reports)
```

## Architecture

```
saas-enrichment/
├── anomaly_detector.py       # Main CLI tool
├── extractors/
│   ├── slack_extractor.py    # Slack API integration
│   └── zoom_extractor.py     # Zoom API integration
├── enrichment/
│   ├── spur_enrichment.py    # Spur API integration
│   └── file_enrichment.py    # File-based IP matching
├── reports/                  # Output directory (auto-created)
├── examples/                 # Sample outputs
└── test_credentials.py       # Credential testing tool
```

## Security Best Practices

**Never commit tokens to version control!**

```bash
# Use .env file (add to .gitignore)
echo "SLACK_API_TOKEN=xoxp-xxx" >> .env
echo "ZOOM_CLIENT_SECRET=xxx" >> .env
echo "SPUR_API_TOKEN=xxx" >> .env

# Or use environment variables
export SLACK_API_TOKEN="xoxp-xxx"
```

## Troubleshooting

### Slack: "Missing admin scope"
- Ensure you're a Workspace Admin
- Add `admin` scope under **User Token Scopes** (not Bot Token Scopes)
- Reinstall the app to your workspace

### Slack: Users show as "Unknown"
- Add `users:read` and `users:read.email` scopes
- Reinstall the app

### Zoom: No IP addresses returned
- Requires Business or Business+ plan (Pro does NOT work)
- Check Dashboard API is enabled in your account
- Verify `dashboard_meetings:read:admin` scope is added

### Zoom: "Access denied to Dashboard API"
- Your plan doesn't support Dashboard API (upgrade to Business+)
- Or Dashboard feature is not enabled (contact Zoom support)

## API Rate Limits

- **Spur API**: 100 requests/second
- **Slack API**: ~1 request/second (built-in rate limiting)
- **Zoom API**: ~3 requests/second (built-in rate limiting)

## Performance Optimization

The Spur enrichment uses **parallel API requests** for high performance:
- **Default**: 50 concurrent workers
- Typical speed: ~50 IPs/second (depending on network and API response time)
- Adjustable via the `max_workers` parameter in code:

```python
from enrichment.spur_enrichment import SpurEnrichment

# Use more workers for faster processing (if your API plan allows)
enricher = SpurEnrichment(api_token, reports_dir="reports", max_workers=100)

# Or fewer workers for rate-limited plans
enricher = SpurEnrichment(api_token, reports_dir="reports", max_workers=25)
```

**Note**: The Spur API supports high concurrency. If you have a large number of IPs to check, increasing `max_workers` to 100+ can significantly speed up processing.

## Plan Limitations

| Service | Free/Pro | Standard/Plus | Business/Enterprise |
|---------|----------|---------------|---------------------|
| **Slack** | ❌ No access logs | ✅ 7 days | ✅ 7-30+ days |
| **Zoom** | ❌ No IP data | ❌ No IP data | ✅ Full access |

## Examples

### Slack Only
```bash
python anomaly_detector.py \
  --slack-token "$SLACK_API_TOKEN" \
  --enrichment spur \
  --spur-token "$SPUR_API_TOKEN" \
  --days 7
```

### Zoom Only
```bash
python anomaly_detector.py \
  --zoom-account-id "$ZOOM_ACCOUNT_ID" \
  --zoom-client-id "$ZOOM_CLIENT_ID" \
  --zoom-client-secret "$ZOOM_CLIENT_SECRET" \
  --enrichment spur \
  --spur-token "$SPUR_API_TOKEN" \
  --days 7
```

### Both Slack and Zoom
```bash
python anomaly_detector.py \
  --slack-token "$SLACK_API_TOKEN" \
  --zoom-account-id "$ZOOM_ACCOUNT_ID" \
  --zoom-client-id "$ZOOM_CLIENT_ID" \
  --zoom-client-secret "$ZOOM_CLIENT_SECRET" \
  --enrichment spur \
  --spur-token "$SPUR_API_TOKEN" \
  --days 7
```

### Using IP File Instead of Spur
```bash
python anomaly_detector.py \
  --slack-token "$SLACK_API_TOKEN" \
  --enrichment file \
  --ip-file examples/suspicious_ips.txt \
  --days 7
```

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## Support

For issues, questions, or feature requests, please open a GitHub issue.
