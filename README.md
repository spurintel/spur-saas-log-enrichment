# SaaS IP Anomaly Detector

Detect anonymous VPN tunnels and suspicious IP addresses in your Slack, Zoom, Teamtailor and Okta logs. Perfect for security teams conducting audits, compliance checks, or investigating potential account compromises.

## Features

- **Slack Integration** - Extract IP logs from workspace access logs
- **Zoom Integration** - Pull participant IP addresses from meetings
- **Okta Integration** - Pull sign-in IPs from the Okta System Log
- **Spur API** - Detect anonymous VPN tunnels/proxies
- **Filtered Alerts** - Only display critical VPN/proxy operators on command line
- **Full Reports** - Complete enrichment data saved to JSON reports
- **Zero PII Leakage** - Deduplicated user display, minimal CLI output

## Requirements

- Python 3.7+
- **Slack**: Paid plan (Standard/Plus/Enterprise Grid) with admin access
- **Zoom**: Business or Business+ plan (Pro does NOT work)
- **Okta**: API token with read access to the System Log (optional)
- **Spur API**: Token from https://spur.us/ (optional)

## Quick Start

### 1. Install

```bash
git clone https://github.com/spurintel/spur-saas-log-enrichment.git
cd spur-saas-log-enrichment
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

### Watchlist hits

Every VPN/proxy match in the report is shown in the CLI summary and counted as critical; the
watchlist (Spur's operator classification, or your `--ip-file`) is the place to curate what
counts. Operator names come from `tunnels.operator` in `reports/enrichment_report_YYYYMMDD.json`.

The `ip` column takes a single address or a CIDR range, and the most specific entry wins, so
a `/32` carve-out beats the `/16` it sits inside:

```csv
ip,operator
198.51.100.7,ASTRILL_VPN
192.0.2.0/24,SOME_HOSTING_RANGE
2001:db8::/32,SOME_V6_RANGE
```

Ranges matter more than they look: on a 4,000-user org an exact-address watchlist matched one
`(user, IP)` pair in 24,784 while Okta's own `isProxy` flag marked 270. A malformed row is
skipped and counted rather than taking the whole watchlist down.

### Teamtailor (applicant IPs)

The Teamtailor extractor reads the audit log (`/v1/audit-events`) and yields one entry per
(candidate, IP) for applicant actions. One API key per workspace, named by workspace:

```bash
echo "TEAMTAILOR_API_KEY_GLOBAL=..." >> .env   # workspace "global"
echo "TEAMTAILOR_API_KEY_DK=..." >> .env       # workspace "dk"
```

Every `TEAMTAILOR_API_KEY_<WORKSPACE>` variable is picked up automatically; `--no-teamtailor`
skips the source. The key needs read access to audit events and candidates (admin API key).

### Okta (sign-in IPs)

The Okta extractor reads the System Log (`/api/v1/logs`) and yields one entry per (user, IP).
Set the org — a custom domain works as well as the `*.okta.com` one — and an API token, which
is sent as `SSWS`:

```bash
echo "OKTA_ORG_URL=https://auth.example.com" >> .env
echo "OKTA_API_TOKEN=..." >> .env
```

Every event type in the window is pulled. Filtering server side saved only about 6s of a
32s pull on a 2000-user org while risking a blind spot — a sign-on denied by a network zone
surfaces as `policy.evaluate_sign_on` with a DENY outcome, not as a login event — so the
filter is opt-in. Narrow it with `OKTA_EVENT_TYPES` (comma separated) only if volume demands
it; `*` or unset means everything:

```bash
echo "OKTA_EVENT_TYPES=user.session.start,user.account.lock" >> .env
```

Each row keeps its `eventType` and `outcome`, so failed and denied attempts are
distinguishable downstream; the Slack alert marks a non-success outcome as *auth failed*.

Each row keeps Okta's own `securityContext.isProxy` verdict along with the country and AS
org, and the alert prints them, because "Astrill from China" is a different conversation
from the same operator at a known office range. Set `OKTA_ALERT_ON_PROXY=1` to alert on
`isProxy` directly rather than only on watchlist hits — off by default.

Before enabling it, note that the raw flag is mostly iCloud Private Relay: measured over 90
days on a 4,000-user org, 310 of the 316 `isProxy` addresses staff used were Akamai,
Cloudflare or Fastly, Apple's three relay egress partners. Those AS orgs are therefore
excluded by default, which turned 267 findings into 5 over the same period. Override the list
with `OKTA_PROXY_IGNORE_ASORG` (comma separated, matched as lowercase substrings) — a
sanctioned corporate VPN gateway belongs in it too:

```bash
echo "OKTA_PROXY_IGNORE_ASORG=akamai,cloudflare,fastly,proton ag" >> .env
```

Harvesting `isProxy` addresses into `data.csv` is the wrong move for the same reason: they are
addresses your own staff use, so they belong in a per-finding signal, not a blocklist.

isProxy findings are a lower-signal stream than a watchlist hit, so they post to their own
channel via `SLACK_WEBHOOK_URL_PROXY` rather than diluting the main one. If that variable is
unset while the flag is on, they are **held** — logged as a failure and left out of the state
file so they post on the next run once the webhook exists — rather than falling back to the
main channel.

Only `actor.type == "User"` rows are kept, so API-token and application actors do not appear
as findings. `--no-okta` skips the source. Okta identities are internal, so the cron's
`WHITELIST` applies to them as it does to Slack and Zoom.

### Slack alert cron (`slack_alert_cron.py`)

Runs the detector and posts only *new* findings to a Slack incoming webhook; alerted
`(user, IP, operator, source)` keys are kept in `.slack_alert_state.json`, so any cadence up
to 24h works and a finding alerts once. A lock file stops overlapping runs.

Each run scans back to `.slack_alert_watermark.json` — the start time of the last run that
finished with no failures — less a 15 minute overlap, capped at 24h. On a 30 minute cadence
that is a 45 minute window instead of a full day, which matters because Slack's access log is
rate limited and the page count, not the data, is what makes a run slow: 29 pages become 2.
A run with any failure leaves the watermark alone, so the next run re-covers its window, and
a long outage widens the window automatically until it reaches the ceiling. Delete the file
to force a full 24h scan.

Zoom is the exception: its Dashboard API takes `from`/`to` as whole dates, so a sub-day
window still lists the whole day's meetings.

```bash
*/30 * * * * cd /path/to/repo && venv/bin/python slack_alert_cron.py >> anomaly_cron.log 2>&1
./slack_alert_cron.py --dry-run                    # preview: no Slack post, no notes, no state writes
./slack_alert_cron.py reports/some_report.json     # replay a report instead of extracting
./note_report.py reports/some_report.json          # retry the profile notes of a posted report
```

Credentials are read from `.env` next to the script (real environment variables win):

| Variable | Purpose |
|---|---|
| `SLACK_WEBHOOK_URL` | Incoming webhook the alerts are posted to (required) |
| `TEAMTAILOR_API_KEY_<WORKSPACE>` | One key per workspace, as for the detector |
| `TEAMTAILOR_NOTE_USER_ID` | Author of profile notes (a user id in the workspace) |
| `TEAMTAILOR_NOTE_USER_EMAIL` | Or: look the author up by email in each workspace |
| `TEAMTAILOR_NOTE_USER_ID_<WORKSPACE>` | Per-workspace author override |
| `OKTA_ORG_URL` / `OKTA_API_TOKEN` | Okta System Log source (both, or neither) |
| `OKTA_EVENT_TYPES` | Narrow the pull to these event types (default: all) |
| `OKTA_ALERT_ON_PROXY` | `1` alerts on Okta's isProxy verdict as well as watchlist hits |
| `OKTA_PROXY_IGNORE_ASORG` | AS orgs whose isProxy verdict is ignored (default: the relay CDNs) |
| `SLACK_WEBHOOK_URL_PROXY` | Separate webhook for isProxy findings; unset holds them |

Teamtailor user ids are per workspace. The author is resolved in that order; when nothing
matches in a workspace, the note is posted as the recruiter (job owner) of the candidate's
application; such a note ends with an "automated message from team.blue Security" footer so
recruiters do not read it as their colleague's own words. Teamtailor findings get a security note on the profile once per candidate
(`.teamtailor_noted.json`); applications sent via an AI job tool get an info note only
(`.teamtailor_ai_noted.json`), no Slack alert; a bare-IP referrer is alerted as a finding.
A note whose text is already on the profile is never posted twice.

`user_logins.py [USER_ID] [DAYS]` prints one Slack user's recent logins with watchlist hits.

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

Credentials are read from `.env` next to the script, so the detector runs standalone with no
environment setup.

```bash
# Data Sources
--slack-token TOKEN          Slack API token (required for Slack)
--zoom-account-id ID         Zoom Account ID (required for Zoom)
--zoom-client-id ID          Zoom Client ID (required for Zoom)
--zoom-client-secret SECRET  Zoom Client Secret (required for Zoom)
--days N                     Days to analyze (default: 30, Slack limited to 7 on most plans)
--no-teamtailor              Skip Teamtailor even if TEAMTAILOR_API_KEY_<WORKSPACE> is set
--okta-org-url URL           Okta org or custom domain (env: OKTA_ORG_URL)
--okta-token TOKEN           Okta API token, sent as SSWS (env: OKTA_API_TOKEN)
--no-okta                    Skip Okta even if OKTA_ORG_URL and OKTA_API_TOKEN are set

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
│   ├── zoom_extractor.py     # Zoom API integration
│   ├── teamtailor_extractor.py  # Teamtailor ATS audit log (applicant IPs)
│   └── okta_extractor.py     # Okta System Log (sign-in IPs)
├── enrichment/
│   ├── spur_enrichment.py    # Spur API integration
│   └── file_enrichment.py    # File-based IP matching
├── slack_alert_cron.py       # Cron wrapper: new findings -> Slack, Teamtailor profile notes
├── note_report.py            # Retry profile notes for an already-posted report
├── user_logins.py            # One Slack user's recent logins, watchlist-flagged
├── user_check.py             # Per-user IP check
├── test_*.py                 # Offline unit tests (python -m unittest discover -p 'test_*.py')
├── AGENTS.md                 # Contributor/agent notes
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
- **Teamtailor API**: 50 requests per 10 seconds per token; 429s honour `X-Rate-Limit-Reset`
- **Okta API**: per-org System Log budget; 429s honour `X-Rate-Limit-Reset` (a Unix timestamp)

Every extractor also retries a stalled request (read timeout or dropped connection) on a
small separate budget, so one slow response costs a retry rather than the whole source.

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
