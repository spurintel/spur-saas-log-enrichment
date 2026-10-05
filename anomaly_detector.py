#!/usr/bin/env python3
"""
SaaS IP Anomaly Detector
Extracts IP addresses from Slack and Zoom logs and detects anomalies using various enrichment methods.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from enrichment.spur_enrichment import SpurEnrichment
from enrichment.file_enrichment import FileEnrichment
from extractors.slack_extractor import SlackExtractor
from extractors.zoom_extractor import ZoomExtractor
from extractors.teamtailor_extractor import TeamtailorExtractor
from extractors.okta_extractor import OktaExtractor

TEAMTAILOR_KEY_PREFIX = 'TEAMTAILOR_API_KEY_'
OKTA_PROXY_TAG = 'OKTA_FLAGGED_PROXY'
# AS orgs whose isProxy verdict is not worth alerting on, matched as lowercase substrings.
# iCloud Private Relay egresses through Akamai, Cloudflare and Fastly: on this org they were
# 310 of the 316 isProxy addresses staff used in 90 days, every one a legitimate Apple user.
# Without this the flag is unusable. Override with OKTA_PROXY_IGNORE_ASORG (comma separated);
# a sanctioned corporate VPN gateway belongs here too.
DEFAULT_PROXY_IGNORE_ASORG = ('akamai', 'cloudflare', 'fastly')
REPO = os.path.dirname(os.path.abspath(__file__))


def load_env():
    """Load KEY=VALUE lines from .env (an `export ` prefix is tolerated); real environment variables win."""
    path = os.path.join(REPO, '.env')
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith('export '):
                line = line[len('export '):].lstrip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def teamtailor_keys() -> Dict[str, str]:
    """{workspace: api_key} from TEAMTAILOR_API_KEY_<WORKSPACE> env vars, e.g. TEAMTAILOR_API_KEY_DK."""
    return {k[len(TEAMTAILOR_KEY_PREFIX):].lower(): v
            for k, v in os.environ.items() if k.startswith(TEAMTAILOR_KEY_PREFIX) and v}


def okta_proxy_ignored() -> List[str]:
    """AS-org substrings whose isProxy verdict is ignored, from OKTA_PROXY_IGNORE_ASORG."""
    raw = (os.environ.get('OKTA_PROXY_IGNORE_ASORG') or '').strip()
    if not raw:
        return list(DEFAULT_PROXY_IGNORE_ASORG)
    return [t.strip().lower() for t in raw.split(',') if t.strip()]


def okta_event_types() -> List[str]:
    """Event types to pull, from OKTA_EVENT_TYPES (comma separated). Unset, or '*', means
    every type: the filter is an optimisation, not a safety net, so it is opt-in."""
    raw = (os.environ.get('OKTA_EVENT_TYPES') or '').strip()
    if not raw or raw == '*':
        return []
    return [t.strip() for t in raw.split(',') if t.strip()]


class AnomalyDetector:
    """Main class for detecting IP anomalies in SaaS logs."""

    def __init__(self):
        self.slack_data = []
        self.zoom_data = []
        self.teamtailor_data = []
        self.okta_data = []
        self.anomalies = []
        self._file_enricher = None

    def extract_teamtailor_data(self, api_key: str, account: str, days: int = 30) -> List[Dict]:
        """Extract applicant IPs from Teamtailor. Failures are logged, not raised, so Slack/Zoom still run."""
        print(f"📥 Extracting Teamtailor ({account}) data for the last {days} days...")
        try:
            data = TeamtailorExtractor(api_key, account).extract_ip_logs(days)
        except Exception as e:
            print(f"   ⚠️  Teamtailor ({account}) extraction failed: {e}", file=sys.stderr)
            return []
        self.teamtailor_data.extend(data)
        print(f"✅ Extracted {len(data)} Teamtailor ({account}) entries")
        return data

    def extract_okta_data(self, org_url: str, api_token: str, days: int = 30) -> List[Dict]:
        """Extract user IPs from the Okta System Log. Failures are logged, not raised, so the
        other sources still run (the cron wrapper turns the logged failure into a non-zero exit)."""
        print(f"\U0001f4e5 Extracting Okta data for the last {days} days...")
        try:
            data = OktaExtractor(org_url, api_token, okta_event_types()).extract_ip_logs(days)
        except Exception as e:
            print(f"   \u26a0\ufe0f  Okta extraction failed: {e}", file=sys.stderr)
            return []
        self.okta_data = data
        print(f"\u2705 Extracted {len(data)} Okta entries")
        return data

    def _all_data(self) -> List[Dict]:
        return ([{**e, 'source': 'slack'} for e in self.slack_data]
                + [{**e, 'source': 'zoom'} for e in self.zoom_data]
                + [{**e, 'source': 'teamtailor'} for e in self.teamtailor_data]
                + [{**e, 'source': 'okta'} for e in self.okta_data])

    def extract_slack_data(self, api_token: str, days: int = 30) -> List[Dict]:
        """Extract IP addresses and user data from Slack."""
        print(f"📥 Extracting Slack data for the last {days} days...")
        extractor = SlackExtractor(api_token)
        self.slack_data = extractor.extract_ip_logs(days)
        print(f"✅ Extracted {len(self.slack_data)} Slack entries")
        return self.slack_data

    def extract_zoom_data(self, account_id: str, client_id: str, client_secret: str, days: int = 30) -> List[Dict]:
        """Extract IP addresses and user data from Zoom."""
        print(f"📥 Extracting Zoom data for the last {days} days...")
        extractor = ZoomExtractor(account_id, client_id, client_secret)
        self.zoom_data = extractor.extract_ip_logs(days)
        print(f"✅ Extracted {len(self.zoom_data)} Zoom entries")
        return self.zoom_data

    def enrich_with_spur(self, api_token: str, reports_dir: str = "reports") -> List[Dict]:
        """Enrich IP data using Spur Context API to detect VPNs and tunnels."""
        print(f"\n🔍 Enriching data with Spur API...")
        enricher = SpurEnrichment(api_token, reports_dir)
        self.anomalies = enricher.enrich_and_detect(self._all_data())
        return self.anomalies

    def enrich_with_file(self, filepath: str) -> List[Dict]:
        """Enrich IP data using a file containing suspicious IP addresses."""
        print(f"🔍 Enriching data with IP list from {filepath}...")
        # Built once and reused: file enrichment reruns after every source finishes, and
        # reparsing a 60k-row watchlist ~40 times costs more CPU than the extraction does.
        # Reusing it also keeps the per-address lookup cache warm across sources.
        if self._file_enricher is None or self._file_enricher.filepath != filepath:
            self._file_enricher = FileEnrichment(filepath)
        enricher = self._file_enricher
        entries = self._all_data()
        self.anomalies = enricher.enrich_and_detect(entries)
        print(
            f"⚠️  Found {len(self.anomalies)} anomalies (matched suspicious IPs)")
        self.anomalies += self._okta_proxy_anomalies(entries, enricher)
        return self.anomalies

    @staticmethod
    def _okta_proxy_anomalies(entries: List[Dict], enricher) -> List[Dict]:
        """Okta's own isProxy verdict, as findings. Opt in with OKTA_ALERT_ON_PROXY=1.

        Off by default because enabling it on an org that routes a business unit through a
        shared VPN gateway produces a burst. It is worth having: on this org the address
        watchlist matched a single (user, IP) pair in 24,784 while isProxy marked 270, so
        the vendor sees anonymising infrastructure that a list of literal addresses cannot.
        Entries already flagged by the watchlist are left alone rather than duplicated."""
        if (os.environ.get('OKTA_ALERT_ON_PROXY') or '').strip().lower() not in ('1', 'true', 'yes'):
            return []
        ignored = okta_proxy_ignored()
        found = []
        for entry in entries:
            if entry.get('source') != 'okta' or not entry.get('is_proxy'):
                continue
            as_org = (entry.get('as_org') or '').lower()
            if any(skip in as_org for skip in ignored):
                continue  # consumer relay or a sanctioned gateway, not a finding
            if entry.get('ip') and enricher.lookup(entry['ip']):
                continue  # already reported as a watchlist hit
            found.append({
                **entry,
                'vpn_operator': entry.get('as_org') or OKTA_PROXY_TAG,
                'enrichment': {'ip': entry.get('ip'), 'matched': True,
                               'source': 'okta_is_proxy', 'operator': OKTA_PROXY_TAG},
                'anomaly_type': 'Anonymising infrastructure (Okta isProxy)',
                'risk_score': 60,  # a vendor heuristic, not a curated watchlist hit
            })
        print(f"⚠️  Found {len(found)} Okta isProxy anomalies")
        return found

    def generate_report(self, output_file: str = None):
        """Generate a detailed report of findings."""
        report = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'summary': {
                'slack_entries': len(self.slack_data),
                'zoom_entries': len(self.zoom_data),
                'teamtailor_entries': len(self.teamtailor_data),
                'okta_entries': len(self.okta_data),
                'total_anomalies': len(self.anomalies)
            },
            'anomalies': self.anomalies
        }

        if output_file:
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n✓ Anomaly report saved to {output_file}")

        # Every watchlist hit is critical
        critical_anomalies = list(self.anomalies)

        # Count and display critical alerts with deduplication
        displayed_count = 0
        displayed_alerts = []

        if critical_anomalies:
            # Track users we've already shown to avoid duplicates
            slack_users_shown = set()
            zoom_users_shown = set()

            for anomaly in critical_anomalies:
                user = anomaly.get('user') or anomaly.get('email', 'Unknown')
                vpn_operator = anomaly.get('vpn_operator', 'Unknown')
                source = anomaly.get('source', 'Unknown')

                # For Slack, skip if we've already shown this user
                if source == 'slack':
                    user_key = anomaly.get('email', user)
                    if user_key in slack_users_shown:
                        continue
                    slack_users_shown.add(user_key)

                # For Zoom, skip if we've already shown this user+meeting combination
                if source == 'zoom':
                    zoom_key = (anomaly.get('email', user),
                                anomaly.get('meeting_topic', ''))
                    if zoom_key in zoom_users_shown:
                        continue
                    zoom_users_shown.add(zoom_key)

                # This alert will be displayed, so add it to our list
                displayed_alerts.append(anomaly)
                displayed_count += 1

        # Print minimal summary to console (no PII unless critical)
        print(f"\n{'='*60}")
        print(f"DETECTION SUMMARY")
        print(f"{'='*60}")
        print(
            f"Entries analyzed: {report['summary']['slack_entries'] + report['summary']['zoom_entries'] + report['summary']['teamtailor_entries'] + report['summary']['okta_entries']}")
        print(
            f"Anonymous VPN detections: {report['summary']['total_anomalies']}")
        print(f"Critical alerts (displayed): {displayed_count}")

        if displayed_alerts:
            print(f"\n{'='*60}")
            print(f"🚨 CRITICAL VPN/PROXY DETECTIONS")
            print(f"{'='*60}")

            for anomaly in displayed_alerts:
                user = anomaly.get('user') or anomaly.get('email', 'Unknown')
                vpn_operator = anomaly.get('vpn_operator', 'Unknown')
                source = anomaly.get('source', 'Unknown')

                # Format operator name (e.g., MULLVAD_VPN -> Mullvad VPN)
                vpn_name = vpn_operator.replace('_', ' ').title()

                # For Zoom, include meeting name
                if source == 'zoom' and anomaly.get('meeting_topic'):
                    meeting_name = anomaly.get('meeting_topic')
                    print(f"User: {user}")
                    print(f"  VPN/Proxy: {vpn_name}")
                    print(f"  Meeting: {meeting_name}")
                    print(f"  Source: Zoom")
                    print()
                else:
                    print(f"User: {user}")
                    print(f"  VPN/Proxy: {vpn_name}")
                    print(f"  Source: {source.title()}")
                    print()
        else:
            print("\n✓ No critical VPN/proxy detections")


        print(f"{'='*60}\n")
        return report


def main():
    # Before the parser: every credential argument defaults from os.environ, so the .env
    # values have to be in place by the time add_argument runs. Without this the detector
    # only worked as a subprocess of slack_alert_cron.py, which loaded .env on its behalf.
    load_env()
    parser = argparse.ArgumentParser(
        description='Detect IP anomalies in Slack, Zoom, Teamtailor and Okta logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract from Slack and Zoom, enrich with Spur API
  python anomaly_detector.py --slack-token xoxp-xxx --zoom-account-id xxx \\
    --zoom-client-id xxx --zoom-client-secret xxx \\
    --enrichment spur --spur-token xxx \\
    --output report.json

  # Extract from Slack only, use IP file for detection
  python anomaly_detector.py --slack-token xoxp-xxx \\
    --enrichment file --ip-file suspicious_ips.txt \\
    --output report.json
        """
    )

    # Data extraction arguments (fall back to env vars so secrets stay out of the process list)
    parser.add_argument('--slack-token', default=os.environ.get('SLACK_API_TOKEN'),
                        help='Slack API token (env: SLACK_API_TOKEN)')
    parser.add_argument('--zoom-account-id', default=os.environ.get('ZOOM_ACCOUNT_ID'),
                        help='Zoom Account ID (env: ZOOM_ACCOUNT_ID)')
    parser.add_argument('--zoom-client-id', default=os.environ.get('ZOOM_CLIENT_ID'),
                        help='Zoom Client ID (env: ZOOM_CLIENT_ID)')
    parser.add_argument('--zoom-client-secret', default=os.environ.get('ZOOM_CLIENT_SECRET'),
                        help='Zoom Client Secret (env: ZOOM_CLIENT_SECRET)')
    parser.add_argument('--no-teamtailor', action='store_true',
                        help='Skip Teamtailor even if TEAMTAILOR_API_KEY_<WORKSPACE> env vars are set')
    parser.add_argument('--okta-org-url', default=os.environ.get('OKTA_ORG_URL'),
                        help='Okta org or custom domain, e.g. https://auth.example.com (env: OKTA_ORG_URL)')
    parser.add_argument('--okta-token', default=os.environ.get('OKTA_API_TOKEN'),
                        help='Okta API token, used as SSWS (env: OKTA_API_TOKEN)')
    parser.add_argument('--no-okta', action='store_true',
                        help='Skip Okta even if OKTA_ORG_URL and OKTA_API_TOKEN are set')
    parser.add_argument('--days', type=int, default=30,
                        help='Number of days to analyze (default: 30)')
    parser.add_argument('--hours', type=float,
                        help='Window in hours, overriding --days; fractions allowed. The cron '
                             'wrapper passes the gap back to its last clean run.')

    # Enrichment arguments
    parser.add_argument('--enrichment', choices=['spur', 'file'], required=True,
                        help='Enrichment method: spur (API) or file (IP list)')
    parser.add_argument(
        '--spur-token', default=os.environ.get('SPUR_API_TOKEN'),
        help='Spur Context API token (required for spur enrichment, env: SPUR_API_TOKEN)')
    parser.add_argument(
        '--ip-file', help='Path to file with suspicious IPs (required for file enrichment)')

    # Output arguments
    parser.add_argument(
        '--output', help='Output file for JSON report (optional, defaults to reports/anomaly_report_YYYYMMDD.json)')
    parser.add_argument('--reports-dir', default='reports',
                        help='Directory for reports (default: reports)')

    args = parser.parse_args()
    if args.hours is not None and args.hours <= 0:
        parser.error("--hours must be positive")
    # Extractors take a day count; a float is fine, they all build a timedelta from it.
    days = args.hours / 24 if args.hours is not None else args.days

    # Validate arguments
    tt_keys = {} if args.no_teamtailor else teamtailor_keys()
    use_okta = bool(args.okta_org_url and args.okta_token) and not args.no_okta
    if not (args.slack_token or args.zoom_account_id or tt_keys or use_okta):
        parser.error(
            "At least one data source (--slack-token, --zoom-account-id, --okta-org-url with "
            "--okta-token, or TEAMTAILOR_API_KEY_<WORKSPACE>) must be provided")

    if bool(args.okta_org_url) != bool(args.okta_token) and not args.no_okta:
        parser.error("--okta-org-url and --okta-token must be given together")

    if args.zoom_account_id and not (args.zoom_client_id and args.zoom_client_secret):
        parser.error(
            "--zoom-client-id and --zoom-client-secret are required when using --zoom-account-id")

    if args.enrichment == 'spur' and not args.spur_token:
        parser.error("--spur-token is required when using spur enrichment")

    if args.enrichment == 'file' and not args.ip_file:
        parser.error("--ip-file is required when using file enrichment")

    # Run detection
    detector = AnomalyDetector()

    # Default report filename if not specified
    output_file = args.output
    if not output_file:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d')
        output_file = f"{args.reports_dir}/anomaly_report_{timestamp}.json"

    try:
        # Extract data in parallel
        with ThreadPoolExecutor() as executor:
            futures = []

            if args.slack_token:
                futures.append(
                    executor.submit(
                        detector.extract_slack_data,
                        args.slack_token,
                        days
                    )
                )

            if args.zoom_account_id:
                futures.append(
                    executor.submit(
                        detector.extract_zoom_data,
                        args.zoom_account_id,
                        args.zoom_client_id,
                        args.zoom_client_secret,
                        days
                    )
                )

            for account, key in tt_keys.items():
                futures.append(executor.submit(
                    detector.extract_teamtailor_data, key, account, days))

            if use_okta:
                futures.append(executor.submit(
                    detector.extract_okta_data, args.okta_org_url, args.okta_token, days))

            # File enrichment is a cheap local lookup, so write an interim
            # report as each source finishes instead of waiting for both.
            done = 0
            for future in as_completed(futures):
                future.result()
                done += 1
                if args.enrichment == 'file':
                    if done < len(futures):
                        print(f"\n📝 Writing interim report ({done}/{len(futures)} sources done)...")
                    detector.enrich_with_file(args.ip_file)
                    detector.generate_report(output_file)

        # Spur enrichment costs API calls per IP — run it once, after all sources
        if args.enrichment == 'spur':
            detector.enrich_with_spur(args.spur_token, args.reports_dir)
            detector.generate_report(output_file)

    except Exception as e:
        print(f"❌ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
