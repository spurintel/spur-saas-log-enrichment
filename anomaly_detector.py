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

TEAMTAILOR_KEY_PREFIX = 'TEAMTAILOR_API_KEY_'


def teamtailor_keys() -> Dict[str, str]:
    """{workspace: api_key} from TEAMTAILOR_API_KEY_<WORKSPACE> env vars, e.g. TEAMTAILOR_API_KEY_DK."""
    return {k[len(TEAMTAILOR_KEY_PREFIX):].lower(): v
            for k, v in os.environ.items() if k.startswith(TEAMTAILOR_KEY_PREFIX) and v}


class AnomalyDetector:
    """Main class for detecting IP anomalies in SaaS logs."""

    def __init__(self):
        self.slack_data = []
        self.zoom_data = []
        self.teamtailor_data = []
        self.anomalies = []

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

    def _all_data(self) -> List[Dict]:
        return ([{**e, 'source': 'slack'} for e in self.slack_data]
                + [{**e, 'source': 'zoom'} for e in self.zoom_data]
                + [{**e, 'source': 'teamtailor'} for e in self.teamtailor_data])

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
        enricher = FileEnrichment(filepath)
        self.anomalies = enricher.enrich_and_detect(self._all_data())
        print(
            f"⚠️  Found {len(self.anomalies)} anomalies (matched suspicious IPs)")
        return self.anomalies

    def generate_report(self, output_file: str = None):
        """Generate a detailed report of findings."""
        report = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'summary': {
                'slack_entries': len(self.slack_data),
                'zoom_entries': len(self.zoom_data),
                'teamtailor_entries': len(self.teamtailor_data),
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
            f"Entries analyzed: {report['summary']['slack_entries'] + report['summary']['zoom_entries'] + report['summary']['teamtailor_entries']}")
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
    parser = argparse.ArgumentParser(
        description='Detect IP anomalies in Slack and Zoom logs',
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
    parser.add_argument('--days', type=int, default=30,
                        help='Number of days to analyze (default: 30)')

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

    # Validate arguments
    tt_keys = {} if args.no_teamtailor else teamtailor_keys()
    if not (args.slack_token or args.zoom_account_id or tt_keys):
        parser.error(
            "At least one data source (--slack-token, --zoom-account-id or TEAMTAILOR_API_KEY_<WORKSPACE>) must be provided")

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
                        args.days
                    )
                )

            if args.zoom_account_id:
                futures.append(
                    executor.submit(
                        detector.extract_zoom_data,
                        args.zoom_account_id,
                        args.zoom_client_id,
                        args.zoom_client_secret,
                        args.days
                    )
                )

            for account, key in tt_keys.items():
                futures.append(executor.submit(
                    detector.extract_teamtailor_data, key, account, args.days))

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
