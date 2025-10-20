#!/usr/bin/env python3
"""
SaaS IP Anomaly Detector
Extracts IP addresses from Slack and Zoom logs and detects anomalies using various enrichment methods.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Dict, List, Set
from enrichment.spur_enrichment import SpurEnrichment
from enrichment.file_enrichment import FileEnrichment
from extractors.slack_extractor import SlackExtractor
from extractors.zoom_extractor import ZoomExtractor


class AnomalyDetector:
    """Main class for detecting IP anomalies in SaaS logs."""
    
    # Critical VPN/Proxy operators to alert on in CLI output
    # Edit this list to add/remove operators that require immediate attention
    CRITICAL_OPERATORS = ['ASTRILL_VPN', 'PROXYSOCKS5_PROXY']
    
    def __init__(self):
        self.slack_data = []
        self.zoom_data = []
        self.anomalies = []
    
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
        
        all_data = [
            {**entry, 'source': 'slack'} for entry in self.slack_data
        ] + [
            {**entry, 'source': 'zoom'} for entry in self.zoom_data
        ]
        
        self.anomalies = enricher.enrich_and_detect(all_data)
        return self.anomalies
    
    def enrich_with_file(self, filepath: str) -> List[Dict]:
        """Enrich IP data using a file containing suspicious IP addresses."""
        print(f"🔍 Enriching data with IP list from {filepath}...")
        enricher = FileEnrichment(filepath)
        
        all_data = [
            {**entry, 'source': 'slack'} for entry in self.slack_data
        ] + [
            {**entry, 'source': 'zoom'} for entry in self.zoom_data
        ]
        
        self.anomalies = enricher.enrich_and_detect(all_data)
        print(f"⚠️  Found {len(self.anomalies)} anomalies (matched suspicious IPs)")
        return self.anomalies
    
    def generate_report(self, output_file: str = None):
        """Generate a detailed report of findings."""
        report = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'summary': {
                'slack_entries': len(self.slack_data),
                'zoom_entries': len(self.zoom_data),
                'total_anomalies': len(self.anomalies)
            },
            'anomalies': self.anomalies
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n✓ Anomaly report saved to {output_file}")
        
        # Filter anomalies for critical operators only (for CLI display)
        critical_anomalies = [
            a for a in self.anomalies 
            if a.get('vpn_operator') in self.CRITICAL_OPERATORS
        ]
        
        # Print minimal summary to console (no PII unless critical)
        print(f"\n{'='*60}")
        print(f"DETECTION SUMMARY")
        print(f"{'='*60}")
        print(f"Entries analyzed: {report['summary']['slack_entries'] + report['summary']['zoom_entries']}")
        print(f"Anonymous VPN detections: {report['summary']['total_anomalies']}")
        print(f"Critical alerts (displayed): {len(critical_anomalies)}")
        
        if critical_anomalies:
            print(f"\n{'='*60}")
            print(f"🚨 CRITICAL VPN/PROXY DETECTIONS")
            print(f"{'='*60}")
            
            # Track Slack users we've already shown to avoid duplicates
            slack_users_shown = set()
            
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
        
        if report['summary']['total_anomalies'] > len(critical_anomalies):
            print(f"Note: {report['summary']['total_anomalies'] - len(critical_anomalies)} other VPN detections saved to report (not critical)")
        
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
    
    # Data extraction arguments
    parser.add_argument('--slack-token', help='Slack API token')
    parser.add_argument('--zoom-account-id', help='Zoom Account ID')
    parser.add_argument('--zoom-client-id', help='Zoom Client ID')
    parser.add_argument('--zoom-client-secret', help='Zoom Client Secret')
    parser.add_argument('--days', type=int, default=30, help='Number of days to analyze (default: 30)')
    
    # Enrichment arguments
    parser.add_argument('--enrichment', choices=['spur', 'file'], required=True,
                       help='Enrichment method: spur (API) or file (IP list)')
    parser.add_argument('--spur-token', help='Spur Context API token (required for spur enrichment)')
    parser.add_argument('--ip-file', help='Path to file with suspicious IPs (required for file enrichment)')
    
    # Output arguments
    parser.add_argument('--output', help='Output file for JSON report (optional, defaults to reports/anomaly_report_YYYYMMDD.json)')
    parser.add_argument('--reports-dir', default='reports', help='Directory for reports (default: reports)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.slack_token and not args.zoom_account_id:
        parser.error("At least one data source (--slack-token or --zoom-account-id) must be provided")
    
    if args.zoom_account_id and not (args.zoom_client_id and args.zoom_client_secret):
        parser.error("--zoom-client-id and --zoom-client-secret are required when using --zoom-account-id")
    
    if args.enrichment == 'spur' and not args.spur_token:
        parser.error("--spur-token is required when using spur enrichment")
    
    if args.enrichment == 'file' and not args.ip_file:
        parser.error("--ip-file is required when using file enrichment")
    
    # Run detection
    detector = AnomalyDetector()
    
    try:
        # Extract data
        if args.slack_token:
            detector.extract_slack_data(args.slack_token, args.days)
        
        if args.zoom_account_id:
            detector.extract_zoom_data(
                args.zoom_account_id,
                args.zoom_client_id,
                args.zoom_client_secret,
                args.days
            )
        
        # Enrich data
        if args.enrichment == 'spur':
            detector.enrich_with_spur(args.spur_token, args.reports_dir)
        elif args.enrichment == 'file':
            detector.enrich_with_file(args.ip_file)
        
        # Generate report with default filename if not specified
        output_file = args.output
        if not output_file:
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d')
            output_file = f"{args.reports_dir}/anomaly_report_{timestamp}.json"
        
        detector.generate_report(output_file)
        
    except Exception as e:
        print(f"❌ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

