"""Spur Context API enrichment for detecting VPNs, proxies, and tunnels."""

import json
import os
from datetime import datetime, timezone
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests


class SpurEnrichment:
    """Enrich IP addresses using Spur Context API to detect anonymous infrastructure."""
    
    BASE_URL = "https://api.spur.us/v2/context"
    
    def __init__(self, api_token: str, reports_dir: str = "reports", max_workers: int = 50):
        """
        Initialize Spur enrichment.
        
        Args:
            api_token: Spur Context API token
            reports_dir: Directory to store reports (default: "reports")
            max_workers: Maximum concurrent API requests (default: 50)
        """
        self.api_token = api_token
        self.headers = {
            'Token': api_token,
            'Content-Type': 'application/json'
        }
        self.cache = {}  # Cache results to avoid duplicate API calls
        self.reports_dir = reports_dir
        self.max_workers = max_workers
        
        # Create reports directory if it doesn't exist
        os.makedirs(self.reports_dir, exist_ok=True)
    
    def enrich_and_detect(self, log_entries: List[Dict]) -> List[Dict]:
        """
        Enrich log entries with Spur data and detect anomalies.
        
        Args:
            log_entries: List of log entries with IP addresses
            
        Returns:
            List of anomalous entries with enrichment data
        """
        anomalies = []
        all_enriched_data = []
        
        # Get unique IPs to reduce API calls
        unique_ips = list(set(entry['ip'] for entry in log_entries if entry.get('ip')))
        print(f"   Analyzing {len(unique_ips)} unique IP addresses with Spur API...")
        print(f"   Using {self.max_workers} concurrent workers for parallel lookups...")
        
        # Enrich IPs in parallel using ThreadPoolExecutor
        completed = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_ip = {executor.submit(self._enrich_ip, ip): ip for ip in unique_ips}
            
            # Process completed tasks as they finish
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    enrichment = future.result()
                    self.cache[ip] = enrichment
                except Exception as e:
                    # Handle any exceptions from the thread
                    self.cache[ip] = {'ip': ip, 'found': False, 'error': str(e)}
                
                completed += 1
                if completed % 50 == 0 or completed == len(unique_ips):
                    print(f"   Progress: {completed}/{len(unique_ips)} IPs analyzed")
        
        # Now check all entries against enriched data
        for entry in log_entries:
            ip = entry.get('ip')
            if not ip or ip not in self.cache:
                continue
            
            enrichment = self.cache[ip]
            
            # Create full enriched entry for audit log
            enriched_entry = {
                **entry,
                'enrichment': enrichment
            }
            all_enriched_data.append(enriched_entry)
            
            # Check if this is an anomaly (anonymous VPN tunnel only)
            if self._is_anomalous(enrichment):
                anomaly = {
                    **entry,
                    'enrichment': enrichment,
                    'vpn_operator': self._get_vpn_operator(enrichment)
                }
                anomalies.append(anomaly)
        
        # Save all enriched data to audit log
        self._save_audit_log(all_enriched_data)
        
        return anomalies
    
    def _enrich_ip(self, ip: str) -> Dict:
        """
        Call Spur API to enrich a single IP address.
        
        Args:
            ip: IP address to enrich
            
        Returns:
            Dict with enrichment data
        """
        try:
            response = requests.get(
                f"{self.BASE_URL}/{ip}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 404:
                # IP not in Spur database
                return {'ip': ip, 'found': False}
            
            response.raise_for_status()
            data = response.json()
            
            return {
                'ip': ip,
                'found': True,
                'as': data.get('as', {}),
                'location': data.get('location', {}),
                'client': data.get('client', {}),
                'organization': data.get('organization', ''),
                'infrastructure': data.get('infrastructure', ''),
                'risks': data.get('risks', []),
                'tunnels': data.get('tunnels', []),
                'vpn_operators': data.get('vpn_operators', {})
            }
            
        except requests.exceptions.RequestException as e:
            # Silently handle errors to avoid cluttering output
            return {'ip': ip, 'found': False, 'error': str(e)}
    
    def _is_anomalous(self, enrichment: Dict) -> bool:
        """
        Determine if enriched IP data indicates an anomaly.
        Only flags entries with anonymous VPN tunnels.
        
        Args:
            enrichment: Enriched IP data from Spur
            
        Returns:
            True if has anonymous VPN tunnel, False otherwise
        """
        if not enrichment.get('found'):
            return False
        
        # Only check for tunnels with anonymous=true and a VPN operator
        tunnels = enrichment.get('tunnels', [])
        for tunnel in tunnels:
            if tunnel.get('anonymous') and tunnel.get('operator') and tunnel.get('type') == 'VPN':
                return True
        
        return False
    
    def _get_vpn_operator(self, enrichment: Dict) -> str:
        """
        Get the VPN operator name from tunnels.
        
        Args:
            enrichment: Enriched IP data from Spur
            
        Returns:
            VPN operator name or 'Unknown'
        """
        tunnels = enrichment.get('tunnels', [])
        for tunnel in tunnels:
            if tunnel.get('anonymous') and tunnel.get('operator') and tunnel.get('type') == 'VPN':
                return tunnel.get('operator', 'Unknown')
        return 'Unknown'
    
    def _save_audit_log(self, enriched_data: List[Dict]):
        """
        Save all enriched data to reports directory.
        
        Args:
            enriched_data: List of all enriched log entries
        """
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d')
        report_file = os.path.join(self.reports_dir, f'enrichment_report_{timestamp}.json')
        
        report = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_entries': len(enriched_data),
            'entries': enriched_data
        }
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"   ✓ Full enrichment data saved to {report_file}")

