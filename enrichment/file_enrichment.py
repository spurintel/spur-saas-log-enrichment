"""File-based IP enrichment for detecting known suspicious IPs."""

from typing import Dict, List
import os
import csv


class FileEnrichment:
    """Enrich IP addresses using a file containing suspicious IP addresses."""
    
    def __init__(self, filepath: str):
        """
        Initialize file-based enrichment.
        
        Args:
            filepath: Path to CSV file of suspicious IPs with columns: ip, operator
        """
        self.filepath = filepath
        self.suspicious_ips = self._load_suspicious_ips()
    
    def _load_suspicious_ips(self) -> Dict[str, str]:
        """Load suspicious IPs from CSV file into a dict mapping IP -> operator/tag."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Suspicious IP file not found: {self.filepath}")
        
        suspicious = {}
        
        with open(self.filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get('ip', '').strip()
                operator = row.get('operator', '').strip()
                # Skip empty IPs
                if ip:
                    suspicious[ip] = operator
        
        print(f"   Loaded {len(suspicious)} suspicious IPs from {self.filepath}")
        return suspicious
    
    def enrich_and_detect(self, log_entries: List[Dict]) -> List[Dict]:
        """
        Check log entries against suspicious IP list and detect anomalies.
        
        Args:
            log_entries: List of log entries with IP addresses
            
        Returns:
            List of anomalous entries
        """
        anomalies = []
        
        # Get unique IPs
        unique_ips = set(entry['ip'] for entry in log_entries if entry.get('ip'))
        print(f"   Analyzing {len(unique_ips)} unique IP addresses against watchlist...")
        
        # Find matching IPs
        matching_ips = unique_ips & self.suspicious_ips.keys()
        print(f"   Found {len(matching_ips)} IPs matching the suspicious list")
        
        # Print matching IPs with their tags
        if matching_ips:
            print("\n   Offending IPs detected:")
            for ip in sorted(matching_ips):
                tag = self.suspicious_ips[ip]
                print(f"      - IP: {ip} | Tag: {tag}")
            print()
        
        # Build anomalies list
        for entry in log_entries:
            ip = entry.get('ip')
            if ip and ip in self.suspicious_ips:
                operator_tag = self.suspicious_ips[ip]
                anomaly = {
                    **entry,
                    'vpn_operator': operator_tag,  # Add top-level field for critical alert detection
                    'enrichment': {
                        'ip': ip,
                        'matched': True,
                        'source': 'suspicious_ip_list',
                        'operator': operator_tag
                    },
                    'anomaly_type': f'Suspicious IP (Watchlist Match - {operator_tag})',
                    'risk_score': 90  # High risk since it's on a known bad list
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def is_suspicious(self, ip: str) -> bool:
        """
        Check if an IP is in the suspicious list.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if suspicious, False otherwise
        """
        return ip in self.suspicious_ips

