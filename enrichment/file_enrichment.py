"""File-based IP enrichment for detecting known suspicious IPs."""

from typing import Dict, List, Set
import os


class FileEnrichment:
    """Enrich IP addresses using a file containing suspicious IP addresses."""
    
    def __init__(self, filepath: str):
        """
        Initialize file-based enrichment.
        
        Args:
            filepath: Path to newline-delimited file of suspicious IPs
        """
        self.filepath = filepath
        self.suspicious_ips = self._load_suspicious_ips()
    
    def _load_suspicious_ips(self) -> Set[str]:
        """Load suspicious IPs from file into a set for fast lookup."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Suspicious IP file not found: {self.filepath}")
        
        suspicious = set()
        
        with open(self.filepath, 'r') as f:
            for line in f:
                ip = line.strip()
                # Skip empty lines and comments
                if ip and not ip.startswith('#'):
                    suspicious.add(ip)
        
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
        matching_ips = unique_ips & self.suspicious_ips
        print(f"   Found {len(matching_ips)} IPs matching the suspicious list")
        
        # Build anomalies list
        for entry in log_entries:
            ip = entry.get('ip')
            if ip and ip in matching_ips:
                anomaly = {
                    **entry,
                    'enrichment': {
                        'ip': ip,
                        'matched': True,
                        'source': 'suspicious_ip_list'
                    },
                    'anomaly_type': 'Suspicious IP (Watchlist Match)',
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

