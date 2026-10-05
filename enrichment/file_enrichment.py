"""File-based IP enrichment for detecting known suspicious addresses and ranges."""

import csv
import ipaddress
import os
from typing import Dict, List, Optional


class FileEnrichment:
    """Enrich IP addresses using a file of suspicious addresses and CIDR ranges.

    Exact addresses stay a dict lookup. Ranges are bucketed by prefix length, so a lookup
    masks the address once per distinct prefix length rather than walking every range: a
    watchlist of tens of thousands of entries costs a handful of dict hits per IP.
    """

    def __init__(self, filepath: str):
        """
        Args:
            filepath: CSV with columns ip, operator. The ip column takes a single address
                      or a CIDR range (192.0.2.0/24, 2001:db8::/32).
        """
        self.filepath = filepath
        self.suspicious_ips: Dict[str, str] = {}      # exact address -> operator/tag
        self._nets: Dict[tuple, Dict] = {}            # (version, prefixlen) -> {network -> tag}
        self._prefixes: List[tuple] = []              # (version, prefixlen), most specific first
        self._cache: Dict[str, Optional[str]] = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"Suspicious IP file not found: {self.filepath}")

        skipped = 0
        with open(self.filepath, 'r') as f:
            for row in csv.DictReader(f):
                entry = (row.get('ip') or '').strip()
                operator = (row.get('operator') or '').strip()
                if not entry:
                    continue
                try:
                    if '/' in entry:
                        net = ipaddress.ip_network(entry, strict=False)
                        if net.prefixlen == net.max_prefixlen:  # /32 or /128 is just an address
                            self.suspicious_ips[str(net.network_address)] = operator
                        else:
                            self._nets.setdefault((net.version, net.prefixlen), {})[
                                net.network_address] = operator
                    else:
                        self.suspicious_ips[str(ipaddress.ip_address(entry))] = operator
                except ValueError:
                    skipped += 1  # a malformed row must not take the whole watchlist down

        # Most specific first, so a /32 carve-out beats the /16 it sits inside.
        self._prefixes = sorted(self._nets, key=lambda key: -key[1])
        ranges = sum(len(v) for v in self._nets.values())
        print(f"   Loaded {len(self.suspicious_ips)} suspicious IPs"
              + (f" and {ranges} ranges" if ranges else "")
              + f" from {self.filepath}"
              + (f" ({skipped} unparseable row(s) skipped)" if skipped else ""))

    def lookup(self, ip: str) -> Optional[str]:
        """The operator/tag for `ip`: an exact entry first, then the most specific range
        containing it. None if the address is not listed or is not an address at all."""
        if ip in self._cache:
            return self._cache[ip]

        tag = self.suspicious_ips.get(ip)
        if tag is None and self._prefixes:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                addr = None
            if addr is not None:
                packed, width = int(addr), addr.max_prefixlen
                for version, prefixlen in self._prefixes:
                    if version != addr.version:
                        continue
                    mask = ((1 << prefixlen) - 1) << (width - prefixlen)
                    tag = self._nets[(version, prefixlen)].get(type(addr)(packed & mask))
                    if tag is not None:
                        break
        self._cache[ip] = tag
        return tag

    def enrich_and_detect(self, log_entries: List[Dict]) -> List[Dict]:
        """Return the log entries whose IP is on the watchlist, annotated with the match."""
        unique_ips = set(entry['ip'] for entry in log_entries if entry.get('ip'))
        print(f"   Analyzing {len(unique_ips)} unique IP addresses against watchlist...")

        hits = {ip: tag for ip in unique_ips for tag in [self.lookup(ip)] if tag is not None}
        print(f"   Found {len(hits)} IPs matching the suspicious list")

        if hits:
            print("\n   Offending IPs detected:")
            for ip in sorted(hits):
                print(f"      - IP: {ip} | Tag: {hits[ip]}")
            print()

        anomalies = []
        for entry in log_entries:
            operator_tag = hits.get(entry.get('ip'))
            if operator_tag is None:
                continue
            anomalies.append({
                **entry,
                'vpn_operator': operator_tag,  # Add top-level field for critical alert detection
                'enrichment': {
                    'ip': entry['ip'],
                    'matched': True,
                    'source': 'suspicious_ip_list',
                    'operator': operator_tag,
                },
                'anomaly_type': f'Suspicious IP (Watchlist Match - {operator_tag})',
                'risk_score': 90,  # High risk since it's on a known bad list
            })
        return anomalies

    def is_suspicious(self, ip: str) -> bool:
        """True if the address is listed exactly or falls inside a listed range."""
        return self.lookup(ip) is not None
