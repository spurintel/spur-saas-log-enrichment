"""Teamtailor candidate IP extractor (audit events)."""

import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import requests


class TeamtailorExtractor:
    """Extract applicant IPs from the Teamtailor audit log (/v1/audit-events)."""

    BASE_URL = "https://api.teamtailor.com/v1"

    def __init__(self, api_key: str, account: str = 'global'):
        self.account = account
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token token={api_key}',
            'X-Api-Version': '20240904',
            'Accept': 'application/vnd.api+json',
        })

    def _get(self, url: str, params: Dict = None, max_retries: int = 5) -> Dict:
        # audit-events returns sporadic 500s; retry those and 429s with backoff
        for attempt in range(max_retries + 1):
            r = self.session.get(url, params=params, timeout=30)
            if (r.status_code == 429 or r.status_code >= 500) and attempt < max_retries:
                time.sleep(int(r.headers.get('Retry-After') or 2 ** attempt))
                continue
            r.raise_for_status()
            return r.json()

    def extract_ip_logs(self, days: int = 30) -> List[Dict]:
        """One entry per (candidate, IP) seen in the last `days` days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        # ponytail: "@eu" assumes the EU API host; NA workspaces use api.na.teamtailor.com
        company = f"{self._get(f'{self.BASE_URL}/company')['data']['id']}@eu"
        logs, seen = [], set()
        # Newest first so the hourly run stops at the cutoff. Page sizes below 10 return 500s.
        url, params = f"{self.BASE_URL}/audit-events", {'sort': '-id', 'page[size]': 30}
        while url:
            data = self._get(url, params)
            params = None  # next links already carry the query
            for ev in data.get('data', []):
                a = ev['attributes']
                ts = datetime.fromisoformat(a['timestamp'])
                if ts < cutoff:
                    return logs
                # Recruiter actions on a candidate carry the recruiter's IP, not the applicant's
                if a.get('source-type') != 'candidate' or a.get('actor-type') == 'user' or not a.get('ip-address'):
                    continue
                cid = str(a['source-id'])
                if (cid, a['ip-address']) in seen:
                    continue
                seen.add((cid, a['ip-address']))
                logs.append({
                    'user': a.get('source-label') or 'Unknown',
                    'email': f"tt:{self.account}:{cid}",  # unique per candidate for dedup keys
                    'candidate_id': cid,
                    'account': self.account,
                    'company': company,  # used to build the candidate profile URL
                    'ip': a['ip-address'],
                    'timestamp': ts.astimezone(timezone.utc).isoformat(),
                    'action': a.get('action'),
                })
            url = data.get('links', {}).get('next')
        return logs
