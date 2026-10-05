"""Teamtailor candidate IP extractor (audit events)."""

import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import requests


def retry_delay(response, attempt, cap: int = 60) -> int:
    """Seconds to wait before retrying `response`.

    Teamtailor documents X-Rate-Limit-Reset (seconds left in the 50-requests-per-10s
    bucket) rather than Retry-After, so honour both before falling back to backoff."""
    for header in ('Retry-After', 'X-Rate-Limit-Reset'):
        value = (response.headers.get(header) or '').strip()
        if value.isdecimal():
            return min(cap, int(value))
    return min(cap, 2 ** attempt)


class TeamtailorExtractor:
    """Extract applicant IPs from the Teamtailor audit log (/v1/audit-events)."""

    BASE_URL = "https://api.teamtailor.com/v1"
    TIMEOUT = 30            # seconds to wait for a response
    TIMEOUT_RETRIES = 2     # extra attempts for a stalled request, budgeted apart from 429/5xx

    def __init__(self, api_key: str, account: str = 'global'):
        self.account = account
        self.last_request_id = None  # anchor for a support ticket: a stall returns no headers
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token token={api_key}',
            'X-Api-Version': '20240904',
            'Accept': 'application/vnd.api+json',
        })

    def _get(self, url: str, params: Dict = None, max_retries: int = 5) -> Dict:
        """GET with backoff. Retries 429s, 5xx (audit-events returns sporadic 500s) and
        stalled requests.

        A read timeout used to escape to the caller, which aborts extract_ip_logs and
        drops the whole workspace for that run; repeating a GET is safe, so it costs a
        retry instead. The timeout budget is smaller than the 429/5xx one so a real
        outage still fails the run rather than stalling it past the cron period.
        """
        retries = timeouts = 0
        while True:
            try:
                r = self.session.get(url, params=params, timeout=self.TIMEOUT)
            except (requests.Timeout, requests.ConnectionError) as e:
                timeouts += 1
                if timeouts > self.TIMEOUT_RETRIES:
                    # A stalled request has no response and so no x-request-id of its own;
                    # the id of the last answered call is what Teamtailor support can trace.
                    seen = (f"; last answered x-request-id {self.last_request_id}"
                            if self.last_request_id else "")
                    raise requests.RequestException(
                        f"{type(e).__name__} on {url} after {timeouts} attempts{seen}") from e
                time.sleep(2 ** (timeouts - 1))
                continue
            self.last_request_id = r.headers.get('x-request-id') or self.last_request_id
            if (r.status_code == 429 or r.status_code >= 500) and retries < max_retries:
                time.sleep(retry_delay(r, retries))
                retries += 1
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
