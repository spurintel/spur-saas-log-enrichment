"""Okta System Log IP extractor (/api/v1/logs)."""

import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import requests

# Every event type is pulled by default: filtering server side saved about 6s of a 32s pull
# while risking a blind spot, since a zone block or a denied sign-on can surface under an
# event type nobody thought to list. Narrow it with OKTA_EVENT_TYPES only if volume demands it.
ALL_EVENT_TYPES = ()


def retry_delay(response, attempt, cap: int = 60) -> int:
    """Seconds to wait before retrying `response`.

    Okta's X-Rate-Limit-Reset is a Unix epoch timestamp, not a duration, so it is
    turned into one against the server's own clock (its Date header) to stay right
    when the local clock has drifted."""
    reset = (response.headers.get('X-Rate-Limit-Reset') or '').strip()
    if reset.isdecimal():
        now = None
        served = response.headers.get('Date')
        if served:
            try:
                now = datetime.strptime(served, '%a, %d %b %Y %H:%M:%S %Z').replace(
                    tzinfo=timezone.utc).timestamp()
            except ValueError:
                now = None
        if now is None:
            now = datetime.now(timezone.utc).timestamp()
        return max(1, min(cap, int(int(reset) - now)))
    return min(cap, 2 ** attempt)


class OktaExtractor:
    """Extract user IPs from the Okta System Log.

    One entry per (user, IP) in the window, matching the other extractors, so a noisy
    login loop does not drown the report in duplicate rows for the same address. Every
    event type is read unless `event_types` narrows it, so a sign-on denied by a network
    zone is caught alongside an ordinary session start.
    """

    PAGE_SIZE = 1000        # API maximum
    TIMEOUT = 30            # seconds to wait for a response
    TIMEOUT_RETRIES = 2     # extra attempts for a stalled request, budgeted apart from 429/5xx
    MAX_PAGES = 500         # guard against a next link that never drains

    def __init__(self, org_url: str, api_token: str, event_types=ALL_EVENT_TYPES):
        self.base_url = org_url.rstrip('/')
        self.event_types = tuple(event_types or ())
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'SSWS {api_token}',
            'Accept': 'application/json',
        })

    def _filter(self) -> str:
        """SCIM filter limiting the pull to the configured event types ('' means every type)."""
        return ' or '.join(f'eventType eq "{t}"' for t in self.event_types)

    def _get(self, url: str, params: Dict = None, max_retries: int = 5) -> requests.Response:
        """GET with backoff, retrying 429s, 5xx and stalled requests.

        Repeating a GET is safe, so a slow response costs a retry rather than the whole
        source; the smaller timeout budget keeps a real outage from stalling the run."""
        retries = timeouts = 0
        while True:
            try:
                r = self.session.get(url, params=params, timeout=self.TIMEOUT)
            except (requests.Timeout, requests.ConnectionError) as e:
                timeouts += 1
                if timeouts > self.TIMEOUT_RETRIES:
                    raise requests.RequestException(
                        f"{type(e).__name__} on {url} after {timeouts} attempts") from e
                time.sleep(2 ** (timeouts - 1))
                continue
            if (r.status_code == 429 or r.status_code >= 500) and retries < max_retries:
                time.sleep(retry_delay(r, retries))
                retries += 1
                continue
            r.raise_for_status()
            return r

    @staticmethod
    def _client_ip(event: Dict) -> str:
        """The caller's address: client.ipAddress, else the first hop of the request IP chain."""
        ip = (event.get('client') or {}).get('ipAddress')
        if ip:
            return ip
        chain = (event.get('request') or {}).get('ipChain') or []
        return chain[0].get('ip') if chain else None

    def extract_ip_logs(self, days: int = 30) -> List[Dict]:
        """One entry per (user, IP) seen in the last `days` days."""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        params = {'since': since.strftime('%Y-%m-%dT%H:%M:%S.000Z'), 'limit': self.PAGE_SIZE}
        if self.event_types:
            params['filter'] = self._filter()

        url, logs, seen, pages = f"{self.base_url}/api/v1/logs", [], set(), 0
        while url and pages < self.MAX_PAGES:
            r = self._get(url, params)
            params = None  # the next link already carries the query
            pages += 1
            events = r.json()
            if not events:  # the next link stays valid for polling, so an empty page is the end
                break
            for ev in events:
                actor = ev.get('actor') or {}
                ip = self._client_ip(ev)
                # Only real people have an email-shaped alternateId; skip API-token and app actors
                if not ip or actor.get('type') != 'User':
                    continue
                email = actor.get('alternateId') or 'Unknown'
                key = (actor.get('id') or email, ip)
                if key in seen:
                    continue
                seen.add(key)
                client = ev.get('client') or {}
                agent = client.get('userAgent') or {}
                geo = client.get('geographicalContext') or {}
                sec = ev.get('securityContext') or {}
                logs.append({
                    'user': actor.get('displayName') or email,
                    'email': email,
                    'user_id': actor.get('id'),
                    'ip': ip,
                    'timestamp': ev.get('published'),
                    'action': ev.get('eventType'),
                    'outcome': (ev.get('outcome') or {}).get('result'),
                    'user_agent': agent.get('rawUserAgent') or 'Unknown',
                    # Okta's own verdict on the address. On this org it marked two orders of
                    # magnitude more anonymising infrastructure than the IP watchlist did.
                    'is_proxy': bool(sec.get('isProxy')),
                    'country': geo.get('country'),
                    'as_org': sec.get('asOrg'),
                })
            url = (r.links.get('next') or {}).get('url')
        return logs

    def test_connection(self) -> bool:
        """True if the token can read the System Log."""
        try:
            self._get(f"{self.base_url}/api/v1/logs", {'limit': 1})
            return True
        except Exception:
            return False
