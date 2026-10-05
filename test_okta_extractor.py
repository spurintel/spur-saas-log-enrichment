"""Offline self-check for the Okta extractor: mocks HTTP, verifies the event-type filter,
pagination, dedup, actor filtering, the IP-chain fallback, retries and the 429 backoff clock.

Run: python test_okta_extractor.py
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import requests

from extractors.okta_extractor import OktaExtractor, retry_delay

ORG = 'https://auth.team.blue'
LOGS = f'{ORG}/api/v1/logs'


def resp(events, status_code=200, headers=None, next_url=None):
    r = Mock()
    r.status_code = status_code
    r.headers = headers or {}
    r.links = {'next': {'url': next_url}} if next_url else {}
    r.json.return_value = events
    r.raise_for_status = Mock()
    return r


def event(uid, ip, event_type='user.session.start', actor_type='User',
          outcome='SUCCESS', ip_chain=None, hours_ago=1):
    published = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    return {
        'published': published,
        'eventType': event_type,
        'outcome': {'result': outcome},
        'actor': {'id': f'00u{uid}', 'type': actor_type,
                  'alternateId': f'user{uid}@team.blue', 'displayName': f'User {uid}'},
        'client': {'ipAddress': ip, 'userAgent': {'rawUserAgent': 'Firefox'}},
        'request': {'ipChain': [{'ip': c} for c in (ip_chain or [])]},
    }


def test_extract():
    page1 = [
        event(1, '1.1.1.1'),
        event(1, '1.1.1.1', hours_ago=2),                       # same user + IP: dedup
        event(2, '2.2.2.2', actor_type='PublicClientApp'),      # not a person: skip
        event(3, None),                                         # no IP anywhere: skip
        event(4, None, ip_chain=['4.4.4.4']),                   # falls back to the IP chain
        event(5, '5.5.5.5', event_type='user.account.lock', outcome='FAILURE'),
    ]
    calls = []

    def fake_get(url, params=None, timeout=None):
        calls.append((url, params))
        if len(calls) == 1:
            return resp(page1, next_url=f'{LOGS}?after=2')
        return resp([])  # an empty page ends the poll even though the next link stays valid

    ex = OktaExtractor(ORG, 'tok')
    with patch.object(ex.session, 'get', side_effect=fake_get), patch('time.sleep'):
        logs = ex.extract_ip_logs(days=1)

    assert [(l['email'], l['ip']) for l in logs] == [
        ('user1@team.blue', '1.1.1.1'),
        ('user4@team.blue', '4.4.4.4'),
        ('user5@team.blue', '5.5.5.5'),
    ], logs
    assert logs[0]['user'] == 'User 1' and logs[0]['user_agent'] == 'Firefox'
    assert logs[2]['outcome'] == 'FAILURE' and logs[2]['action'] == 'user.account.lock'

    url, params = calls[0]
    assert url == LOGS, url
    assert params['limit'] == 1000 and params['since'].endswith('Z'), params
    assert 'filter' not in params, 'every event type is pulled by default'
    assert calls[1][1] is None, 'the next link already carries the query'
    print('okta extract ok')


def test_event_types_narrow_the_pull():
    """OKTA_EVENT_TYPES is opt-in: naming types adds a server-side filter, nothing else does."""
    calls = []

    def fake_get(url, params=None, timeout=None):
        calls.append(params)
        return resp([])

    ex = OktaExtractor(ORG, 'tok', event_types=['user.session.start', 'user.account.lock'])
    with patch.object(ex.session, 'get', side_effect=fake_get):
        ex.extract_ip_logs(days=1)
    assert calls[0]['filter'] == (
        'eventType eq "user.session.start" or eventType eq "user.account.lock"'), calls[0]

    calls.clear()
    ex = OktaExtractor(ORG, 'tok', event_types=[])
    with patch.object(ex.session, 'get', side_effect=fake_get):
        ex.extract_ip_logs(days=1)
    assert 'filter' not in calls[0], calls[0]
    print('okta event-type filter ok')


def test_retries():
    """429s and stalled reads are retried; the session is not lost to one slow response."""
    seen = []

    def fake_get(url, params=None, timeout=None):
        seen.append(url)
        if len(seen) == 1:
            return resp([], status_code=429, headers={'X-Rate-Limit-Reset': '1'})
        if len(seen) == 2:
            raise requests.exceptions.ReadTimeout('Read timed out. (read timeout=30)')
        return resp([event(1, '1.1.1.1')])  # last page: no next link, so the poll ends

    ex = OktaExtractor(ORG, 'tok')
    with patch.object(ex.session, 'get', side_effect=fake_get), patch('time.sleep'):
        logs = ex.extract_ip_logs(days=1)
    assert [l['ip'] for l in logs] == ['1.1.1.1'], logs
    assert len(seen) == 3, seen  # 429, timeout, then the page
    print('okta retry ok')


def test_retry_delay_is_epoch_based():
    """Okta sends an absolute reset time; it is turned into a wait against the server clock."""
    def r(headers):
        m = Mock()
        m.headers = headers
        return m

    served = datetime(2026, 9, 28, 14, 30, 0, tzinfo=timezone.utc)
    reset = int((served + timedelta(seconds=9)).timestamp())
    headers = {'Date': served.strftime('%a, %d %b %Y %H:%M:%S GMT'),
               'X-Rate-Limit-Reset': str(reset)}
    assert retry_delay(r(headers), 0) == 9

    # A reset already in the past still waits a second rather than hammering.
    past = dict(headers, **{'X-Rate-Limit-Reset': str(int(served.timestamp()) - 30)})
    assert retry_delay(r(past), 0) == 1
    # No usable header: exponential backoff, capped.
    assert retry_delay(r({}), 3) == 8
    assert retry_delay(r({'X-Rate-Limit-Reset': 'later'}), 2) == 4
    print('okta backoff ok')


def test_proxy_alerting_skips_relay_operators():
    """iCloud Private Relay was 310 of 316 isProxy addresses on this org, so alerting on the
    raw flag is unusable; the AS-org exclusion is what makes it a signal."""
    import os
    from unittest.mock import patch
    import anomaly_detector as det

    entries = [
        {'source': 'okta', 'ip': '1.1.1.1', 'is_proxy': True, 'as_org': 'Cloudflare, Inc.'},
        {'source': 'okta', 'ip': '2.2.2.2', 'is_proxy': True, 'as_org': 'akamai technologies  inc.'},
        {'source': 'okta', 'ip': '3.3.3.3', 'is_proxy': True, 'as_org': 'Fastly'},
        {'source': 'okta', 'ip': '4.4.4.4', 'is_proxy': True, 'as_org': 'vpn consumer cosenza  italy'},
        {'source': 'okta', 'ip': '5.5.5.5', 'is_proxy': False, 'as_org': 'some isp'},
        {'source': 'slack', 'ip': '6.6.6.6', 'is_proxy': True, 'as_org': 'whatever'},
    ]

    class NoWatchlist:
        def lookup(self, ip):
            return None

    with patch.dict(os.environ, {'OKTA_ALERT_ON_PROXY': '1'}, clear=False):
        found = det.AnomalyDetector._okta_proxy_anomalies(entries, NoWatchlist())
    assert [f['ip'] for f in found] == ['4.4.4.4'], found   # relays out, real VPN kept

    # a sanctioned corporate gateway can be added to the exclusion
    with patch.dict(os.environ, {'OKTA_ALERT_ON_PROXY': '1',
                                 'OKTA_PROXY_IGNORE_ASORG': 'vpn consumer cosenza'}, clear=False):
        found = det.AnomalyDetector._okta_proxy_anomalies(entries, NoWatchlist())
    assert [f['ip'] for f in found] == ['1.1.1.1', '2.2.2.2', '3.3.3.3'], found

    # off by default: no flag, no findings
    with patch.dict(os.environ, {'OKTA_ALERT_ON_PROXY': ''}, clear=False):
        assert det.AnomalyDetector._okta_proxy_anomalies(entries, NoWatchlist()) == []
    print('okta proxy exclusion ok')


if __name__ == '__main__':
    test_extract()
    test_event_types_narrow_the_pull()
    test_retries()
    test_retry_delay_is_epoch_based()
    test_proxy_alerting_skips_relay_operators()
