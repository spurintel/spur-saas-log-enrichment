"""Offline self-check for the Teamtailor extractor: mocks HTTP, verifies filtering, dedup,
cutoff, 5xx retry, read-timeout retry and the rate-limit backoff headers.

Run: python test_teamtailor_extractor.py
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import requests

from extractors.teamtailor_extractor import TeamtailorExtractor, retry_delay


def resp(json_data, status_code=200, headers=None):
    r = Mock()
    r.status_code = status_code
    r.headers = headers or {}
    r.json.return_value = json_data
    r.raise_for_status = Mock()
    return r


def event(cid, ip, hours_ago, actor_type='candidate', source_type='candidate'):
    ts = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    return {'attributes': {'source-type': source_type, 'source-id': cid, 'source-label': f'Candidate {cid}',
                           'actor-type': actor_type, 'ip-address': ip, 'timestamp': ts, 'action': 'update'}}


def test_teamtailor():
    page1 = {'data': [
        event(1, '1.1.1.1', 1),
        event(2, '9.9.9.9', 1, actor_type='user'),          # recruiter action: recruiter's IP, skip
        event(1, '1.1.1.1', 2),                             # same candidate + IP: dedup
        event(5, '5.5.5.5', 2, source_type='job'),          # not a candidate: skip
        event(6, None, 2),                                  # no IP: skip
    ], 'links': {'next': 'https://api.teamtailor.com/v1/audit-events?page2'}}
    page2 = {'data': [
        event(3, '3.3.3.3', 3, actor_type=None),            # System row on a candidate carries applicant IP
        event(4, '4.4.4.4', 48),                            # older than cutoff: stop here
    ], 'links': {'next': 'https://api.teamtailor.com/v1/audit-events?page3'}}

    calls = []
    page2_failed = []

    def fake_get(url, params=None, timeout=None):
        calls.append(url)
        if url.endswith('/company'):
            return resp({'data': {'id': 'ABC'}})
        if url.endswith('page2'):
            if not page2_failed:
                page2_failed.append(True)
                return resp({}, status_code=500)
            return resp(page2)
        if url.endswith('page3'):
            raise AssertionError('fetched past the cutoff')
        assert params == {'sort': '-id', 'page[size]': 30}
        return resp(page1)

    ex = TeamtailorExtractor('key', account='dk')
    with patch.object(ex.session, 'get', side_effect=fake_get), patch('time.sleep'):
        logs = ex.extract_ip_logs(days=1)

    assert [(l['candidate_id'], l['ip']) for l in logs] == [('1', '1.1.1.1'), ('3', '3.3.3.3')], logs
    assert all(l['account'] == 'dk' and l['company'] == 'ABC@eu' for l in logs)
    assert logs[0]['email'] == 'tt:dk:1'
    assert calls.count('https://api.teamtailor.com/v1/audit-events?page2') == 2  # 500 then retry
    print('teamtailor ok')


def test_read_timeout_is_retried():
    """A stalled page costs a retry, not the whole workspace (the cause of the 28 Sept pages)."""
    attempts = []

    def fake_get(url, params=None, timeout=None):
        attempts.append(url)
        if url.endswith('/company'):
            return resp({'data': {'id': 'ABC'}})
        if len(attempts) < 4:  # company, then two stalled audit-events reads
            raise requests.exceptions.ReadTimeout('Read timed out. (read timeout=30)')
        return resp({'data': [event(1, '1.1.1.1', 1)], 'links': {}})

    ex = TeamtailorExtractor('key', account='global')
    with patch.object(ex.session, 'get', side_effect=fake_get), patch('time.sleep'):
        logs = ex.extract_ip_logs(days=1)

    assert [l['ip'] for l in logs] == ['1.1.1.1'], logs
    assert len(attempts) == 4, attempts


def test_read_timeout_gives_up_with_the_url():
    """Past the timeout budget it still fails, naming the endpoint that stalled."""
    def fake_get(url, params=None, timeout=None):
        if url.endswith('/company'):
            return resp({'data': {'id': 'ABC'}}, headers={'x-request-id': 'req-42'})
        raise requests.exceptions.ReadTimeout('Read timed out. (read timeout=30)')

    ex = TeamtailorExtractor('key', account='global')
    with patch.object(ex.session, 'get', side_effect=fake_get), patch('time.sleep'):
        try:
            ex.extract_ip_logs(days=1)
        except requests.RequestException as e:
            assert 'audit-events' in str(e) and 'ReadTimeout' in str(e), e
            # the stall itself has no headers, so report the last call Teamtailor did answer
            assert 'req-42' in str(e), e
        else:
            raise AssertionError('a permanent timeout should still fail the workspace')


def test_retry_delay_headers():
    """Teamtailor documents X-Rate-Limit-Reset (seconds left), not Retry-After."""
    def r(headers):
        m = Mock()
        m.headers = headers
        return m

    assert retry_delay(r({'X-Rate-Limit-Reset': '7'}), 0) == 7
    assert retry_delay(r({'Retry-After': '3'}), 0) == 3        # still honoured if sent
    assert retry_delay(r({}), 3) == 8                          # exponential fallback
    assert retry_delay(r({'X-Rate-Limit-Reset': '900'}), 0) == 60   # capped
    assert retry_delay(r({'X-Rate-Limit-Reset': 'soon'}), 2) == 4   # unparseable -> fallback


if __name__ == '__main__':
    test_teamtailor()
    test_read_timeout_is_retried()
    test_read_timeout_gives_up_with_the_url()
    test_retry_delay_headers()
