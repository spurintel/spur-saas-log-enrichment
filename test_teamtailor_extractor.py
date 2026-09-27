"""Offline self-check for the Teamtailor extractor: mocks HTTP, verifies filtering, dedup, cutoff, 5xx retry.

Run: python test_teamtailor_extractor.py
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from extractors.teamtailor_extractor import TeamtailorExtractor


def resp(json_data, status_code=200):
    r = Mock()
    r.status_code = status_code
    r.headers = {}
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


if __name__ == '__main__':
    test_teamtailor()
