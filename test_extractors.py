"""Offline self-check for extractors: mocks HTTP, verifies pagination, user prefetch, 429 retry.

Run: python test_extractors.py
"""

import time
from unittest.mock import Mock, patch

from extractors.slack_extractor import SlackExtractor
from extractors.zoom_extractor import ZoomExtractor

NOW = int(time.time())


def resp(json_data, status_code=200, headers=None):
    r = Mock()
    r.status_code = status_code
    r.headers = headers or {}
    r.json.return_value = json_data
    r.raise_for_status = Mock()
    return r


def test_slack():
    calls = []

    def fake_get(url, headers=None, params=None, timeout=None):
        calls.append(url)
        if url.endswith('users.list'):
            return resp({
                'ok': True,
                'members': [
                    {'id': 'U1', 'name': 'alice', 'real_name': 'Alice',
                     'profile': {'email': 'alice@example.com'}},
                    {'id': 'U2', 'name': 'bob', 'real_name': 'Bob',
                     'profile': {'email': 'bob@example.com'}},
                ],
                'response_metadata': {'next_cursor': ''}
            })
        if url.endswith('team.accessLogs'):
            if params['before'] == NOW - 200:  # second page
                return resp({'ok': True, 'logins': []})
            return resp({
                'ok': True,
                'logins': [
                    {'user_id': 'U1', 'ip': '1.2.3.4', 'date_first': NOW - 100,
                     'user_agent': 'x', 'count': 3},
                    {'user_id': 'U2', 'ip': '5.6.7.8', 'date_first': NOW - 200,
                     'user_agent': 'y', 'count': 1},
                ],
                'paging': {'page': 1, 'pages': 2}
            })
        raise AssertionError(f"unexpected URL: {url}")

    with patch('requests.Session.get', side_effect=fake_get):
        logs = SlackExtractor('xoxp-test').extract_ip_logs(days=7)

    assert len(logs) == 2, logs
    assert logs[0]['email'] == 'alice@example.com'
    assert logs[1]['email'] == 'bob@example.com'
    assert logs[0]['ip'] == '1.2.3.4'
    # bulk prefetch used — no per-user users.info calls
    assert not any(u.endswith('users.info') for u in calls), calls
    assert sum(u.endswith('users.list') for u in calls) == 1
    print("slack: OK")


def test_zoom():
    state = {'meetings_429_left': 1, 'meeting_pages': 0}

    def fake_get(url, headers=None, params=None, timeout=None):
        if url.endswith('/metrics/meetings'):
            assert params['page_size'] == 300, params
            if state['meetings_429_left']:  # first attempt rate-limited
                state['meetings_429_left'] -= 1
                return resp({}, status_code=429, headers={'Retry-After': '0'})
            state['meeting_pages'] += 1
            if state['meeting_pages'] == 1:
                return resp({'meetings': [{'id': 111, 'topic': 'Standup'}],
                             'next_page_token': 'tok'})
            return resp({'meetings': [{'id': 222, 'topic': 'Retro'}],
                         'next_page_token': ''})
        if '/participants' in url:
            assert params['page_size'] == 300, params
            meeting_id = url.split('/')[-2]
            return resp({'participants': [
                {'user_name': 'carol@example.com', 'ip_address': '9.9.9.9',
                 'join_time': '2026-08-12T10:00:00Z', 'duration': 60},
                {'user_name': 'noip', 'join_time': '2026-08-12T10:00:00Z'},
            ] if meeting_id == '111' else [], 'next_page_token': ''})
        raise AssertionError(f"unexpected URL: {url}")

    fake_post = Mock(return_value=resp({'access_token': 'tok'}))

    with patch('requests.Session.get', side_effect=fake_get), \
         patch('extractors.zoom_extractor.requests.post', fake_post), \
         patch('extractors.zoom_extractor.time.sleep'):
        logs = ZoomExtractor('acc', 'cid', 'secret').extract_ip_logs(days=7)

    assert state['meetings_429_left'] == 0  # 429 was consumed and retried
    assert state['meeting_pages'] == 2      # both pages fetched
    assert len(logs) == 1, logs             # participant without IP skipped
    assert logs[0]['ip'] == '9.9.9.9'
    assert logs[0]['email'] == 'carol@example.com'
    assert logs[0]['meeting_topic'] == 'Standup'
    print("zoom: OK")


def test_incremental_report(tmpdir='/tmp/claude-1001/-home-esp-spur-saas-log-enrichment/60c50d59-dc06-4382-a641-dcc56f6695ef/scratchpad'):
    """Slack finishes first -> interim report written before Zoom completes."""
    import io
    import json
    import os
    import sys
    from contextlib import redirect_stdout

    import anomaly_detector

    os.makedirs(tmpdir, exist_ok=True)
    ip_file = os.path.join(tmpdir, 'ips.csv')
    # nested non-existent dir: also verifies generate_report creates it
    report_file = os.path.join(tmpdir, 'nested_reports', 'report.json')
    with open(ip_file, 'w') as f:
        f.write("ip,operator\n1.2.3.4,ASTRILL_VPN\n9.9.9.9,KASM_VDI\n")

    class FakeSlack:
        def __init__(self, token):
            pass

        def extract_ip_logs(self, days):
            return [{'user': 'alice', 'email': 'alice@example.com',
                     'ip': '1.2.3.4', 'timestamp': 't'}]

    class FakeZoom:
        def __init__(self, *creds):
            pass

        def extract_ip_logs(self, days):
            time.sleep(0.3)  # slack lands first
            return [{'user': 'carol', 'email': 'carol@example.com',
                     'ip': '9.9.9.9', 'timestamp': 't', 'meeting_topic': 'Standup'}]

    argv = ['anomaly_detector.py', '--slack-token', 'x',
            '--zoom-account-id', 'a', '--zoom-client-id', 'b',
            '--zoom-client-secret', 'c',
            '--enrichment', 'file', '--ip-file', ip_file,
            '--output', report_file, '--days', '7']

    out = io.StringIO()
    with patch.object(anomaly_detector, 'SlackExtractor', FakeSlack), \
         patch.object(anomaly_detector, 'ZoomExtractor', FakeZoom), \
         patch.object(sys, 'argv', argv), \
         redirect_stdout(out):
        anomaly_detector.main()

    output = out.getvalue()
    assert 'Writing interim report (1/2 sources done)' in output, output

    with open(report_file) as f:
        report = json.load(f)
    sources = {a['source'] for a in report['anomalies']}
    assert sources == {'slack', 'zoom'}, report['anomalies']
    assert report['summary']['total_anomalies'] == 2
    print("incremental report: OK")


if __name__ == '__main__':
    test_slack()
    test_zoom()
    test_incremental_report()
    print("all OK")
