"""Offline self-check for the watchlist matcher: exact addresses, CIDR ranges, longest-prefix
wins, IPv6, malformed rows, and that a range never swallows an address outside it.

Run: python test_file_enrichment.py
"""

import os
import tempfile

from enrichment.file_enrichment import FileEnrichment


def watchlist(rows):
    path = os.path.join(tempfile.mkdtemp(), 'data.csv')
    with open(path, 'w') as f:
        f.write('ip,operator\n')
        for r in rows:
            f.write(r + '\n')
    return FileEnrichment(path)


def test_exact_and_range():
    w = watchlist([
        '198.51.100.7,ASTRILL_VPN',
        '192.0.2.0/24,DPRK_RANGE',
        '2001:db8::/32,IPV6_RANGE',
        '203.0.113.5/32,SINGLE_AS_CIDR',
    ])
    assert w.lookup('198.51.100.7') == 'ASTRILL_VPN'
    assert w.lookup('192.0.2.1') == 'DPRK_RANGE'          # inside the range
    assert w.lookup('192.0.2.255') == 'DPRK_RANGE'        # last address of the range
    assert w.lookup('192.0.3.1') is None                  # just outside it
    assert w.lookup('2001:db8::dead:beef') == 'IPV6_RANGE'
    assert w.lookup('2001:db9::1') is None
    assert w.lookup('203.0.113.5') == 'SINGLE_AS_CIDR'    # /32 folded into the exact table
    assert w.lookup('203.0.113.6') is None
    assert w.is_suspicious('192.0.2.42') and not w.is_suspicious('8.8.8.8')
    print('exact + range ok')


def test_most_specific_wins():
    w = watchlist(['10.0.0.0/8,BROAD', '10.1.0.0/16,NARROWER', '10.1.2.3,EXACT'])
    assert w.lookup('10.9.9.9') == 'BROAD'
    assert w.lookup('10.1.9.9') == 'NARROWER'
    assert w.lookup('10.1.2.3') == 'EXACT'
    print('longest prefix ok')


def test_v4_and_v6_do_not_cross():
    """An IPv4 address must not match an IPv6 range that happens to share an integer value."""
    w = watchlist(['::/0,ALL_V6'])
    assert w.lookup('2001:db8::1') == 'ALL_V6'
    assert w.lookup('192.0.2.1') is None
    print('v4/v6 separation ok')


def test_malformed_rows_are_skipped_not_fatal():
    w = watchlist(['not-an-ip,JUNK', '192.0.2.0/33,BAD_PREFIX', ',EMPTY', '198.51.100.9,GOOD'])
    assert w.lookup('198.51.100.9') == 'GOOD'
    assert w.lookup('not-an-ip') is None
    print('malformed rows ok')


def test_enrich_and_detect_annotates_range_hits():
    w = watchlist(['192.0.2.0/24,DPRK_RANGE'])
    entries = [{'ip': '192.0.2.50', 'user': 'ann'}, {'ip': '8.8.8.8', 'user': 'bob'},
               {'user': 'no ip at all'}]
    found = w.enrich_and_detect(entries)
    assert [a['user'] for a in found] == ['ann'], found
    assert found[0]['vpn_operator'] == 'DPRK_RANGE'
    assert found[0]['enrichment']['matched'] is True
    assert 'DPRK_RANGE' in found[0]['anomaly_type']
    print('enrich_and_detect ok')


def test_the_real_watchlist_still_loads_and_matches():
    """data.csv is plain addresses today; the rewrite must not change what it matches."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.csv')
    if not os.path.exists(path):
        print('real watchlist absent, skipped')
        return
    w = FileEnrichment(path)
    ip, tag = next(iter(w.suspicious_ips.items()))
    assert w.lookup(ip) == tag
    assert w.lookup('127.0.0.1') is None
    print(f'real watchlist ok ({len(w.suspicious_ips)} addresses)')


if __name__ == '__main__':
    test_exact_and_range()
    test_most_specific_wins()
    test_v4_and_v6_do_not_cross()
    test_malformed_rows_are_skipped_not_fatal()
    test_enrich_and_detect_annotates_range_hits()
    test_the_real_watchlist_still_loads_and_matches()
