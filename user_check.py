#!/usr/bin/env python3
"""One-off check on a single Okta identity: where they signed in from, on what, and whether
any of it is anonymising infrastructure or on the watchlist.

    ./user_check.py simone.torre@team.blue
    ./user_check.py "Simone Torre" --days 30
    ./user_check.py sabir.buxsoo@team.blue --days 90 --events

An email is matched exactly on actor.alternateId; anything else is matched as a display-name
prefix. Read-only: no Slack post, no state file, no profile note.
"""

import argparse
import collections
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from anomaly_detector import load_env, okta_proxy_ignored          # noqa: E402
from enrichment.file_enrichment import FileEnrichment              # noqa: E402
from extractors.okta_extractor import OktaExtractor                # noqa: E402

REPO = os.path.dirname(os.path.abspath(__file__))
MAX_PAGES = 200


def fetch(ex, who, days):
    """Every Okta event for `who` in the window, oldest first."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    field = 'actor.alternateId eq' if '@' in who else 'actor.displayName sw'
    params = {'since': since, 'limit': 1000, 'filter': f'{field} "{who}"'}
    url, rows, pages = f'{ex.base_url}/api/v1/logs', [], 0
    while url and pages < MAX_PAGES:
        r = ex._get(url, params)
        params = None
        pages += 1
        batch = r.json()
        if not batch:
            break
        rows += batch
        url = (r.links.get('next') or {}).get('url')
    rows.sort(key=lambda e: e.get('published') or '')
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split('\n\n', 1)[1])
    p.add_argument('who', help='email (exact) or display-name prefix')
    p.add_argument('--days', type=int, default=30, help='window in days (default 30, max useful 90)')
    p.add_argument('--events', action='store_true', help='also print every event, oldest first')
    args = p.parse_args()

    load_env()
    org, token = os.environ.get('OKTA_ORG_URL'), os.environ.get('OKTA_API_TOKEN')
    if not (org and token):
        sys.exit('OKTA_ORG_URL and OKTA_API_TOKEN must be set (env or .env)')

    rows = fetch(OktaExtractor(org, token, []), args.who, args.days)
    if not rows:
        print(f'no Okta events for {args.who!r} in the last {args.days} days')
        return

    actors = {(e.get('actor') or {}).get('alternateId') for e in rows}
    print(f"{' / '.join(sorted(a for a in actors if a))}")
    print(f"{len(rows)} events, {rows[0]['published'][:10]} .. {rows[-1]['published'][:10]}"
          f" (last {args.days}d)\n")

    watchlist = FileEnrichment(os.path.join(REPO, 'data.csv'))
    ignored = okta_proxy_ignored()

    per = collections.defaultdict(lambda: {'n': 0, 'out': collections.Counter(),
                                           'first': None, 'last': None, 'meta': None})
    agents, outcomes, events = collections.Counter(), collections.Counter(), collections.Counter()
    for e in rows:
        c = e.get('client') or {}
        sc = e.get('securityContext') or {}
        g = c.get('geographicalContext') or {}
        ua = c.get('userAgent') or {}
        outcomes[(e.get('outcome') or {}).get('result')] += 1
        events[e.get('eventType')] += 1
        agents[f"{ua.get('os')} / {ua.get('browser')}"] += 1
        ip = c.get('ipAddress')
        if not ip:
            continue
        d = per[ip]
        d['n'] += 1
        d['out'][(e.get('outcome') or {}).get('result')] += 1
        ts = e.get('published') or ''
        d['first'] = min(d['first'] or ts, ts)
        d['last'] = max(d['last'] or ts, ts)
        d['meta'] = (g.get('country'), sc.get('asOrg'), bool(sc.get('isProxy')))

    print(f"{'IP':<17}{'country':<16}{'network':<30}{'flags':<22}{'n':>5}  first..last")
    for ip, d in sorted(per.items(), key=lambda x: x[1]['first']):
        country, as_org, is_proxy = d['meta']
        hit = watchlist.lookup(ip)
        relay = is_proxy and any(s in (as_org or '').lower() for s in ignored)
        flags = ' '.join(filter(None, [
            f'WATCHLIST:{hit}' if hit else '',
            'relay' if relay else ('PROXY' if is_proxy else ''),
        ])) or '-'
        print(f"{ip:<17}{str(country)[:15]:<16}{str(as_org)[:29]:<30}{flags[:21]:<22}"
              f"{d['n']:>5}  {d['first'][:10]}..{d['last'][:10]}")

    print(f"\ncountries: {dict(collections.Counter(d['meta'][0] for d in per.values()))}")
    print(f"os / browser: {dict(agents.most_common(6))}")
    print(f"outcomes: {dict(outcomes)}")
    print(f"top events: {dict(events.most_common(8))}")

    concerns = [ip for ip, d in per.items()
                if watchlist.lookup(ip)
                or (d['meta'][2] and not any(s in (d['meta'][1] or '').lower() for s in ignored))]
    print(f"\n{'>>> ' + str(len(concerns)) + ' address(es) worth a look: ' + ', '.join(concerns)
          if concerns else '>>> nothing on the watchlist, no non-relay proxy'}")

    if args.events:
        print()
        for e in rows:
            c = e.get('client') or {}
            print(f"  {e['published'][:19]}Z {str(e.get('eventType'))[:40]:<40} "
                  f"{str((e.get('outcome') or {}).get('result')):<9} {c.get('ipAddress')}")


if __name__ == '__main__':
    main()
