#!/usr/bin/env -S python3 -u
"""Print recent Slack logins for one user, flagging watchlist IPs.

Usage: ./user_logins.py [USER_ID] [DAYS]   (defaults: U04T45CMY91, 30)
Creds from .env via the cron wrapper's loader.
"""

import csv
import os
import sys
from collections import Counter

from slack_alert_cron import load_env, REPO
from extractors.slack_extractor import SlackExtractor
from enrichment.file_enrichment import FileEnrichment


def main():
    user_id = sys.argv[1] if len(sys.argv) > 1 else 'U04T45CMY91'
    days = int(sys.argv[2]) if len(sys.argv) > 2 else 30

    load_env()
    logs = SlackExtractor(os.environ['SLACK_API_TOKEN']).extract_ip_logs(days)
    mine = sorted((l for l in logs if l['user_id'] == user_id),
                  key=lambda l: l['timestamp'])
    if not mine:
        print(f"no logins for {user_id} in the last {days} days")
        return

    watchlist = FileEnrichment(os.path.join(REPO, 'data.csv'))  # .lookup covers ranges too

    print(f"\n{len(mine)} login records for {mine[0]['user']} ({mine[0]['email']}), last {days} days:\n")
    for l in mine:
        hit = watchlist.lookup(l['ip'])
        flag = f"  🚨 {hit}" if hit else ''
        print(f"{l['timestamp']}  {l['ip']:<15}  x{l['count']:<4} {l['user_agent'][:60]}{flag}")

    print("\nUnique IPs:")
    for ip, n in Counter(l['ip'] for l in mine).most_common():
        hit = watchlist.lookup(ip)
        flag = f"  🚨 {hit}" if hit else ''
        print(f"  {ip:<15}  {n} record(s){flag}")

    out = os.path.join(REPO, 'reports', f'user_{user_id}_{days}d.csv')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['timestamp', 'ip', 'count', 'user_agent', 'watchlist'])
        w.writeheader()
        for l in mine:
            w.writerow({'timestamp': l['timestamp'], 'ip': l['ip'], 'count': l['count'],
                        'user_agent': l['user_agent'], 'watchlist': watchlist.lookup(l['ip']) or ''})
    print(f"\nsaved to {out}")


if __name__ == '__main__':
    main()
