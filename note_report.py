#!/usr/bin/env python3
"""Post the Teamtailor security notes for every Teamtailor finding in a report, once per candidate.

Use after a replay whose notes failed (e.g. no note user in a workspace yet): a second replay
posts nothing because the findings are already in the Slack state, but the noted set only
grows on success, so this retries exactly the candidates that are still unflagged.

    ./note_report.py reports/retro_teamtailor_20260925.json [--dry-run]
"""
import json
import sys
from collections import Counter

import slack_alert_cron as c

if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if a != '--dry-run']
    if len(args) != 1:
        sys.exit(__doc__)
    c.load_env()
    findings = [a for a in json.load(open(args[0]))['anomalies'] if a.get('source') == 'teamtailor']
    noted = set(c.load_json(c.NOTED, []))
    pending = [a for a in findings if f"{a.get('account')}:{a.get('candidate_id')}" not in noted]
    c.add_teamtailor_emails(pending)  # email, jobs and the recruiter (note author of last resort)
    c.post_teamtailor_notes(findings, dry_run='--dry-run' in sys.argv)
    if '--dry-run' in sys.argv:
        for a in pending:
            c.log(f"would flag {a.get('account')}:{a.get('candidate_id')} {a.get('user')} as user "
                  f"{c.note_user_id(a.get('account')) or a.get('tt_recruiter_id')} (jobs: {a.get('tt_jobs')})")
    c.log(f"{args[0]}: {dict(Counter((a['account'], a.get('tt_note')) for a in findings))}")
