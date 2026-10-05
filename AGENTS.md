# spur-saas-log-enrichment

Detects anonymising VPN/proxy and watchlisted IPs across Slack, Zoom, Teamtailor and Okta
logs and posts new findings to Slack. `slack_alert_cron.py` runs every 30 minutes; see
`README.md` for configuration and the data sources.

Read the ground rules below before running anything.

## One-off security checks

Notes for whoever (person or agent) picks this repo up to answer a question like "is this
user / IP / applicant a problem?". The scheduled job is the automated side; everything here
is the manual side.

## Ground rules

These have all been learned the hard way. Break them and you either page someone at 2am or
accuse an innocent person of being a North Korean operative.

1. **Never run `slack_alert_cron.py` live for a check.** It takes a lock, posts to Slack,
   writes profile notes on real candidates and advances the watermark. Use `--dry-run`, or
   run `anomaly_detector.py` directly with `--output` pointing somewhere scratch.
2. **Never write `.slack_alert_state.json`, `.teamtailor_noted.json`,
   `.teamtailor_ai_noted.json` or `.slack_alert_watermark.json` by hand.** Writing the
   watermark makes the next scheduled run skip a window; writing the state file makes real
   findings never alert.
3. **Before adding anything to `data.csv`, check whether a human already signs in from it.**
   On 2026-09-28 eleven ThreatInsight IPs were added and four turned out to be employees'
   own home addresses, because ThreatInsight fires on failed-login bursts and a locked-out
   employee produces those too. The gate is in "Checking a candidate watchlist entry" below.
4. **A Teamtailor false positive is not noise.** The cron writes a note on the candidate's
   profile saying they are a suspected DPRK IT worker and must not be progressed. Prefer a
   missed detection over a wrong accusation: add the observed address, not the whole range,
   unless you have measured the range.
5. **Don't bulk-add addresses your own staff use.** Okta's `isProxy` addresses are staff
   addresses by definition; they belong in a per-finding signal, not a blocklist.
6. **Throttle.** Okta's budget is ~60 requests/minute and the cron uses some of it every
   30 minutes. A long backfill should stay at or below ~32/min or it starves the cron,
   which fails the run, which suppresses the healthcheck ping, which pages a human.

## Checking one user

```bash
./user_check.py simone.torre@team.blue          # last 30 days
./user_check.py "Simone Torre" --days 90        # display-name prefix
./user_check.py sabir.buxsoo@team.blue --events # plus every event
```

Prints every IP with country, network, watchlist status and Okta's `isProxy` verdict, then
the OS/browser mix, outcomes and event types, and ends with the addresses worth a look.
Read-only. `relay` in the flags column means iCloud Private Relay (Akamai/Cloudflare/Fastly)
and is benign; `PROXY` means anonymising infrastructure that is not a relay.

Absence of events is evidence too: if someone reports a failure and there are no failed
events, their traffic never reached Okta — usually a VPN or network block on their side.

## Checking one Slack user

```bash
./user_logins.py <SLACK_USER_ID> [DAYS]
```

## Checking an IP or a range

```python
from enrichment.file_enrichment import FileEnrichment
w = FileEnrichment('data.csv')
w.lookup('1.2.3.4')     # operator tag, or None. Handles CIDR entries.
```

## Checking a candidate watchlist entry (the gate)

Before adding any address or range, confirm no human signs in from it successfully. The
cheapest source is Okta, which covers all staff:

```python
import gzip, glob, json
from enrichment.file_enrichment import FileEnrichment
w = FileEnrichment('candidates.csv')          # ip,operator — the entries you want to add
for fn in glob.glob('<scratch>/okta-*/**/*.jsonl.gz', recursive=True):
    with gzip.open(fn, 'rt') as fh:
        for line in fh:
            e = json.loads(line)
            if e.get('atype') == 'User' and e.get('ip') and w.lookup(e['ip']) \
                    and e.get('out') in ('SUCCESS', 'ALLOW'):
                print('COLLISION', e['ip'], e.get('email'))
```

Any hit on a `@team.blue` account means do not add that entry. Attempted usernames that are
not `@team.blue` with only `FAILURE` outcomes are the attack, not a collision.

If no local event dump exists, pull one with `OktaExtractor` day by day (see
`extractors/okta_extractor.py`) at the throttle above.

## Ad-hoc detector run

```bash
/home/esp/venv/bin/python anomaly_detector.py --enrichment file --ip-file data.csv \
  --hours 168 --output /tmp/scratch/check.json
# Okta only:        --no-teamtailor --slack-token '' --zoom-account-id ''
# then replay it through the cron, still without posting:
./slack_alert_cron.py --dry-run /tmp/scratch/check.json
```

`--hours` takes fractions. The detector reads `.env` itself, so no environment setup.

## Known gaps

Standing blind spots. Worth re-reading before concluding "nothing found".

- **Corporate VPN egresses are not fully inventoried.** Three are known — `195.184.253.28`
  (Proton, 21 accounts), `172.105.249.178` and `212.71.254.38` (both SimplyBook, Linode, in
  the GitLab ACL). SimplyBook stated on 2026-09-29 that they run "a few" more that have not
  been identified. **Every unlisted egress adds staff to a location blind spot**: anyone
  behind a gateway shows the gateway's country, not their own, so location analysis silently
  skips them. That is the same blind spot that hid an employee working from China and
  southeast Asia for 80 days while recorded as based in Georgia. Ask whoever maintains the
  GitLab IP allow-list for the full set, and record each one.
- **`data.csv` has no IPRoyal coverage.** It is a partial Spur export — comprehensive on
  SOCKS5, the VDI/KVM families and Astrill, and missing IPRoyal entirely, which Spur measures
  at 66.5% of AS7849 alone. There is no Spur API access to refresh it, so coverage comes from
  ASN ranges (RIPEstat) and hand-added confirmed exits.
- **Teamtailor audit retention is 30 days**, Okta's is 90. Applicant hunts cannot reach
  further back than a month. A preserved Okta capture for 2026-06-30 → 09-28 is kept in
  `~/work/okta-events-2026Q3/` precisely because that window is now unrecoverable.
- **A quiet Teamtailor log may mean retries absorbed the problem**, not that upstream is
  healthy — a stall only surfaces if it survives three attempts.

## Things that are not what they look like

- **`x-rate-limit-reset` means different things.** Teamtailor sends seconds remaining; Okta
  sends an absolute Unix timestamp. Same header name.
- **Zoom's Dashboard API takes whole dates**, so a sub-day window still lists the whole day's
  meetings. `ZoomExtractor._overlaps` filters them client side.
- **`policy.evaluate_sign_on` carries the DENY/CHALLENGE decisions**, not `user.session.start`.
  A network-zone block appears there and nowhere else, which is why every Okta event type is
  pulled rather than a hand-written list.
- **Geolocation is Okta's and is sometimes wrong.** AS7849 resolves to "Greenfield, Wisconsin"
  for addresses on a Western Massachusetts ISP. Don't build a case on geo alone.

## Backups

Anything that edits `data.csv` or `.env` should copy it to `<file>.bak-YYYYMMDD-<what>` first.
Both are gitignored, as are all the state files.
